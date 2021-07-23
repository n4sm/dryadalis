#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libelf.h>
#include <elf.h>
#include <sys/mman.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <keystone/keystone.h>

#include "../include/dryadalis_x86.h"

// =-=-=-=-=--

// check if an instruction will change the control flow
_Bool is_cflow(cs_insn *insn) {
    return (insn->id & (X86_GRP_CALL | X86_GRP_INT | X86_GRP_JUMP | X86_GRP_RET)) != 0;
}

_Bool is_ret(cs_insn *insn) {
    return (insn->id & (X86_GRP_RET));
}

// returns how much byte there is up to the first cflow instruction, returns -1 if it fails
int opcodes_cflow(unsigned long addr, mdata_binary_t* s_binary) {
    int n = 0;
    csh handle;
	cs_insn *insn;
	size_t count;
    unsigned long page_offt = PAGE_OFFT(addr);
    unsigned long size;

    if (!is_mapped(addr, s_binary)) {
        return -1;
    }

    // We can handle cases where the instruction is overlapping between two pages
    if (is_mapped(PAGE_ALIGN(addr) + 0x1000, s_binary)) {
        size = PAGE_OFFT(~page_offt) + 0x1000;
    } else {
        size = PAGE_OFFT(~page_offt);
    }

    unsigned char* insn_buf = calloc(1, size);

    memcpy(insn_buf, (void* )addr, size);

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return -1;
    }

    count = cs_disasm(handle, insn_buf, size, 0, 0, &insn);

    for (int i = 0 ; i < count ; i++ ) {
        n += insn[i].size;
        fprintf(stdout, "0x%"PRIx64":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic,
					insn[i].op_str);
        if (is_cflow(&(insn[i]))) {
            free(insn_buf);
            cs_free(insn, count);
            return n;
        }
    }

    if (is_mapped(PAGE_ALIGN(addr) + PAGE_SZ, s_binary)) {
        free(insn_buf);
        cs_free(insn, count);
        return opcodes_cflow(addr + n, s_binary);
    }

    return -1;
}

// =====

// returns the length of the instruction for which target points to
off_t insn_len(unsigned long target, mdata_binary_t* s_binary) {
    csh handle;
	cs_insn *insn;
    ssize_t count;
    unsigned long size;
    char buf_insn[16] = {0};

    if (!is_mapped(target, s_binary)) {
        return -1;
    }

    memcpy(buf_insn, (void* )target, ~(PAGE_OFFT(target)) > 15 ? 15 : ~(PAGE_OFFT(target)));

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return -1;
    }

    count = cs_disasm(handle, buf_insn, size, 0, 0, &insn);

    off_t ret = insn[0].size;

    cs_free(insn, count);
    return ret;
}

// =-=-=-=-=--

int craft_trampoline_restore(unsigned char* patch, mdata_binary_t* s_binary) {
    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode;
    size_t size;
    char insns[64] = {0};

    sprintf(insns, "movabs rax, [%p]", &(s_binary->dbi_handler->state->rax));
    puts(insns);
    err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
    if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), quit\n");
        return -1;
    }

    if (ks_asm(ks, insns, 0, &encode, &size, &count) != KS_ERR_OK) {
        printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
                count, ks_errno(ks));
        return -1;
    }

    memcpy(patch, encode, size);

    return size;
}

// encodes the patch used as a trampoline in @patch to @target, returns -1 if it fails and else the length of the patch 
int hook(unsigned char* patch, mdata_binary_t* s_binary) {
    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode;
    size_t size;
    char insns[64] = {0};

    sprintf(insns, "movabs [0x%lx], rax; mov rax, %p; jmp rax", &(s_binary->dbi_handler->state->rax), s_binary->dbi_handler->dump_stub);
    puts(insns);
    err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
    if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), quit\n");
        return -1;
    }

    if (ks_asm(ks, insns, 0, &encode, &size, &count) != KS_ERR_OK) {
        printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
                count, ks_errno(ks));
        return -1;
    }

    memcpy(patch, encode, size);

    return size;
}

// =-=-=-=-=--

// unsigned long hook_reloc(mdata_binary_t* s_binary) {
//     unsigned char *reloc = mmap(RELOC_ADDR_RESTORE, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);

//     if (MAP_FAILED == reloc) {
//         return -1;
//     }

//     return (unsigned long)reloc;
// }

// returns the newly mmapped shellcode that dumps the state of the guest into the state struct
unsigned long craft_hook(mdata_binary_t* s_binary) {
    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode = mmap(STUB_ADDR_DUMP, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    size_t size;
    char insns[3000] = {0};

    if (MAP_FAILED == encode) {
        return -1;
    }

    s_binary->dbi_handler->dump_stub = encode;
    s_binary->dbi_handler->state->null_entry = 0x0; // useless
    sprintf(insns, "         mov rax, rbx;\
                             movabs [%p], rax; \
                             mov rax, rcx;\
                             movabs [%p], rax; \
                             mov rax, rdx;\
                             movabs [%p], rax; \
                             mov rax, rsi;\
                             movabs [%p], rax; \
                             mov rax, rdi;\
                             movabs [%p], rax; \
                             mov rax, rsp;\
                             movabs [%p], rax; \
                             mov rax, rbp;\
                             movabs [%p], rax; \
            pushfq; pop rax; movabs [%p], rax; \
                mov rax, es; movabs [%p], rax; \
                mov rax, gs; movabs [%p], rax; \
                mov rax, fs; movabs [%p], rax; \
                mov rax, cs; movabs [%p], rax; \
                mov rax, ss; movabs [%p], rax; \
                mov rax, ds; movabs [%p], rax; \
                             mov rax, r8;\
                             movabs [%p], rax; \
                             mov rax, r9;\
                             movabs [%p], rax; \
                             mov rax, r10;\
                             movabs [%p], rax; \
                             mov rax, r11;\
                             movabs [%p], rax; \
                             mov rax, r12;\
                             movabs [%p], rax; \
                             mov rax, r13;\
                             movabs [%p], rax; \
                             mov rax, r14;\
                             movabs [%p], rax; \
                             mov rax, r15;\
                             movabs [%p], rax; \
                             mov rsp, 0x%lx;\
                             mov rdi, 0x%lx; \
                             mov rax, 0x%lx; \
                             jmp rax", &(s_binary->dbi_handler->state->rbx), &(s_binary->dbi_handler->state->rcx), \
                                                           &(s_binary->dbi_handler->state->rdx), &(s_binary->dbi_handler->state->rsi), &(s_binary->dbi_handler->state->rdi), \
                                                           &(s_binary->dbi_handler->state->rsp), &(s_binary->dbi_handler->state->rbp), \
                                                           &(s_binary->dbi_handler->state->rflags), &(s_binary->dbi_handler->state->es), &(s_binary->dbi_handler->state->gs), \
                                                           &(s_binary->dbi_handler->state->fs), &(s_binary->dbi_handler->state->cs), &(s_binary->dbi_handler->state->ss), \
                                                           &(s_binary->dbi_handler->state->ds), &(s_binary->dbi_handler->state->r8), &(s_binary->dbi_handler->state->r9), \
                                                           &(s_binary->dbi_handler->state->r10), &(s_binary->dbi_handler->state->r11), &(s_binary->dbi_handler->state->r12), \
                                                           &(s_binary->dbi_handler->state->r13), &(s_binary->dbi_handler->state->r14), &(s_binary->dbi_handler->state->r15), \
                                                           (unsigned long)(s_binary->dbi_handler->host_rsp), s_binary, (unsigned long)(s_binary->dispatcher));

    err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
    if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), quit\n");
        return -1;
    }

    if (ks_asm(ks, insns, 0, &encode, &size, &count) != KS_ERR_OK) {
        printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
                count, ks_errno(ks));
        puts(insns);
        return -1;
    }

    memcpy(STUB_ADDR_DUMP, encode, size);

    return STUB_ADDR_DUMP;
}

unsigned long craft_restore_stub(mdata_binary_t* s_binary) {
    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode = mmap(STUB_ADDR_RESTORE, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    size_t size;
    char insns[2048] = {0};

    if (MAP_FAILED == encode) {
        return -1;
    }

    s_binary->dbi_handler->restore_stub = STUB_ADDR_RESTORE;

    sprintf(insns, "         movabs rax, [%p]; \
                             mov rbx, rax;   \
                             movabs rax, [%p]; \
                             mov rcx, rax; \
                             movabs rax, [%p]; \
                             mov rdx, rax; \
                             movabs rax, [%p]; \
                             mov rdi, rax; \
                             movabs rax, [%p]; \
                             mov rsi, rax; \
                             movabs rax, [%p]; \
                             mov rbp, rax; \
                movabs rax, [%p]; mov es, rax; \
                movabs rax, [%p]; mov gs, rax; \
                movabs rax, [%p]; mov fs, rax; \
                movabs rax, [%p]; mov cs, rax; \
                movabs rax, [%p]; mov ss, rax; \
                movabs rax, [%p]; mov ds, rax; \
                             movabs rax, [%p]; \
                             mov r8, rax; \
                             movabs rax, [%p]; \
                             mov r9, rax; \
                             movabs rax, [%p]; \
                             mov r10, rax; \
                             movabs rax, [%p]; \
                             mov r11, rax; \
                             movabs rax, [%p]; \
                             mov r12, rax; \
                             movabs rax, [%p]; \
                             mov r13, rax; \
                             movabs rax, [%p]; \
                             mov r14, rax; \
                             movabs rax, [%p]; \
                             mov r15, rax; \
                    movabs rax, [%p]; push rax; \
                    movabs rax, [%p]; push rax; \
                             popfq; \
                             pop rsp; \
                             movabs rax, [%p]; \
                             jmp rax", &(s_binary->dbi_handler->state->rbx), &(s_binary->dbi_handler->state->rcx), &(s_binary->dbi_handler->state->rdx), \
                                                           &(s_binary->dbi_handler->state->rdi), &(s_binary->dbi_handler->state->rsi), &(s_binary->dbi_handler->state->rbp), \
                                                           &(s_binary->dbi_handler->state->es), &(s_binary->dbi_handler->state->gs), &(s_binary->dbi_handler->state->fs), \
                                                           &(s_binary->dbi_handler->state->cs), &(s_binary->dbi_handler->state->ss), &(s_binary->dbi_handler->state->ds), \
                                                           &(s_binary->dbi_handler->state->r8), &(s_binary->dbi_handler->state->r9), &(s_binary->dbi_handler->state->r10), \
                                                           &(s_binary->dbi_handler->state->r11), &(s_binary->dbi_handler->state->r12), &(s_binary->dbi_handler->state->r13), \
                                                           &(s_binary->dbi_handler->state->r14), &(s_binary->dbi_handler->state->r15), &(s_binary->dbi_handler->state->rsp), &(s_binary->dbi_handler->state->rflags), \
                                                           &(s_binary->dbi_handler->jmp_restore));

    err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
    if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), quit\n");
        return -1;
    }

    if (ks_asm(ks, insns, 0, &encode, &size, &count) != KS_ERR_OK) {
        printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
                count, ks_errno(ks));
        puts(insns);
        return -1;
    }

    memcpy(STUB_ADDR_RESTORE, encode, size);
    return (unsigned long)STUB_ADDR_RESTORE;
}

// =-=-=-=-=--

// main instrumentation abstraction
int instrument(mdata_binary_t* s_binary, u_callback_t callback, arg_t* arguments) {
    unsigned long entry = (unsigned long)(s_binary->interp ? s_binary->interp->eh->e_entry + (s_binary->interp->base) : s_binary->eh->e_entry + s_binary->base);
    s_binary->dbi_handler->curr_hook = calloc(1, sizeof(unsigned long));
    s_binary->dbi_handler->host_rsp = (unsigned long)map_stack() + 8;
    s_binary->dispatcher = _dispatcher;

    alloc_state(s_binary);
    if (-1 == craft_hook(s_binary) || -1 == craft_restore_stub(s_binary)) {
        return -1;
    }

    s_binary->dbi_handler->trampoline = calloc(1, 256);
    ssize_t size_trampoline = (ssize_t)hook(s_binary->dbi_handler->trampoline, s_binary);
    if (-1 == size_trampoline) {
        return -1;
    }
    realloc(s_binary->dbi_handler->trampoline, size_trampoline+1);
    s_binary->dbi_handler->trampoline[size_trampoline] = 0x0;
    s_binary->dbi_handler->length_trampoline = size_trampoline;
    // main hook trampoline

    // restore hook trampoline
    s_binary->dbi_handler->trampoline_restore = calloc(1, 256);
    ssize_t size_trampoline_restore = craft_trampoline_restore(s_binary->dbi_handler->trampoline_restore);
    if (-1 == size_trampoline_restore) {
        return -1;
    }
    realloc(s_binary->dbi_handler->trampoline_restore, size_trampoline_restore+1);
    s_binary->dbi_handler->trampoline_restore[size_trampoline_restore] = 0x0;
    s_binary->dbi_handler->length_trampoline_restore = size_trampoline_restore;
    

    s_binary->dbi_handler->hashmap = calloc(1, sizeof(hashmap_t));
    s_binary->dbi_handler->u_handler = callback;

    *(s_binary->dbi_handler->curr_hook) = entry + _instrument(s_binary, entry, s_binary->dbi_handler->trampoline);

    s_binary->dbi_handler->take_callback = true;
    exec_binary(s_binary, arguments->argv, arguments->argc);
    return 0;
}

// internal part, returns the offset right after the cflow instruction
int _instrument(mdata_binary_t* s_binary, unsigned long target, unsigned char* trampoline) {
    off_t off_cflow = opcodes_cflow(target, s_binary);

    if (-1 == off_cflow) {
        return -1;
    }

    memcpy(s_binary->dbi_handler->orig_bytes, (void* )(target+off_cflow), s_binary->dbi_handler->length_trampoline);
    if (mprotect(PAGE_ALIGN((target+off_cflow)), PAGE_SZ, prot(target, s_binary) | PROT_WRITE)) {
        return -1;
    }

    memcpy((void* )(target+off_cflow), trampoline, s_binary->dbi_handler->length_trampoline);
    if (mprotect(PAGE_ALIGN((target+off_cflow)), PAGE_SZ, prot(target, s_binary))) {
        return -1;
    }

    return off_cflow;
}

// restore the s_binary->orig_bytes at s_binary->curr_hook
int restore_bytes(mdata_binary_t* s_binary) {
    //memcpy((void* )*(s_binary->dbi_handler->curr_hook), s_binary->dbi_handler->orig_bytes, s_binary->dbi_handler->length_trampoline);
    
    for (size_t i = 0; i < s_binary->dbi_handler->length_trampoline; i++) {
        ((unsigned char* )s_binary->dbi_handler->curr_hook)[i] = s_binary->dbi_handler->orig_bytes[i];
    }

    return 0;
}

void _dispatcher(mdata_binary_t* s_binary) {
    if (s_binary->dbi_handler->take_callback) {
        s_binary->dbi_handler->u_handler(s_binary);
    }

    if (s_binary->dbi_handler->jmp_restore) {
        
    }

    restore_bytes(s_binary);
    unsigned long target = eval_target((void* )*(s_binary->dbi_handler->curr_hook), s_binary);
    off_t offset_cflow = _instrument(s_binary, 
                                     target, 
                                     s_binary->dbi_handler->trampoline);

    
    s_binary->dbi_handler->jmp_restore = *(s_binary->dbi_handler->curr_hook) - s_binary->dbi_handler->length_trampoline_restore;
    if (mprotect(PAGE_ALIGN(s_binary->dbi_handler->jmp_restore), PAGE_SZ, prot(s_binary->dbi_handler->jmp_restore, s_binary) | PROT_WRITE)) {
        return -1;
    }
    memcpy((void* )(s_binary->dbi_handler->jmp_restore), s_binary->dbi_handler->trampoline_restore, s_binary->dbi_handler->length_trampoline_restore);
    if (mprotect(PAGE_ALIGN(s_binary->dbi_handler->jmp_restore), PAGE_SZ, prot(s_binary->dbi_handler->jmp_restore, s_binary))) {
        return -1;
    }

    *(s_binary->dbi_handler->curr_hook) = target + offset_cflow;
    continue_exec(s_binary);
}

unsigned long eval_target(unsigned char* instruction, mdata_binary_t* s_binary) {
    unsigned long target = 0x0;
    csh handle;
	cs_insn *insn;
    ssize_t count;
    unsigned long size;
    char buf_insn[16] = {0};

    if (instruction) {
        return -1;
    }

    memcpy(buf_insn, instruction, 15);

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return -1;
    }

    count = cs_disasm(handle, buf_insn, size, 0, 0, &insn);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_detail* details = insn->detail;
    cs_x86* x86 = &details->x86;

    if (x86->op_count) {
        cs_x86_op* operand = &(x86->operands[0]);
        switch (operand->type)
        {
        case X86_OP_REG:
            target = read_reg(operand->reg, s_binary->dbi_handler->hashmap);
        case X86_OP_IMM:
            target = (unsigned long)operand->imm;
        case X86_OP_MEM:
            // no need to perform checks about the sanity of the index, base & segment registers cause if a reg is invalid it will return 0
            target = read_reg(operand->mem.base, s_binary->dbi_handler->hashmap)
                   + read_reg(operand->mem.index, s_binary->dbi_handler->hashmap)
                   * operand->mem.scale
                   + operand->mem.disp;
        default:
            target = -1;
        }
    }

    if (is_ret(insn)) {
        target = *((unsigned long* )read_reg(X86_REG_RSP, s_binary->dbi_handler->hashmap));
    }

    cs_free(insn, count);
    return target;
}

// =-=-=-=-

void continue_exec(mdata_binary_t* s_binary) {
    __asm__ __volatile__ (
        "mov %0, %%rax\n"
        "jmp *%%rax\n" // shitty at&t
        :: "r"(s_binary->dbi_handler->restore_stub):);
}

void alloc_state(mdata_binary_t* s_binary) {
    s_binary->dbi_handler->state = calloc(1, sizeof(state_rtime_t));
}