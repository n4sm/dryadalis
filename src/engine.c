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
#include <sys/types.h>
#include <sys/syscall.h>
#include <asm/ldt.h>   
#include <asm/prctl.h>
#include <sys/prctl.h>

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <keystone/keystone.h>

#include "../include/dryadalis_x86.h"

// =-=-=-=-=--

int set_fs_gs(void* fs, void* gs) {
    if (-1 == arch_prctl(ARCH_SET_FS, fs) || -1 == arch_prctl(ARCH_SET_GS, gs)) {
        return -1;
    }
    return 0;
}

int save_fs_gs(unsigned long* fs, unsigned long* gs) {
    if (-1 == arch_prctl(ARCH_GET_FS, fs) || -1 == arch_prctl(ARCH_GET_GS, gs)) {
        return -1;
    }
    return 0;
}

int arch_prctl(int func, void *ptr) {
    return syscall(__NR_arch_prctl, func, ptr);
}

// =-=-=-=-=--

// check if an instruction will change the control flow
_Bool is_cflow(int group) {
    if ((group == X86_GRP_CALL)) {
        return true;
    } else if (group == X86_GRP_INT) {
        return true;
    } else if (group == X86_GRP_JUMP) {
        return true;
    } else if (group == X86_GRP_RET) {
        return true;
    } else if (group == X86_GRP_BRANCH_RELATIVE) {
        return true;
    }

    return false;
}

_Bool is_ret(int group) {
    return (group == X86_GRP_RET);
}

_Bool is_call(int group) {
    return (group == X86_GRP_CALL);
}

_Bool is_interrupt(int group) {
    return group == X86_GRP_INT;
}

_Bool is_endbr64(unsigned char* s) {
    return !memcmp(s, "\xf3\x0f\x1e\xfa", 4);
}

// returns how much byte there is up to the first cflow instruction, returns -1 if it fails
int opcodes_cflow(unsigned long addr, mdata_binary_t* s_binary, _Bool beg) {
    csh handle;
    unsigned char insn_buffer[PAGE_SZ] = {0};
    unsigned long saved_addr = addr;
    unsigned char* insn_buf = insn_buffer;
    
    size_t size = PAGE_SZ;
    int n = 0;

    if (!is_mapped(addr + size-1, s_binary)) {
        fprintf(stderr, "FATAL addr + size is not mapped\n");
        return -1;
    }

    if (!is_mapped(addr, s_binary)) {
        fprintf(stderr, "0x%lx is not mapped\n", addr);
        return -1;
    }

    memcpy(insn_buf, (unsigned char* )addr, size);

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "FATAL capstone\n");
        return -1;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn = cs_malloc(handle);

    if (!insn) {
        exit(-1);
    }

    // if (size > 4) {
    //     if (is_endbr64((unsigned char* )addr)) {
    //         if (DEBUG) {
    //             fprintf(stdout, "0x%lx:\t%s\n", addr, "endbr64");
    //         }

    //         addr += 4;
    //         size -= 4;
    //         insn_buf += 4;
    //         n += 4;
    //     }
    // }

    while(cs_disasm_iter(handle, (const uint8_t **)&insn_buf, &size, &addr, insn)) {
        // if (size > 4) {
        //     if (is_endbr64((unsigned char* )addr)) {
        //         if (DEBUG) {
        //             fprintf(stdout, "0x%lx:\t%s\n", addr, "endbr64");
        //         }
                
        //         size -= 4;
        //         n += 4;
        //         addr += 4;
        //         insn_buf += 4;
        //         continue;
        //     }
        // }

        if (DEBUG) {
            fprintf(stdout, "0x%"PRIx64":\t%s\t\t%s\n", insn->address, insn->mnemonic, insn->op_str);
        }
        
        for (size_t i = 0; i < insn->detail->groups_count; i++) {
            if (is_cflow(insn->detail->groups[i]) && (!beg || insn->detail->groups[i] != X86_GRP_INT)) {
                cs_free(insn, 1);
                return n;
            }
        }

        n += insn->size;
        beg = false;
    }

    if (is_mapped((addr), s_binary) && addr != saved_addr) {
        // if the page next to the current page is mapped we call opcode_cflow onto it
        if (DEBUG) {
            fprintf(stdout, "recurr call, size: %lx, addr: %lx\n", size, addr-insn->size);
        }
        
        cs_free(insn, 1);
        return opcodes_cflow(addr, s_binary, false);
    }

    cs_free(insn, 1);
    fprintf(stderr, "FATAL found nothing\n");
    return -1;
}

// =====

// returns the length of the instruction for which target points to
off_t insn_len(unsigned long target, mdata_binary_t* s_binary) {
    csh handle;
	cs_insn *insn;
    ssize_t count;
    char buf_insn[16] = {0};

    if (!is_mapped(target, s_binary)) {
        return -1;
    }

    memcpy(buf_insn, (void* )target, ~(PAGE_OFFT(target)) > 15 ? 15 : ~(PAGE_OFFT(target)));

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return -1;
    }

    count = cs_disasm(handle, (const uint8_t *)buf_insn, 15, 0, 0, &insn);

    off_t ret = insn[0].size;

    cs_free(insn, count);
    return ret;
}

// =-=-=-=-=--

int restore_hook(unsigned char* patch, mdata_binary_t* s_binary) {
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
int dump_hook(unsigned char* patch, mdata_binary_t* s_binary) {
    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode;
    size_t size;
    char insns[64] = {0};

    sprintf(insns, "movabs [%p], rax; mov rax, %p; jmp rax", &(s_binary->dbi_handler->state->rax), s_binary->dbi_handler->dump_stub);
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
    unsigned char *encode = mmap((void* )STUB_ADDR_DUMP, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    size_t size;
    char insns[3000] = {0};

    if (MAP_FAILED == encode) {
        return -1;
    }

    s_binary->dbi_handler->dump_stub = encode;
    sprintf(insns, "         mov rax, rsp;\
                             movabs [%p], rax; \
                             mov rsp, 0x%lx;\
            pushfq; pop rax; movabs [%p], rax; \
                             mov rax, rbx;\
                             movabs [%p], rax; \
                             mov rax, rcx;\
                             movabs [%p], rax; \
                             mov rax, rdx;\
                             movabs [%p], rax; \
                             mov rax, rsi;\
                             movabs [%p], rax; \
                             mov rax, rdi;\
                             movabs [%p], rax; \
                             mov rax, rbp;\
                             movabs [%p], rax; \
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
                             mov rdi, 0x%lx; \
                             mov rax, 0x%lx; \
                             push 0x0;\
                             push rax;\
                             movabs rax, [%p];\
                             movabs [%p], rax;\
                             ret", &(s_binary->dbi_handler->state->rsp), (unsigned long)(s_binary->dbi_handler->host_rsp), &(s_binary->dbi_handler->state->rflags), &(s_binary->dbi_handler->state->rbx), &(s_binary->dbi_handler->state->rcx), \
                                                           &(s_binary->dbi_handler->state->rdx), &(s_binary->dbi_handler->state->rsi), &(s_binary->dbi_handler->state->rdi), \
                                                           &(s_binary->dbi_handler->state->rbp), \
                                                           &(s_binary->dbi_handler->state->es), &(s_binary->dbi_handler->state->gs), \
                                                           &(s_binary->dbi_handler->state->fs), &(s_binary->dbi_handler->state->cs), &(s_binary->dbi_handler->state->ss), \
                                                           &(s_binary->dbi_handler->state->ds), &(s_binary->dbi_handler->state->r8), &(s_binary->dbi_handler->state->r9), \
                                                           &(s_binary->dbi_handler->state->r10), &(s_binary->dbi_handler->state->r11), &(s_binary->dbi_handler->state->r12), \
                                                           &(s_binary->dbi_handler->state->r13), &(s_binary->dbi_handler->state->r14), &(s_binary->dbi_handler->state->r15), \
                                                           (unsigned long)s_binary, (unsigned long)(s_binary->dispatcher), s_binary->dbi_handler->curr_hook, &(s_binary->dbi_handler->state->rip));

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

    memcpy((void* )STUB_ADDR_DUMP, encode, size);
    return STUB_ADDR_DUMP;
}

unsigned long craft_restore_stub(mdata_binary_t* s_binary) {
    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode = mmap((void* )STUB_ADDR_RESTORE, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    size_t size;
    char insns[25000] = {0};

    if (MAP_FAILED == encode) {
        return -1;
    }

    s_binary->dbi_handler->restore_stub = (unsigned char* )STUB_ADDR_RESTORE;

    sprintf(insns, "            movabs rax, [%p]; \
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
                                push rax;\
                                movabs rax, [%p];\
                                ret;", &(s_binary->dbi_handler->state->rbx), &(s_binary->dbi_handler->state->rcx), &(s_binary->dbi_handler->state->rdx), \
                                                            &(s_binary->dbi_handler->state->rdi), &(s_binary->dbi_handler->state->rsi), &(s_binary->dbi_handler->state->rbp), \
                                                            &(s_binary->dbi_handler->state->es), &(s_binary->dbi_handler->state->gs), &(s_binary->dbi_handler->state->fs), \
                                                            &(s_binary->dbi_handler->state->ss), &(s_binary->dbi_handler->state->ds), \
                                                            &(s_binary->dbi_handler->state->r8), &(s_binary->dbi_handler->state->r9), &(s_binary->dbi_handler->state->r10), \
                                                            &(s_binary->dbi_handler->state->r11), &(s_binary->dbi_handler->state->r12), &(s_binary->dbi_handler->state->r13), \
                                                            &(s_binary->dbi_handler->state->r14), &(s_binary->dbi_handler->state->r15), &(s_binary->dbi_handler->state->rsp), &(s_binary->dbi_handler->state->rflags), \
                                                            &(s_binary->dbi_handler->state->rip), &s_binary->dbi_handler->state->rax);

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

    memcpy((void* )STUB_ADDR_RESTORE, encode, size);
    return (unsigned long)STUB_ADDR_RESTORE;
}

int host_save_state(state_rtime_t* state) {
    __asm__ __volatile__ (
        "mov %%fs, %0\n"
        "mov %%cs, %1\n"
        "mov %%gs, %2\n"
        "mov %%ds, %3\n"
        "mov %%ss, %4\n"
        // "mov %%rax, %5\n"
        // "mov %%rbx, %6\n"
        // "mov %%rcx, %7\n"
        // "mov %%rdx, %8\n"
        // "mov %%rsi, %9\n"
        // "mov %%rdi, %10\n"
        // "mov %%rbp, %11\n"
        // "mov %%rsp, %12\n"
        // "mov %%r8, %13\n"
        // "mov %%r9, %14\n"
        // "mov %%r10, %15\n"
        // "mov %%r11, %16\n"
        // "mov %%r12, %17\n"
        // "mov %%r13, %18\n"
        // "mov %%r14, %19\n"
        // "mov %%r15, %20\n"
        // :   , "=m"(state->rax), "=m"(state->rbx),
        //     "=m"(state->rcx), "=m"(state->rdx), "=m"(state->rsi), "=m"(state->rdi), "=m"(state->rbp), "=m"(state->rsp), "=m"(state->r8),
        //     "=m"(state->r9), "=m"(state->r10), "=m"(state->r11), "=m"(state->r12), "=m"(state->r13), "=m"(state->r14), "=m"(state->r15)
        :"=m"(state->fs), "=m"(state->cs), "=m"(state->gs), "=m"(state->ds), "=m"(state->ss): :);

    return 0;
}

// =-=-=-=-=--

// main instrumentation abstraction
int instrument(mdata_binary_t* s_binary, u_callback_t callback) {
    unsigned long entry = (unsigned long)(s_binary->interp ? s_binary->interp->eh->e_entry + (s_binary->interp->base) : s_binary->eh->e_entry + s_binary->base);
    s_binary->dbi_handler->curr_hook = calloc(1, sizeof(unsigned long));
    s_binary->dbi_handler->host_rsp = (unsigned long* )((map_stack()));
    s_binary->dispatcher = (unsigned long)_dispatcher;

    if (-1 == craft_hook(s_binary) || -1 == craft_restore_stub(s_binary)) {
        return -1;
    }

    s_binary->dbi_handler->dump->code = calloc(1, 256);
    ssize_t size_trampoline = (ssize_t)dump_hook(s_binary->dbi_handler->dump->code, s_binary);
    if (-1 == size_trampoline) {
        return -1;
    }
    if (!realloc(s_binary->dbi_handler->dump->code, size_trampoline)) {
        exit(-1);
    }
    s_binary->dbi_handler->dump->length = size_trampoline;
    s_binary->dbi_handler->dump->jmp = entry;
    // main hook trampoline

    // restore hook trampoline
    // s_binary->dbi_handler->restore->code = calloc(1, 256);
    // ssize_t size_trampoline_restore = restore_hook(s_binary->dbi_handler->restore->code, s_binary);
    // if (-1 == size_trampoline_restore) {
    //     return -1;
    // }
    // if (!realloc(s_binary->dbi_handler->restore->code, size_trampoline_restore)) {
    //     exit(-1);
    // }
    // s_binary->dbi_handler->restore->length = size_trampoline_restore;

    s_binary->dbi_handler->u_handler = callback;

    s_binary->dbi_handler->dump->jmp = entry; // it means we begin to analyse @ entry and 
    *(s_binary->dbi_handler->curr_hook) = _instrument(s_binary, // here the field is updated to target the right cflow instruction 
                                                      s_binary->dbi_handler->dump); // which is rewritten by the hook

    s_binary->dbi_handler->take_callback = true;

    //host_save_state(s_binary->dbi_handler->host_state);
    if (-1 == save_fs_gs(&s_binary->dbi_handler->host_state->fs, &s_binary->dbi_handler->host_state->gs)) {
        exit(-1);
    } else if (-1 == set_fs_gs((void* )INSTRUMENTED_FS, (void* )INSTRUMENTED_GS)) {
        exit(-1);
    }
    exec_binary(s_binary);
    // no return
    return 0;
}

int write_hook(mdata_binary_t* s_binary, hook_t* hook) {
    size_t mprotect_size = (PAGE_OFFT(hook->jmp) + hook->length) > PAGE_SZ ? PAGE_SZ*2 : PAGE_SZ;
    int prot_curr = prot(hook->jmp, s_binary);
    int prot_next = prot(hook->jmp + PAGE_SZ, s_binary);

    if (mprotect_size > PAGE_SZ && !is_mapped(hook->jmp + PAGE_SZ, s_binary)) {
        fprintf(stderr, "PAGE IS NOT MAPPED\n");
        return -1;
    }

    memcpy(hook->orig_bytes, (void* )(hook->jmp), hook->length);
    if (mprotect((void* )PAGE_ALIGN((hook->jmp)), mprotect_size, PROT_READ | PROT_WRITE)) {
        return -1;
    }
    
    // for (size_t i = 0; i < hook->length; i++) {
    //     fprintf(stdout, "%x", hook->orig_bytes[i]);
    // }

    // printf("\n");
    
    memcpy((void* )(hook->jmp), hook->code, hook->length);

    if (mprotect((void* )PAGE_ALIGN((hook->jmp)), PAGE_SZ, prot_curr)) {
        return -1;
    } else if (mprotect((void* )PAGE_ALIGN((hook->jmp+PAGE_SZ)), PAGE_SZ, prot_next))  {
        return -1;
    }

    return 0;
}

// internal part, returns the offset right after the cflow instruction
unsigned long _instrument(mdata_binary_t* s_binary, hook_t* hook) {
    off_t off_cflow = opcodes_cflow(hook->jmp, s_binary, true);

    if (-1 == off_cflow) {
        fprintf(stderr, "FATAL opcodes_cflow\n");
        return -1;
    }

    hook->jmp += off_cflow;
    if (write_hook(s_binary, hook)) {
        return -1;
    }

    return hook->jmp;
}

// restore the s_binary->orig_bytes at s_binary->curr_hook
int restore_bytes(hook_t* hook, mdata_binary_t* s_binary) {
    size_t mprotect_size = (PAGE_OFFT(hook->jmp) + hook->length) > PAGE_SZ ? PAGE_SZ*2 : PAGE_SZ;
    int prot_curr = prot(hook->jmp, s_binary);
    int prot_next = prot(hook->jmp + PAGE_SZ, s_binary);

    if (-1  == mprotect((void* )PAGE_ALIGN(hook->jmp), mprotect_size, PROT_WRITE | PROT_READ)) {
        return -1;
    }

    for (size_t i = 0; i < hook->length; i++) {
        ((unsigned char* )hook->jmp)[i] = hook->orig_bytes[i];
    }

    if (-1  == mprotect((void* )PAGE_ALIGN(hook->jmp), PAGE_SZ, prot_curr)) {
        return -1;
    }

    if (mprotect_size > PAGE_SZ && mprotect((void* )PAGE_ALIGN((hook->jmp + PAGE_SZ)), PAGE_SZ, prot_next)) {
        return -1;
    }

    return 0;
}

void _dispatcher(mdata_binary_t* s_binary) {
    if (-1 == set_fs_gs((void* )s_binary->dbi_handler->host_state->fs, (void* )s_binary->dbi_handler->host_state->gs)) {
        fprintf(stderr, "FATAL arch_prctl\n");
        exit(-1);
    }

    if (s_binary->dbi_handler->take_callback) {
        s_binary->dbi_handler->u_handler(s_binary);
    }

    if (-1 == restore_bytes(s_binary->dbi_handler->dump, s_binary)) {
        fprintf(stderr, "FATAL restore_bytes # dump\n");
        exit(-1);
    }

    if (DEBUG) {
        fprintf(stdout, " = * = [ . ] = * =\n");
    }

    unsigned long target = eval_target((void* )*(s_binary->dbi_handler->curr_hook), s_binary);
    if (-1 == target) {
        fprintf(stderr, "FATAL eval_target \n");
        exit(-1);
    }

    if (DEBUG) {
        fprintf(stdout, "cflow target: 0x%lx\n", target);
    }

    s_binary->dbi_handler->dump->jmp = target;
    if (-1 == _instrument(s_binary, s_binary->dbi_handler->dump)) {
        fprintf(stderr, "FATAL _instrument # dump hook\n");
        exit(-1);
    }

    s_binary->dbi_handler->state->rip = target;
    *(s_binary->dbi_handler->curr_hook) = s_binary->dbi_handler->dump->jmp;
    continue_exec(s_binary);
}
//== internal functions used by eval_target

// Does the instruction tests flags ?
_Bool is_test(unsigned long cs_eflags) {
    return (cs_eflags & (X86_EFLAGS_TEST_AF | X86_EFLAGS_TEST_CF | X86_EFLAGS_TEST_DF | X86_EFLAGS_TEST_IF | X86_EFLAGS_TEST_OF | X86_EFLAGS_TEST_SF | X86_EFLAGS_TEST_TF | X86_EFLAGS_TEST_ZF)) != 0;
}

// return true if the target flag is set in @eflags
_Bool is_set(mdata_binary_t* s_binary, int flag) {
    if (DEBUG) {
        fprintf(stdout, "eflags & flag: %lx & %x = %lx\n", read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap), flag, (read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap) & flag));
    }

    unsigned long eflags = read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap);
    
    if (-1 == eflags) {
        fprintf(stderr, "FATAL read eflags\n");
        exit(-1);
    }

    return (eflags & flag) != 0;
}

_Bool is_jmp_taken(int id, mdata_binary_t* s_binary) {
    switch (id) {
        case X86_INS_JE:
            return is_set(s_binary, ZF);
        case X86_INS_JNE:
            return !is_set(s_binary, ZF);
        
        case X86_INS_JA:
            return !is_set(s_binary, CF) && !is_set(s_binary, ZF);
        case X86_INS_JAE:
            return !is_set(s_binary, CF);
    
        case X86_INS_JB:
            return is_set(s_binary, CF);
        case X86_INS_JBE:
            return is_set(s_binary, CF) || is_set(s_binary, ZF);

        case X86_INS_JCXZ:
            return !read_reg(X86_REG_CX, s_binary->dbi_handler->hashmap);
        case X86_INS_JECXZ:
            return !read_reg(X86_REG_ECX, s_binary->dbi_handler->hashmap);
        case X86_INS_JRCXZ:
            return !read_reg(X86_REG_RCX, s_binary->dbi_handler->hashmap);

        case X86_INS_JG:
            return !is_set(s_binary, ZF) && !is_set(s_binary, SF);
        case X86_INS_JGE:
            return  (((read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap) & SF) >> SF) == ((read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap) & OF) >> OF));

        case X86_INS_JL:
            return !is_set(s_binary, ZF) && !is_set(s_binary, SF);
        case X86_INS_JLE:
            return is_set(s_binary, ZF) || ((read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap) & SF) >> SF) != ((read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap) & OF) >> OF);

        case X86_INS_JO:
            return is_set(s_binary, OF);
        case X86_INS_JNO:
            return !is_set(s_binary, OF);

        case X86_INS_JP:
            return is_set(s_binary, PF);
        case X86_INS_JNP:
            return !is_set(s_binary, PF);

        case X86_INS_JS:
            return is_set(s_binary, SF);
        case X86_INS_JNS:
            return !is_set(s_binary, SF);

        case X86_INS_JMP:
            return true;

        default:
            return false;
    }
}

// ((read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap) & SF) >> SF) != ((read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap) & OF) >> F)

long sign_extend(size_t size, unsigned long value) {
    return (unsigned long) ((value & (1 << (size-1))) | ((value << 1) >> 1));
}

unsigned long eval_target(unsigned char* instruction, mdata_binary_t* s_binary) {
    csh handle;
	cs_insn *insn;
    ssize_t count;
    char buf_insn[16] = {0};
    _Bool achieve = false;

    if (!instruction) {
        return -1;
    }

    memcpy(buf_insn, instruction, 15);
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return -1;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    count = cs_disasm(handle, (const uint8_t *)buf_insn, 15, 0, 1, &insn);

    cs_detail* details = insn->detail;
    cs_x86* x86 = &(details->x86);

    for (size_t i = 0; i < details->groups_count; i++) {
        if (details->groups[i] == X86_GRP_JUMP || details->groups[i] == X86_GRP_BRANCH_RELATIVE || is_call(details->groups[i])) {
            if (is_call(details->groups[i]) || is_jmp_taken(insn->id, s_binary)) {
                cs_x86_op* operand = &(x86->operands[0]);

                if (DEBUG) {
                    fprintf(stdout, " taken ");
                }

                if (is_call(details->groups[i]) && !achieve) {
                    // we emulate the call instruction
                    s_binary->dbi_handler->state->rsp -= 8;

                    if (!is_mapped(s_binary->dbi_handler->state->rsp, s_binary)) {
                        fprintf(stdout, ">.< rsp [ %lx ] sama is not mapped anymore\n", s_binary->dbi_handler->state->rsp);
                        return -1;
                    }

                    *(unsigned long* )s_binary->dbi_handler->state->rsp = s_binary->dbi_handler->state->rip + insn->size;
                    achieve = true;
                }

                switch (operand->type) {
                    unsigned long base, index;
                    case X86_OP_REG:
                        cs_free(insn, count);
                        return read_reg(operand->reg, s_binary->dbi_handler->hashmap);
                    case X86_OP_IMM:
                        cs_free(insn, count);
                        return (unsigned long)(((sign_extend(operand->size, operand->imm) << 1) >> 1) + s_binary->dbi_handler->state->rip);
                    case X86_OP_MEM:
                        // no need to perform checks about the sanity of the index, base & segment registers cause if a reg is invalid it will return 0
                        base = read_reg(operand->mem.base, s_binary->dbi_handler->hashmap);
                        if (operand->mem.index != X86_REG_INVALID) {
                            index = read_reg(operand->mem.index, s_binary->dbi_handler->hashmap);
                        } else {
                            index = 0x0;
                        }

                        if (-1 != base && -1 != index) {
                            if (operand->mem.base == X86_REG_RIP) {
                                base += insn->size;
                            }

                            if (DEBUG) {
                                fprintf(stdout, "(base [ %x ] => [ %lx ], index [ %x ] => [ %lx ], scale [ %x ], disp [ %lx ]) => %lx\n", operand->mem.base, base, operand->mem.index, index, operand->mem.scale, operand->mem.disp, (base + (index * operand->mem.scale) + operand->mem.disp));
                            }

                            cs_free(insn, count);
                            return *((unsigned long* )(base + index * operand->mem.scale + operand->mem.disp));
                        }

                        fprintf(stderr, "failed to read registers, base [ %x ] => [ %lx ], index [ %x ] => [ %lx ]\n", operand->mem.base, base, operand->mem.index, index);
                        cs_free(insn, count);
                        return -1;

                    default:
                        fprintf(stderr, "error operand jmp\n");
                        return -1;
                }
            } else {
                // jmp not taken
                if (DEBUG) {
                    fprintf(stdout, " not taken ");
                }

                cs_free(insn, count);
                return (unsigned long)(instruction + insn->size);
            }
        } else if (is_ret(details->groups[i])) {
            s_binary->dbi_handler->state->rsp += 8;
            cs_free(insn, count);
            return *((unsigned long* )(read_reg(X86_REG_RSP, s_binary->dbi_handler->hashmap)-8));
        } else if (is_interrupt(details->groups[i])) {
            hook_syscall sys_callback = NULL;
            unsigned long ret = 0x0;
            size_t sz = insn->size;
            
            if (-1 != (sys_callback = get_syscall_hook(s_binary->dbi_handler->state->rax, s_binary))) {
                if ((ret = sys_callback(s_binary->dbi_handler->state))) {
                    // if the control flow is broken we jump on a particular location returned by sys_callback when the return value is != 0
                    cs_free(insn, count);
                    return ret;
                }

                cs_free(insn, count);
                return (unsigned long)(instruction + sz);
            }

            return (unsigned long)instruction;
        }
    }

    // if that's not a return, a call or a jmp it can be an interrupt and we handle that by a diffrent way so we ignore it for now
    cs_free(insn, count);
    return (unsigned long)(instruction + insn->size);
}

// =-=-=-=-

void continue_exec(mdata_binary_t* s_binary) {
    if (-1 == set_fs_gs((void* )INSTRUMENTED_FS, (void* )INSTRUMENTED_GS)) {
        fprintf(stderr, "FATAL arch_prctl\n");
    }

    __asm__ __volatile__ (
        "mov %0, %%rax\n"
        "jmp *%%rax\n" // shitty at&t
        :: "r"(s_binary->dbi_handler->restore_stub):);
}