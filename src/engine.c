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

#include "../include/core_mapper.h"
#include "../include/elf_parsing.h"

// =-=-=-=-=--

// check if an instruction will change the control flow
_Bool is_cflow(cs_insn *insn) {
    return (insn->id & (X86_GRP_CALL | X86_GRP_INT | X86_GRP_JUMP | X86_GRP_RET)) != 0;
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

// encodes the patch used as a trampoline in @patch to @target, returns -1 if it fails and else the length of the patch 
int hook(unsigned char* patch, unsigned long target) {
    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode;
    size_t size;
    char insns[64] = {0};

    sprintf(insns, "push rax; mov rax, 0x%lx; jmp rax", target);

    err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
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

// returns the newly mmapped shellcode that dumps the state of the guest into the state struct
unsigned long craft_hook(mdata_binary_t* s_binary) {
    ks_engine *ks;
    ks_err err;
    size_t count;
    unsigned char *encode = mmap(NULL, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONNYMOUS, -1, 0);
    size_t size;
    char insns[0x512] = {0};

    s_binary->state = calloc(1, sizeof(state_rtime_t));
    sprintf(insns, "pop rax; mov qword ptr [0x%lx], rax; \
                             mov qword ptr [0x%lx], rbx; \
                             mov qword ptr [0x%lx], rcx; \
                             mov qword ptr [0x%lx], rdx; \
                             mov qword ptr [0x%lx], rsi; \
                             mov qword ptr [0x%lx], rdi; \
                             mov qword ptr [0x%lx], rsp; \
                             mov qword ptr [0x%lx], rbp; \
            pushfq; pop rax; mov qword ptr [0x%lx], rax; \
                mov rax, es; mov qword ptr [0x%lx], rax; \
                mov rax, gs; mov qword ptr [0x%lx], rax; \
                mov rax, fs; mov qword ptr [0x%lx], rax; \
                mov rax, cs; mov qword ptr [0x%lx], rax; \
                mov rax, ss; mov qword ptr [0x%lx], rax; \
                mov rax, ds; mov qword ptr [0x%lx], rax; \
                             mov qword ptr [0x%lx], r8;  \
                             mov qword ptr [0x%lx], r9;  \
                             mov qword ptr [0x%lx], r10; \
                             mov qword ptr [0x%lx], r11; \
                             mov qword ptr [0x%lx], r12; \
                             mov qword ptr [0x%lx], r13; \
                             mov qword ptr [0x%lx], r14; \
                             mov qword ptr [0x%lx], r15;, \
                             mov rsp, qword ptr [0x%lx]; \
                             mov rdi, 0x%lx;\
                             jmp [0x%lx]", &(s_binary->dbi_handler->state->rax), &(s_binary->dbi_handler->state->rbx), &(s_binary->dbi_handler->state->rcx), \
                                                           &(s_binary->dbi_handler->state->rdx), &(s_binary->dbi_handler->state->rsi), &(s_binary->dbi_handler->state->rdi), \
                                                           &(s_binary->dbi_handler->state->rsp), &(s_binary->dbi_handler->state->rbp), &(s_binary->dbi_handler->state->rbp), \
                                                           &(s_binary->dbi_handler->state->rflags), &(s_binary->dbi_handler->state->es), &(s_binary->dbi_handler->state->gs), \
                                                           &(s_binary->dbi_handler->state->fs), &(s_binary->dbi_handler->state->cs), &(s_binary->dbi_handler->state->ss), \
                                                           &(s_binary->dbi_handler->state->ds), &(s_binary->dbi_handler->state->r8), &(s_binary->dbi_handler->state->r9), \
                                                           &(s_binary->dbi_handler->state->r10), &(s_binary->dbi_handler->state->r11), &(s_binary->dbi_handler->state->r12), \
                                                           &(s_binary->dbi_handler->state->r13), &(s_binary->dbi_handler->state->r14), &(s_binary->dbi_handler->state->r15), \
                                                           (s_binary->dbi_handler->host_rsp), s_binary, &(s_binary->dispatcher));

    err = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
    if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open(), quit\n");
        return -1;
    }

    if (ks_asm(ks, insns, 0, &encode, &size, &count) != KS_ERR_OK) {
        printf("ERROR: ks_asm() failed & count = %lu, error = %u\n",
                count, ks_errno(ks));
        return -1;
    }

    return (unsigned long)encode;
}

// =-=-=-=-=--

// main instrumentation abstraction
int instrument(mdata_binary_t* s_binary, u_callback_t callback, arg_t* arguments) {
    unsigned long entry = (unsigned long)(s_binary->interp ? s_binary->interp->eh->e_entry + (s_binary->interp->base) : s_binary->eh->e_entry + s_binary->base);
    unsigned long state_stub = craft_hook(s_binary);

    s_binary->dbi_handler->trampoline = calloc(1, 256);
    ssize_t size_trampoline = (ssize_t)hook(s_binary->dbi_handler->trampoline, state_stub);
    realloc(s_binary->dbi_handler->trampoline, size_trampoline+1);
    s_binary->dbi_handler->trampoline[size_trampoline] = 0x0;
    // we got the right size
    
    s_binary->dbi_handler->hashmap = calloc(1, sizeof(hashmap_t));
    s_binary->dbi_handler->host_rsp = &(arguments->argv[0]) - 8;
    s_binary->dbi_handler->u_handler = callback;
    s_binary->dispatcher = _dispatcher;
    s_binary->dbi_handler->length_trampoline = size_trampoline;
    s_binary->dbi_handler->curr_hook = entry + _instrument(s_binary, entry, s_binary->dbi_handler->trampoline);

    exec_binary(s_binary, arguments->argv, arguments->argc);
    return 0;
}

// internal part, returns the offset right after the cflow instruction
int _instrument(mdata_binary_t* s_binary, unsigned long target, unsigned char* trampoline) {
    off_t off_cflow = opcodes_cflow(target, s_binary);

    if (-1 == off_cflow) {
        return -1;
    }

    memcpy(s_binary->dbi_handler->orig_bytes, (void* )(target+off_cflow), strlen(trampoline));
    if (mprotect(PAGE_ALIGN((target+off_cflow)), PAGE_SZ, prot(target, s_binary) | PROT_WRITE)) {
        return -1;
    }

    memcpy((void* )(target+off_cflow), trampoline, strlen(trampoline));
    if (mprotect(PAGE_ALIGN((target+off_cflow)), PAGE_SZ, prot(target, s_binary))) {
        return -1;
    }

    return off_cflow;
}

// restore the s_binary->orig_bytes at s_binary->curr_hook
int restore_bytes(mdata_binary_t* s_binary) {
    memcpy((void* )s_binary->dbi_handler->curr_hook, s_binary->dbi_handler->orig_bytes, s_binary->dbi_handler->length_trampoline);
    return 0;
}

void _dispatcher(mdata_binary_t* s_binary) {
    if (s_binary->dbi_handler->take_callback) {
        s_binary->dbi_handler->u_handler(s_binary);
    }

    restore_bytes(s_binary);
    s_binary->dbi_handler->curr_hook += _instrument(s_binary, 
                                                    s_binary->dbi_handler->curr_hook + insn_len(s_binary->dbi_handler->curr_hook, s_binary), 
                                                    s_binary->dbi_handler->trampoline);


}

unsigned long eval_target(unsigned char* instruction) {
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

    cs_free(insn, count); 
}