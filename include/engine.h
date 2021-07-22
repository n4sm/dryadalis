#ifndef ENGINE_H_
#define ENGINE_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libelf.h>
#include <elf.h>
#include <stdbool.h>

#include "elf_parsing.h"
#include "kernel_list.h"
#include "core_mapper.h"

// define

#define OPT_BBL 0x0
#define OPT_SINGLE_STEP 0x1
#define OPT_CFLOW 0x2

#define group_make_link(hashmap, group_reg, reg) \
            for (int i = 0; i < sizeof(group_reg); i++) { \
                make_link(hashmap, group_reg[i], reg);\
            }

#define make_link(hashmap, code_reg, reg) \
            hashmap->value[code_reg] = &(reg)

// structures

typedef int (*u_callback_t) (mdata_binary_t* s_binary);

typedef struct hashmap_s {
    unsigned long** value;
} hashmap_t;

typedef struct dbi_instr_s {
    _Bool take_callback; // internal field
    state_rtime_t* state;
    u_callback_t u_handler;
    unsigned char* orig_bytes;
    ssize_t length_trampoline;
    unsigned char* trampoline;
    unsigned long curr_hook;
    unsigned long *host_rsp;
    hashmap_t* hashmap;
} dbi_instr_t;

typedef struct state_rtime_s {
    unsigned long rax;
    unsigned long rbx;
    unsigned long rcx;
    unsigned long rdx;
    unsigned long rsi;
    unsigned long rdi;
    unsigned long rbp;
    // ==
    unsigned long rsp;
    unsigned long rip;
    unsigned long rflags;
    unsigned long cs;
    unsigned long ss;
    unsigned long gs;
    unsigned long es;
    unsigned long ds;
    unsigned long fs;
    // ==
    unsigned long r8;
    unsigned long r9;
    unsigned long r10;
    unsigned long r11;
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;
} state_rtime_t;

typedef struct arg_s {
    int argc;
    char** argv;
} arg_t;

// functions

// returns how many byte there is up to the first cflow instruction
int opcodes_cflow(unsigned long addr, mdata_binary_t* s_binary);
// encodes the patch used as a trampoline in @patch to @target, returns -1 if it fails and else the length of the patch 
int hook(unsigned char* patch, unsigned long target);
// returns the newly mmapped shellcode that dumps the state of the guest into the state struct
unsigned long craft_hook(mdata_binary_t* s_binary);

int instrument(mdata_binary_t* s_binary, u_callback_t callback, arg_t* arguments);
int _instrument(mdata_binary_t* s_binary, unsigned long target, unsigned char* trampoline);


#endif