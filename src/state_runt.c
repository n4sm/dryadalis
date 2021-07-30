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
#include <assert.h> 

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <keystone/keystone.h>

#include "../include/dryadalis_x86.h"

const unsigned long x86_reg_c[] = {
	X86_REG_INVALID,
	X86_REG_AH, X86_REG_AL, X86_REG_AX, X86_REG_BH, X86_REG_BL,
	X86_REG_BP, X86_REG_BPL, X86_REG_BX, X86_REG_CH, X86_REG_CL,
	X86_REG_CS, X86_REG_CX, X86_REG_DH, X86_REG_DI, X86_REG_DIL,
	X86_REG_DL, X86_REG_DS, X86_REG_DX, X86_REG_EAX, X86_REG_EBP,
	X86_REG_EBX, X86_REG_ECX, X86_REG_EDI, X86_REG_EDX, X86_REG_EFLAGS,
	X86_REG_EIP, X86_REG_EIZ, X86_REG_ES, X86_REG_ESI, X86_REG_ESP,
	X86_REG_FPSW, X86_REG_FS, X86_REG_GS, X86_REG_IP, X86_REG_RAX,
	X86_REG_RBP, X86_REG_RBX, X86_REG_RCX, X86_REG_RDI, X86_REG_RDX,
	X86_REG_RIP, X86_REG_RIZ, X86_REG_RSI, X86_REG_RSP, X86_REG_SI,
	X86_REG_SIL, X86_REG_SP, X86_REG_SPL, X86_REG_SS, X86_REG_CR0,
	X86_REG_CR1, X86_REG_CR2, X86_REG_CR3, X86_REG_CR4, X86_REG_CR5,
	X86_REG_CR6, X86_REG_CR7, X86_REG_CR8, X86_REG_CR9, X86_REG_CR10,
	X86_REG_CR11, X86_REG_CR12, X86_REG_CR13, X86_REG_CR14, X86_REG_CR15,
	X86_REG_DR0, X86_REG_DR1, X86_REG_DR2, X86_REG_DR3, X86_REG_DR4,
	X86_REG_DR5, X86_REG_DR6, X86_REG_DR7, X86_REG_DR8, X86_REG_DR9,
	X86_REG_DR10, X86_REG_DR11, X86_REG_DR12, X86_REG_DR13, X86_REG_DR14,
	X86_REG_DR15, X86_REG_FP0, X86_REG_FP1, X86_REG_FP2, X86_REG_FP3,
	X86_REG_FP4, X86_REG_FP5, X86_REG_FP6, X86_REG_FP7,
	X86_REG_K0, X86_REG_K1, X86_REG_K2, X86_REG_K3, X86_REG_K4,
	X86_REG_K5, X86_REG_K6, X86_REG_K7, X86_REG_MM0, X86_REG_MM1,
	X86_REG_MM2, X86_REG_MM3, X86_REG_MM4, X86_REG_MM5, X86_REG_MM6,
	X86_REG_MM7, X86_REG_R8, X86_REG_R9, X86_REG_R10, X86_REG_R11,
	X86_REG_R12, X86_REG_R13, X86_REG_R14, X86_REG_R15,
	X86_REG_ST0, X86_REG_ST1, X86_REG_ST2, X86_REG_ST3,
	X86_REG_ST4, X86_REG_ST5, X86_REG_ST6, X86_REG_ST7,
	X86_REG_XMM0, X86_REG_XMM1, X86_REG_XMM2, X86_REG_XMM3, X86_REG_XMM4,
	X86_REG_XMM5, X86_REG_XMM6, X86_REG_XMM7, X86_REG_XMM8, X86_REG_XMM9,
	X86_REG_XMM10, X86_REG_XMM11, X86_REG_XMM12, X86_REG_XMM13, X86_REG_XMM14,
	X86_REG_XMM15, X86_REG_XMM16, X86_REG_XMM17, X86_REG_XMM18, X86_REG_XMM19,
	X86_REG_XMM20, X86_REG_XMM21, X86_REG_XMM22, X86_REG_XMM23, X86_REG_XMM24,
	X86_REG_XMM25, X86_REG_XMM26, X86_REG_XMM27, X86_REG_XMM28, X86_REG_XMM29,
	X86_REG_XMM30, X86_REG_XMM31, X86_REG_YMM0, X86_REG_YMM1, X86_REG_YMM2,
	X86_REG_YMM3, X86_REG_YMM4, X86_REG_YMM5, X86_REG_YMM6, X86_REG_YMM7,
	X86_REG_YMM8, X86_REG_YMM9, X86_REG_YMM10, X86_REG_YMM11, X86_REG_YMM12,
	X86_REG_YMM13, X86_REG_YMM14, X86_REG_YMM15, X86_REG_YMM16, X86_REG_YMM17,
	X86_REG_YMM18, X86_REG_YMM19, X86_REG_YMM20, X86_REG_YMM21, X86_REG_YMM22,
	X86_REG_YMM23, X86_REG_YMM24, X86_REG_YMM25, X86_REG_YMM26, X86_REG_YMM27,
	X86_REG_YMM28, X86_REG_YMM29, X86_REG_YMM30, X86_REG_YMM31, X86_REG_ZMM0,
	X86_REG_ZMM1, X86_REG_ZMM2, X86_REG_ZMM3, X86_REG_ZMM4, X86_REG_ZMM5,
	X86_REG_ZMM6, X86_REG_ZMM7, X86_REG_ZMM8, X86_REG_ZMM9, X86_REG_ZMM10,
	X86_REG_ZMM11, X86_REG_ZMM12, X86_REG_ZMM13, X86_REG_ZMM14, X86_REG_ZMM15,
	X86_REG_ZMM16, X86_REG_ZMM17, X86_REG_ZMM18, X86_REG_ZMM19, X86_REG_ZMM20,
	X86_REG_ZMM21, X86_REG_ZMM22, X86_REG_ZMM23, X86_REG_ZMM24, X86_REG_ZMM25,
	X86_REG_ZMM26, X86_REG_ZMM27, X86_REG_ZMM28, X86_REG_ZMM29, X86_REG_ZMM30,
	X86_REG_ZMM31, X86_REG_R8B, X86_REG_R9B, X86_REG_R10B, X86_REG_R11B,
	X86_REG_R12B, X86_REG_R13B, X86_REG_R14B, X86_REG_R15B, X86_REG_R8D,
	X86_REG_R9D, X86_REG_R10D, X86_REG_R11D, X86_REG_R12D, X86_REG_R13D,
	X86_REG_R14D, X86_REG_R15D, X86_REG_R8W, X86_REG_R9W, X86_REG_R10W,
	X86_REG_R11W, X86_REG_R12W, X86_REG_R13W, X86_REG_R14W, X86_REG_R15W,

	X86_REG_ENDING		// <-- mark the end of the list of registers
};

hashmap_t* init_hashmap(hashmap_t* hashmap, mdata_binary_t* s_binary) {
    hashmap->value = calloc(1, (sizeof(x86_reg_c) / sizeof(x86_reg_c[0])) * sizeof(unsigned long* ));

    for (size_t i = 0; x86_reg_c[i] != X86_REG_ENDING; i++) { // iter through all the elem
        hashmap->value[x86_reg_c[i]] = &(s_binary->dbi_handler->state->null_entry);
    }

    int group_rax[] = {X86_REG_AL, X86_REG_AH, X86_REG_AX, X86_REG_EAX, X86_REG_RAX};
    group_make_link(hashmap, group_rax, s_binary->dbi_handler->state->rax);
    int group_rbx[] = {X86_REG_BL, X86_REG_BH, X86_REG_BX, X86_REG_EBX, X86_REG_RBX};
    group_make_link(hashmap, group_rbx, s_binary->dbi_handler->state->rbx);
    int group_rcx[] = {X86_REG_CL, X86_REG_CH, X86_REG_CX, X86_REG_ECX, X86_REG_RCX};
    group_make_link(hashmap, group_rcx, s_binary->dbi_handler->state->rcx);
    int group_rdx[] = {X86_REG_DL, X86_REG_DH, X86_REG_DX, X86_REG_EDX, X86_REG_RDX};
    group_make_link(hashmap, group_rdx, s_binary->dbi_handler->state->rdx);
    int group_rdi[] = {X86_REG_DIL, X86_REG_DI, X86_REG_EDI, X86_REG_RDI};
    group_make_link(hashmap, group_rdi, s_binary->dbi_handler->state->rdi);

    int group_rsi[] = {X86_REG_SIL, X86_REG_SI, X86_REG_ESI, X86_REG_RSI};
    group_make_link(hashmap, group_rsi, s_binary->dbi_handler->state->rsi);
    int group_rbp[] = {X86_REG_BPL, X86_REG_BP, X86_REG_EBP, X86_REG_RBP};
    group_make_link(hashmap, group_rbp, s_binary->dbi_handler->state->rbp);
    int group_rsp[] = {X86_REG_SPL, X86_REG_SP, X86_REG_ESP, X86_REG_RSP};
    group_make_link(hashmap, group_rsp, s_binary->dbi_handler->state->rsp);

    int group_r8[] = {X86_REG_R8B, X86_REG_R8W, X86_REG_R8D, X86_REG_R8};
    group_make_link(hashmap, group_r8, s_binary->dbi_handler->state->r8);
    int group_r9[] = {X86_REG_R9B, X86_REG_R9W, X86_REG_R9D, X86_REG_R9};
    group_make_link(hashmap, group_r9, s_binary->dbi_handler->state->r9);
    int group_r10[] = {X86_REG_R10B, X86_REG_R10W, X86_REG_R10D, X86_REG_R10};
    group_make_link(hashmap, group_r10, s_binary->dbi_handler->state->r10);
    int group_r11[] = {X86_REG_R11B, X86_REG_R11W, X86_REG_R11D, X86_REG_R11};
    group_make_link(hashmap, group_r11, s_binary->dbi_handler->state->r11);
    int group_r12[] = {X86_REG_R12B, X86_REG_R12W, X86_REG_R12D, X86_REG_R12};
    group_make_link(hashmap, group_r12, s_binary->dbi_handler->state->r12);
    int group_r13[] = {X86_REG_R13B, X86_REG_R13W, X86_REG_R13D, X86_REG_R13};
    group_make_link(hashmap, group_r13, s_binary->dbi_handler->state->r13);
    int group_r14[] = {X86_REG_R14B, X86_REG_R14W, X86_REG_R14D, X86_REG_R14};
    group_make_link(hashmap, group_r14, s_binary->dbi_handler->state->r14);
    int group_r15[] = {X86_REG_R15B, X86_REG_R15W, X86_REG_R15D, X86_REG_R15};
    group_make_link(hashmap, group_r15, s_binary->dbi_handler->state->r15);

    int group_eflags[] = {X86_REG_EFLAGS};
    group_make_link(hashmap, group_eflags, s_binary->dbi_handler->state->rflags);

    return hashmap;
}

// free hashmap
int free_hashmap(hashmap_t* hashmap) {
    free(hashmap->value);
    
    return 0;
}

// it will be quite long and boring but I will code some wrappers around the update_<reg>() functions
void update_reg(int key, hashmap_t* hashmap, unsigned long value) {
    *(hashmap->value[key]) = value;
}

_Bool is_8bits_right(int reg) {
    return (reg == X86_REG_AL) || (reg == X86_REG_BL) || (reg == X86_REG_CL)
                             || (reg == X86_REG_DL) || (reg == X86_REG_DIL) || (reg == X86_REG_SIL) || (reg == X86_REG_BPL) || (reg == X86_REG_SPL)
                             || (reg == X86_REG_R8B) || (reg == X86_REG_R9B) || (reg == X86_REG_R10B) || (reg == X86_REG_R11B) || (reg == X86_REG_R12B) || (reg == X86_REG_R13B)
                             || (reg == X86_REG_R14B) || (reg == X86_REG_R15B);
}

_Bool is_8bits_left(int reg) {
    return (reg == X86_REG_AH) || (reg == X86_REG_BH) || (reg == X86_REG_CH)
                             || (reg == X86_REG_DH);
}

_Bool is_16bits(int reg) {
    return (reg == X86_REG_AX) || (reg == X86_REG_BX) || (reg == X86_REG_CX) || (reg == X86_REG_DX) || (reg == X86_REG_SI) 
                             || (reg == X86_REG_DI) || (reg == X86_REG_BP) || (reg == X86_REG_SP) || (reg == X86_REG_R8W) || (reg == X86_REG_R9W)
                             || (reg == X86_REG_R10W) || (reg == X86_REG_R11W) || (reg == X86_REG_R12W) || (reg == X86_REG_R13W)
                             || (reg == X86_REG_R14W) || (reg == X86_REG_R15W);
}

_Bool is_32bits(int reg) {
    return (reg == X86_REG_EAX) || (reg == X86_REG_EBX) || (reg == X86_REG_ECX) || (reg == X86_REG_EDX) || (reg == X86_REG_ESI)
                             || (reg == X86_REG_EDI) || (reg == X86_REG_EBP) || (reg == X86_REG_ESP) || (reg == X86_REG_R8D) || (reg == X86_REG_R9D)
                             || (reg == X86_REG_R10D) || (reg == X86_REG_R11D) || (reg == X86_REG_R12D) || (reg == X86_REG_R13D)
                             || (reg == X86_REG_R14D) || (reg == X86_REG_R15D);
}

_Bool is_64bits(int reg) {
    return (reg == X86_REG_RAX) || (reg == X86_REG_RBX) || (reg == X86_REG_RCX) || (reg == X86_REG_RDX) || (reg == X86_REG_RSI)
                             || (reg == X86_REG_RDI) || (reg == X86_REG_RBP) || (reg == X86_REG_RSP) || (reg == X86_REG_R8) || (reg == X86_REG_R9)
                             || (reg == X86_REG_R10) || (reg == X86_REG_R11) || (reg == X86_REG_R12) || (reg == X86_REG_R13)
                             || (reg == X86_REG_R14) || (reg == X86_REG_R15) || (reg == X86_REG_EFLAGS);
}

unsigned long read_reg(int key, hashmap_t* hashmap) {
    if (is_8bits_right(key)) {
        return (*(hashmap->value[key]) & 0xff);
    } else if (is_8bits_left(key)) {
        return (*(hashmap->value[key]) & 0xff00);
    } else if (is_16bits(key)) {
        return (*(hashmap->value[key]) & 0xffff);
    } else if (is_32bits(key)) {
        return (*(hashmap->value[key]) & 0xffffffff);
    } else if (is_64bits(key)) {
        return (*(hashmap->value[key]) & 0xffffffffffffffff);
    }

    return -1;
}