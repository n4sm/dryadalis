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
#include <inttypes.h>
#include <assert.h>

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <keystone/keystone.h>

#include "../include/dryadalis_x86.h"

/*  Dieu le Roy */

int set_fs_gs(void* fs, void* gs) 
{
    return arch_prctl(ARCH_SET_FS, fs) || arch_prctl(ARCH_SET_GS, gs);
}

int save_fs_gs(uint64_t* fs, uint64_t* gs) 
{
    if (-1 == arch_prctl(ARCH_GET_FS, fs) || -1 == arch_prctl(ARCH_GET_GS, gs)) {
        return -1;
    }
    return 0;
}

int arch_prctl(int func, void *ptr) 
{
    return syscall(__NR_arch_prctl, func, ptr);
}

void default_dtor(void) 
{
    fprintf(stdout, "End of the program ! bbl count: %x\n", insn_count);
    syscall(__NR_exit, 0);
}

void fatal_dump(mdata_binary_t* s_binary) 
{
    log_regs(s_binary, stderr);
    log_map(s_binary->memory_map, stderr);

    fprintf(stderr, "[FATAL] exit(-1)\n");

    s_binary->dbi_handler->dtor();
}

uint64_t mxcsr;

void save_mxcsr() 
{
    mxcsr = _mm_getcsr();
}


void restore_mxcsr() 
{
    __builtin_ia32_ldmxcsr(mxcsr);
}

// TODO: call list_del_map
int unmap(uintptr_t addr, size_t sz) 
{
    return munmap((void* )addr, sz);
}

int restore_hook(uint8_t* patch, mdata_binary_t* s_binary) 
{
    ks_engine *ks;
    ks_err err;
    size_t count;
    uint8_t *encode;
    size_t size;
    char insns[64] = {0};

    sprintf(insns, "movabs rax, [%p]", &(s_binary->dbi_handler->state->rax));
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
int dump_hook(uint8_t* patch, mdata_binary_t* s_binary) 
{
    ks_engine *ks;
    ks_err err;
    size_t count;
    uint8_t *encode;
    size_t size;
    char insns[64] = {0};

    sprintf(insns, "movabs [%p], rax; mov rax, %p; jmp rax", &(s_binary->dbi_handler->state->rax), s_binary->dbi_handler->dump_stub);
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

// returns the newly mmapped shellcode that dumps the state of the guest into the state struct
uint64_t craft_hook(mdata_binary_t* s_binary) 
{
    ks_engine *ks;
    ks_err err;
    size_t count;
    uint8_t *encode = (uint8_t* )mmap((void* )STUB_ADDR_DUMP, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    size_t size;
    char insns[10000] = {0};

    if (MAP_FAILED == encode) {
        return -1;
    }

    s_binary->dbi_handler->dump_stub = encode;

    sprintf(insns, "    mov rax, rsp;\
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
                                        movabs [%p], rax;",         &(s_binary->dbi_handler->state->rsp), (uint64_t)(s_binary->dbi_handler->host_rsp), &(s_binary->dbi_handler->state->rflags), &(s_binary->dbi_handler->state->rbx), &(s_binary->dbi_handler->state->rcx), \
                                                                    &(s_binary->dbi_handler->state->rdx), &(s_binary->dbi_handler->state->rsi), &(s_binary->dbi_handler->state->rdi), \
                                                                    &(s_binary->dbi_handler->state->rbp), \
                                                                    &(s_binary->dbi_handler->state->es), &(s_binary->dbi_handler->state->gs), \
                                                                    &(s_binary->dbi_handler->state->fs), &(s_binary->dbi_handler->state->cs), &(s_binary->dbi_handler->state->ss), \
                                                                    &(s_binary->dbi_handler->state->ds), &(s_binary->dbi_handler->state->r8), &(s_binary->dbi_handler->state->r9), \
                                                                    &(s_binary->dbi_handler->state->r10), &(s_binary->dbi_handler->state->r11), &(s_binary->dbi_handler->state->r12), \
                                                                    &(s_binary->dbi_handler->state->r13), &(s_binary->dbi_handler->state->r14), &(s_binary->dbi_handler->state->r15));


    if (s_binary->dbi_handler->state->sse) {
        sprintf(insns + strlen(insns), "    mov rax, %p;\
                                            movaps [rax], xmm0;\
                                            mov rax, %p;\
                                            movaps xmm0, xmm1;\
                                            movaps [rax], xmm0;\
                                            mov rax, %p;\
                                            movaps xmm0, xmm2;\
                                            movaps [rax], xmm0;\
                                            mov rax, %p;\
                                            movaps xmm0, xmm3;\
                                            movaps [rax], xmm0;\
                                            mov rax, %p;\
                                            movaps xmm0, xmm4;\
                                            movaps [rax], xmm0;\
                                            mov rax, %p;\
                                            movaps xmm0, xmm5;\
                                            movaps [rax], xmm0;\
                                            mov rax, %p;\
                                            movaps xmm0, xmm6;\
                                            movaps [rax], xmm0;\
                                            mov rax, %p;\
                                            movaps xmm0, xmm7;\
                                            movaps [rax], xmm0;\
                                            mov rax, %p;\
                                            movaps xmm0, xmm8;\
                                            movaps [rax], xmm0;\
                                            mov rax, %p;\
                                            movaps xmm0, xmm9;\
                                            movaps [rax], xmm0;\
                                            mov rax, %p;\
                                            movaps xmm0, xmm10;\
                                            movaps [rax], xmm0;\
                                            mov rax, %p;\
                                            movaps xmm0, xmm11;\
                                            movaps [rax], xmm0;\
                                            mov rax, %p;\
                                            movaps xmm0, xmm12;\
                                            movaps [rax], xmm0;\
                                            mov rax, %p;\
                                            movaps xmm0, xmm13;\
                                            movaps [rax], xmm0;\
                                            mov rax, %p;\
                                            movaps xmm0, xmm14;\
                                            movaps [rax], xmm0;\
                                            mov rax, %p;\
                                            movaps xmm0, xmm15;\
                                            movaps [rax], xmm0;",       &(s_binary->dbi_handler->state->sse->xmm0), &(s_binary->dbi_handler->state->sse->xmm1), &(s_binary->dbi_handler->state->sse->xmm2),\
                                                                        &(s_binary->dbi_handler->state->sse->xmm3), &(s_binary->dbi_handler->state->sse->xmm4), &(s_binary->dbi_handler->state->sse->xmm5), \
                                                                        &(s_binary->dbi_handler->state->sse->xmm6), &(s_binary->dbi_handler->state->sse->xmm7), &(s_binary->dbi_handler->state->sse->xmm8), \
                                                                        &(s_binary->dbi_handler->state->sse->xmm9), &(s_binary->dbi_handler->state->sse->xmm10), &(s_binary->dbi_handler->state->sse->xmm11), \
                                                                        &(s_binary->dbi_handler->state->sse->xmm12), &(s_binary->dbi_handler->state->sse->xmm13), &(s_binary->dbi_handler->state->sse->xmm14), &(s_binary->dbi_handler->state->sse->xmm15));
    } else if (s_binary->dbi_handler->state->avx2) {
        sprintf(insns + strlen(insns), "    mov rax, 0x%lx;\
                                            call rax;\
                                            mov rax, %p;\
                                            vmovups [rax], ymm0;\
                                            mov rax, %p;\
                                            vmovups [rax], ymm1;\
                                            mov rax, %p;\
                                            vmovups [rax], ymm2;\
                                            mov rax, %p;\
                                            vmovups [rax], ymm3;\
                                            mov rax, %p;\
                                            vmovups [rax], ymm4;\
                                            mov rax, %p;\
                                            vmovups [rax], ymm5;\
                                            mov rax, %p;\
                                            vmovups [rax], ymm6;\
                                            mov rax, %p;\
                                            vmovups [rax], ymm7;\
                                            mov rax, %p;\
                                            vmovups [rax], ymm8;\
                                            mov rax, %p;\
                                            vmovups [rax], ymm9;\
                                            mov rax, %p;\
                                            vmovups [rax], ymm10;\
                                            mov rax, %p;\
                                            vmovups [rax], ymm11;\
                                            mov rax, %p;\
                                            vmovups [rax], ymm12;\
                                            mov rax, %p;\
                                            vmovups [rax], ymm13;\
                                            mov rax, %p;\
                                            vmovups [rax], ymm14;\
                                            mov rax, %p;\
                                            vmovups [rax], ymm15;",     (uint64_t)save_mxcsr, 
                                                                        &(s_binary->dbi_handler->state->avx2->ymm0), &(s_binary->dbi_handler->state->avx2->ymm1), &(s_binary->dbi_handler->state->avx2->ymm2),\
                                                                        &(s_binary->dbi_handler->state->avx2->ymm3), &(s_binary->dbi_handler->state->avx2->ymm4), &(s_binary->dbi_handler->state->avx2->ymm5), \
                                                                        &(s_binary->dbi_handler->state->avx2->ymm6), &(s_binary->dbi_handler->state->avx2->ymm7), &(s_binary->dbi_handler->state->avx2->ymm8), \
                                                                        &(s_binary->dbi_handler->state->avx2->ymm9), &(s_binary->dbi_handler->state->avx2->ymm10), &(s_binary->dbi_handler->state->avx2->ymm11), \
                                                                        &(s_binary->dbi_handler->state->avx2->ymm12), &(s_binary->dbi_handler->state->avx2->ymm13), &(s_binary->dbi_handler->state->avx2->ymm14), &(s_binary->dbi_handler->state->avx2->ymm15));
    } else if (s_binary->dbi_handler->state->avx512) {
        fprintf(stderr, "FATAL avx512 isn't supported for now\n");
        return -1;
    }        

    sprintf(insns + strlen(insns), "mov rdi, 0x%lx; \
                                    mov rax, 0x%lx; \
                                    push 0x0;\
                                    push rax;\
                                    movabs rax, [%p];\
                                    movabs [%p], rax;\
                                    ret", (uint64_t)s_binary, (uint64_t)(s_binary->dispatcher), s_binary->dbi_handler->curr_hook, &(s_binary->dbi_handler->state->rip));

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

uint64_t craft_restore_stub(mdata_binary_t* s_binary) 
{
    ks_engine *ks;
    ks_err err;
    size_t count;
    uint8_t *encode = (uint8_t* )mmap((void* )STUB_ADDR_RESTORE, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    size_t size;
    char insns[10000] = {0};

    if (MAP_FAILED == encode) {
        return -1;
    }

    s_binary->dbi_handler->restore_stub = (uint8_t* )STUB_ADDR_RESTORE;

    if (s_binary->dbi_handler->state->sse) {
        sprintf(insns,                     "mov rax, %p;\
                                            movaps xmm0, [rax];\
                                            mov rax, %p;\
                                            movaps xmm1, [rax];\
                                            mov rax, %p;\
                                            movaps xmm2, [rax];\
                                            mov rax, %p;\
                                            movaps xmm3, [rax];\
                                            mov rax, %p;\
                                            movaps xmm4, [rax];\
                                            mov rax, %p;\
                                            movaps xmm5, [rax];\
                                            mov rax, %p;\
                                            movaps xmm6, [rax];\
                                            mov rax, %p;\
                                            movaps xmm7, [rax];\
                                            mov rax, %p;\
                                            movaps xmm8, [rax];\
                                            mov rax, %p;\
                                            movaps xmm9, [rax];\
                                            mov rax, %p;\
                                            movaps xmm10, [rax];\
                                            mov rax, %p;\
                                            movaps xmm11, [rax];\
                                            mov rax, %p;\
                                            movaps xmm12, [rax];\
                                            mov rax, %p;\
                                            movaps xmm13, [rax];\
                                            mov rax, %p;\
                                            movaps xmm14, [rax];\
                                            mov rax, %p;\
                                            movaps xmm15, [rax];",  &(s_binary->dbi_handler->state->sse->xmm0), &(s_binary->dbi_handler->state->sse->xmm1), &(s_binary->dbi_handler->state->sse->xmm2),\
                                                                    &(s_binary->dbi_handler->state->sse->xmm3), &(s_binary->dbi_handler->state->sse->xmm4), &(s_binary->dbi_handler->state->sse->xmm5), \
                                                                    &(s_binary->dbi_handler->state->sse->xmm6), &(s_binary->dbi_handler->state->sse->xmm7), &(s_binary->dbi_handler->state->sse->xmm8), \
                                                                    &(s_binary->dbi_handler->state->sse->xmm9), &(s_binary->dbi_handler->state->sse->xmm10), &(s_binary->dbi_handler->state->sse->xmm11), \
                                                                    &(s_binary->dbi_handler->state->sse->xmm12), &(s_binary->dbi_handler->state->sse->xmm13), &(s_binary->dbi_handler->state->sse->xmm14), &(s_binary->dbi_handler->state->sse->xmm15));
    } else if (s_binary->dbi_handler->state->avx2) {
        sprintf(insns,     "                mov rax, %p;\
                                            vmovups ymm0, [rax];\
                                            mov rax, %p;\
                                            vmovups ymm1, [rax];\
                                            mov rax, %p;\
                                            vmovups ymm2, [rax];\
                                            mov rax, %p;\
                                            vmovups ymm3, [rax];\
                                            mov rax, %p;\
                                            vmovups ymm4, [rax];\
                                            mov rax, %p;\
                                            vmovups ymm5, [rax];\
                                            mov rax, %p;\
                                            vmovups ymm6, [rax];\
                                            mov rax, %p;\
                                            vmovups ymm7, [rax];\
                                            mov rax, %p;\
                                            vmovups ymm8, [rax];\
                                            mov rax, %p;\
                                            vmovups ymm9, [rax];\
                                            mov rax, %p;\
                                            vmovups ymm10, [rax];\
                                            mov rax, %p;\
                                            vmovups ymm11, [rax];\
                                            mov rax, %p;\
                                            vmovups ymm12, [rax];\
                                            mov rax, %p;\
                                            vmovups ymm13, [rax];\
                                            mov rax, %p;\
                                            vmovups ymm14, [rax];\
                                            mov rax, %p;\
                                            vmovups ymm15, [rax];\
                                            mov rax, 0x%lx;\
                                            call rax;",  &(s_binary->dbi_handler->state->avx2->ymm0), &(s_binary->dbi_handler->state->avx2->ymm1), &(s_binary->dbi_handler->state->avx2->ymm2),\
                                                                     &(s_binary->dbi_handler->state->avx2->ymm3), &(s_binary->dbi_handler->state->avx2->ymm4), &(s_binary->dbi_handler->state->avx2->ymm5), \
                                                                     &(s_binary->dbi_handler->state->avx2->ymm6), &(s_binary->dbi_handler->state->avx2->ymm7), &(s_binary->dbi_handler->state->avx2->ymm8), \
                                                                     &(s_binary->dbi_handler->state->avx2->ymm9), &(s_binary->dbi_handler->state->avx2->ymm10), &(s_binary->dbi_handler->state->avx2->ymm11), \
                                                                     &(s_binary->dbi_handler->state->avx2->ymm12), &(s_binary->dbi_handler->state->avx2->ymm13), &(s_binary->dbi_handler->state->avx2->ymm14), &(s_binary->dbi_handler->state->avx2->ymm15), (uint64_t)restore_mxcsr);
    } else if (s_binary->dbi_handler->state->avx512) {
        fprintf(stderr, "FATAL avx512 isn't supported for now\n");
        return -1;
    }

    sprintf(insns + strlen(insns), "    movabs rax, [%p]; \
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
                                        mov r15, rax;", &(s_binary->dbi_handler->state->rbx), &(s_binary->dbi_handler->state->rcx), &(s_binary->dbi_handler->state->rdx), \
                                                                    &(s_binary->dbi_handler->state->rdi), &(s_binary->dbi_handler->state->rsi), &(s_binary->dbi_handler->state->rbp), \
                                                                    &(s_binary->dbi_handler->state->es), \
                                                                    &(s_binary->dbi_handler->state->ss), &(s_binary->dbi_handler->state->ds), \
                                                                    &(s_binary->dbi_handler->state->r8), &(s_binary->dbi_handler->state->r9), &(s_binary->dbi_handler->state->r10), \
                                                                    &(s_binary->dbi_handler->state->r11), &(s_binary->dbi_handler->state->r12), &(s_binary->dbi_handler->state->r13), \
                                                                    &(s_binary->dbi_handler->state->r14), &(s_binary->dbi_handler->state->r15));

    sprintf(insns + strlen(insns), "movabs rax, [%p]; push rax; \
                                    movabs rax, [%p]; push rax; \
                                                popfq; \
                                                pop rsp; \
                                                movabs rax, [%p]; \
                                                jmp rax;",  &(s_binary->dbi_handler->state->rsp), &(s_binary->dbi_handler->state->rflags), \
                                                        &(s_binary->dbi_handler->state->rip));

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
    return (uint64_t)STUB_ADDR_RESTORE;
}

int host_save_state(state_rtime_t* state) 
{
    __asm__ __volatile__ (
        "mov %%fs, %0\n"
        "mov %%cs, %1\n"
        "mov %%gs, %2\n"
        "mov %%ds, %3\n"
        "mov %%ss, %4\n"
        :"=m"(state->fs), "=m"(state->cs), "=m"(state->gs), "=m"(state->ds), "=m"(state->ss): :);

    return 0;
}

_Bool parse_request(mdata_binary_t* s_binary, request_t* request, uint64_t base_bbl) 
{
    switch (request->type) {
        case INSTRUMENT_ADDR:
            return ((request->address >= base_bbl) && (request->address <= s_binary->dbi_handler->dump->jmp)) ? true : false;

        case INSTRUMENT_BBL:
            return false;

        default:
            return false;
    }
}

int set_dump_hook(mdata_binary_t* s_binary) 
{
    s_binary->dbi_handler->dump->code = (uint8_t* )calloc(1, 256);
    ssize_t size_trampoline = (ssize_t)dump_hook(s_binary->dbi_handler->dump->code, s_binary);
    if (-1 == size_trampoline) {
        fprintf(stderr, "FATAL set_dump_hook\n");
        return -1;
    }
    if (!(s_binary->dbi_handler->dump->code = (uint8_t* )realloc(s_binary->dbi_handler->dump->code, size_trampoline+1))) {
        fprintf(stderr, "FATAL set_dump_hook\n");
        return -1;
    }
    s_binary->dbi_handler->dump->length = size_trampoline;
    s_binary->dbi_handler->dump->jmp = 0x0; // no hook for now

    return 0;
}

int set_restore_hook(mdata_binary_t* s_binary) 
{
    s_binary->dbi_handler->restore->code = (uint8_t* )calloc(1, 256);
    ssize_t size_trampoline_restore = restore_hook(s_binary->dbi_handler->restore->code, s_binary);
    if (-1 == size_trampoline_restore) {
        fprintf(stderr, "FATAL set_restore_hook\n");
        return -1;
    }
    if (!(s_binary->dbi_handler->restore->code = (uint8_t* )realloc(s_binary->dbi_handler->restore->code, size_trampoline_restore))) {
        fprintf(stderr, "FATAL set_restore_hook\n");
        return -1;
    }
    s_binary->dbi_handler->restore->length = size_trampoline_restore;

    return 0;
}

int log_persistent_hook(mdata_binary_t* s_binary, uint64_t address) 
{
    s_binary->dbi_handler->persistent_hook->state = PERSISTENT_FIND_SPACE;
    s_binary->dbi_handler->persistent_hook->address = address;

    return 0;
}

int instrument_persistent(mdata_binary_t* s_binary, persistent_t* persistent_hook) 
{
    off_t offt_cflow = opcodes_cflow(*s_binary->dbi_handler->curr_hook, s_binary, true);
    s_binary->dbi_handler->take_callback = false;

    if (s_binary->dbi_handler->persistent_hook->state == PERSISTENT_FIND_SPACE) {
        // we're looking for space to write the hook which will hijack cflow to finally write the final hook on the requested address
        if (offt_cflow > s_binary->dbi_handler->dump->length) {
            // either the target br instruction if far enough
            s_binary->dbi_handler->persistent_hook->state = PERSISTENT_SET_ORIG_HOOK;
        } else {
            // there is not enough space between rip and the next br instruction so we write the hook @ the target basic block for the next time we back in the callback
            s_binary->dbi_handler->persistent_hook->state = PERSISTENT_SET_BR_HOOK;
        }

        // in all the cases we write the hook at the br instruction
        s_binary->dbi_handler->dump->jmp = *s_binary->dbi_handler->curr_hook + offt_cflow;
        if (-1 == write_hook(s_binary, s_binary->dbi_handler->dump, WRITE_HOOK_RAW)) {
            fprintf(stderr, "FATAL instrument_request\n");
            return -1;
        }
    } else if (s_binary->dbi_handler->persistent_hook->state == PERSISTENT_SET_BR_HOOK) {
        // we check if the current hook is actually on a br instruction
        assert(!offt_cflow);

        uint64_t br_target = br_emulation(s_binary, *s_binary->dbi_handler->curr_hook);

        s_binary->dbi_handler->dump->jmp = br_target;
        if (-1 == write_hook(s_binary, s_binary->dbi_handler->dump, WRITE_HOOK_RAW)) {
            fprintf(stderr, "FATAL instrument_request\n");
            return -1;
        }

        s_binary->dbi_handler->persistent_hook->state = PERSISTENT_SET_ORIG_HOOK;
    } else if (s_binary->dbi_handler->persistent_hook->state == PERSISTENT_SET_ORIG_HOOK) {
        s_binary->dbi_handler->take_callback = true;
        s_binary->dbi_handler->dump->jmp = s_binary->dbi_handler->persistent_hook->address;
        if (-1 == write_hook(s_binary, s_binary->dbi_handler->dump, WRITE_HOOK_RAW)) {
            fprintf(stderr, "FATAL instrument_request\n");
            return -1;
        }
    }

    return 0;
}

// it writes the dump hook and sets the right mode (INSTRUMENT_ADDR / INSTRUMENT_BBL)
int instrument_request(mdata_binary_t* s_binary, uint64_t base_bbl) 
{
    if (s_binary->dbi_handler->persistent_hook->state) {
        if (-1 == instrument_persistent(s_binary, s_binary->dbi_handler->persistent_hook)) {
            fprintf(s_binary->debug_stream, "FATAL instrument_persistent\n");
            fatal_dump(s_binary);
        }
    } else if (s_binary->dbi_handler->request->type == INSTRUMENT_ADDR_ONLY) {
        if (is_mapped(s_binary->dbi_handler->request->address, s_binary)) {
            s_binary->dbi_handler->dump->jmp = s_binary->dbi_handler->request->address;
            if (-1 == write_hook(s_binary, s_binary->dbi_handler->dump, WRITE_HOOK_RAW)) {
                fprintf(stderr, "FATAL instrument_request\n");
                return -1;
            }

            log_persistent_hook(s_binary, s_binary->dbi_handler->request->address);
            s_binary->dbi_handler->take_callback = true;
        } else {
            fatal_dump(s_binary);
        }
    } else {
        *(s_binary->dbi_handler->curr_hook) = base_bbl + _instrument_bbl(s_binary, s_binary->dbi_handler->dump, base_bbl);

        if ((s_binary->dbi_handler->take_callback = parse_request(s_binary, s_binary->dbi_handler->request, base_bbl))) {
            if (-1 == restore_bytes(s_binary->dbi_handler->dump, s_binary) 
                || (s_binary->dbi_handler->dump->to_unmap && (-1 == unmap(s_binary->dbi_handler->dump->to_unmap, PAGE_SZ)))) {
                fprintf(stderr, "FATAL restore_bytes # dump\n");
                fatal_dump(s_binary);
            }
            s_binary->dbi_handler->dump->to_unmap = 0x0;

            s_binary->dbi_handler->dump->jmp = s_binary->dbi_handler->request->address;
            if (-1 == write_hook(s_binary, s_binary->dbi_handler->dump, WRITE_HOOK_FULL)) {
                fprintf(stderr, "FATAL instrument_request\n");
                return -1;
            }

            s_binary->dbi_handler->curr_instr_mode = INSTRUMENT_ADDR;
        } else {
            s_binary->dbi_handler->curr_instr_mode = INSTRUMENT_BBL;
        }
    }

    s_binary->dbi_handler->restore->jmp = base_bbl - s_binary->dbi_handler->restore->length;
    *(s_binary->dbi_handler->curr_hook) = s_binary->dbi_handler->dump->jmp;
    if (-1 == write_hook(s_binary, s_binary->dbi_handler->restore, WRITE_HOOK_RAW)) {
        fprintf(stderr, "FATAL write_hook # restore\n");
        fatal_dump(s_binary);
    }

    return 0;
}

// main instrumentation abstraction
int instrument(mdata_binary_t* s_binary) 
{
    s_binary->dbi_handler->curr_hook = (uint64_t* )calloc(1, sizeof(uint64_t));
    s_binary->dbi_handler->host_rsp = (uint64_t* )((map_stack()));
    s_binary->dispatcher = (uint64_t)_dispatcher;
    s_binary->dbi_handler->u_handler = s_binary->dbi_handler->request->callback;

    if (-1 == craft_hook(s_binary) || -1 == craft_restore_stub(s_binary)) {
        fatal_dump(s_binary);
    } else if (-1 == set_dump_hook(s_binary)) {
        fatal_dump(s_binary);
    } else if (-1 == set_restore_hook(s_binary)) {
        fatal_dump(s_binary);
    }

    if (-1 == instrument_request(s_binary, s_binary->exec_entry)) {
        fatal_dump(s_binary);
    }

    s_binary->dbi_handler->state->rip = s_binary->exec_entry;

    if (-1 == save_fs_gs(&s_binary->dbi_handler->host_state->fs, &s_binary->dbi_handler->host_state->gs)) {
        fatal_dump(s_binary);
    } else if (s_binary->dbi_handler->instrumented_fs && (-1 == set_fs_gs((void* )s_binary->dbi_handler->instrumented_fs, (void* )s_binary->dbi_handler->instrumented_gs))) {
        fatal_dump(s_binary);
    }

    // rsp is already set in the mapper engine
    exec_binary(s_binary);
    // no return
    return 0;
}

/*
    write_hook - write @hook according to @opt
    @s_binary: object descriptor
    @hook: hook descriptor
    @opt: unused for now
*/
int write_hook(mdata_binary_t* s_binary, hook_t* hook, int opt)
{
    if (!is_mapped(PAGE_ALIGN(hook->jmp), s_binary)) {
        fprintf(stderr, "> @write_hook: %lx isn't mapped\n", hook->jmp);
 
        if (-1 == map_page(PAGE_ALIGN(hook->jmp), PROT_EXEC | PROT_READ, s_binary)) {
            fprintf(stderr, "map_page failed\n");
            fatal_dump(s_binary);
        }

        hook->to_unmap = PAGE_ALIGN(hook->jmp);
    } else if (!is_mapped(hook->jmp + hook->length, s_binary)) {
        fprintf(stderr, "> @write_hook: %lx isn't mapped\n", hook->jmp + hook->length);
        
        if (-1 == map_page(hook->jmp + hook->length, PROT_EXEC | PROT_READ, s_binary)) {
            fprintf(stderr, "map_page failed\n");
            fatal_dump(s_binary);
        }

        hook->to_unmap = PAGE_ALIGN((hook->jmp + hook->length));
    }

    // if (!is_mapped(hook->jmp + PAGE_SZ, s_binary)) {
    //     fprintf(stderr, "> @write_hook > is_mapped, hook->jmp: %lx,\n");
    //     return -1;
    // } else 
    if (-1 == mem_read(s_binary, hook->orig_bytes, hook->jmp, hook->length)) {
        fprintf(stderr, "> @write_hook failed to read the bytes @ %lx\n", hook->jmp);
        fatal_dump(s_binary);
        return -1;
    } else if (-1 == mem_write(s_binary, hook->jmp, hook->code, hook->length)) {
        fprintf(stderr, "> @write_hook failed to write the hook @ %lx\n", hook->jmp);
        fatal_dump(s_binary);
        return -1;
    }

    if (!(prot(s_binary, hook->jmp) & PROT_EXEC)) {
        if (-1 == (long)make_executable(s_binary, hook->jmp, PAGE_OFFT((PAGE_SZ - hook->jmp)))) {
            fprintf(stderr, "> @write_hook > @make_executable, hook->jmp: %lx, offt: %lx\n", hook->jmp, PAGE_OFFT((PAGE_SZ - hook->jmp)));
            fatal_dump(s_binary);
        }
    }

    return 0;
}

/* _instrument_bbl - internal part, returns the offset right after the cflow instruction, updates automatically hook->jmp

    @s_binary: object descriptor
    @hook: hook descriptor
    @base: base address of the basic block we hate to analyse 
*/
uint64_t _instrument_bbl(mdata_binary_t* s_binary, hook_t* hook, uint64_t base) 
{
    off_t off_cflow = opcodes_cflow(base, s_binary, true);

    if (-1 == off_cflow) {
        fprintf(stderr, "> @_instrument_bbl > @opcodes_cflow: failed to get offt_cflow\n");
        fatal_dump(s_binary);
    }

    s_binary->dbi_handler->dump->jmp = base + off_cflow;
    s_binary->dbi_handler->length_cflow = insn_len(base + off_cflow, s_binary);
    if (write_hook(s_binary, hook, WRITE_HOOK_FULL)) {
        fprintf(stderr, "> @_instrument_bbl > @write_hook: hook->jmp: %lx\n", hook->jmp);
        fatal_dump(s_binary);
    }

    return off_cflow;
}

// restore the hook->orig_bytes at hook->curr_hook
int restore_bytes(hook_t* hook, mdata_binary_t* s_binary) 
{
    if (!is_mapped(hook->jmp, s_binary)) {
        fprintf(stderr, "> @restore_bytes, %lx isn't mapped\n", hook->jmp);
        fatal_dump(s_binary);
    } else if (-1 == mem_write(s_binary, hook->jmp, hook->orig_bytes, hook->length)) {
        fprintf(stderr, "> @restore_bytes, failed to write @ %lx\n", hook->jmp);
        fatal_dump(s_binary);
    }

    if (hook->prot_restore) {
        mem_map_t* _mem_desc = NULL;
        if (-1 == (long)(_mem_desc = get_mem_desc(s_binary, hook->jmp))
            || -1 == restore_vprot(s_binary, hook->length, _mem_desc, PAGE_OFFT(hook->jmp))) {
            fatal_dump(s_binary);
        }
    }

    return 0;
}

uint64_t br_emulation(mdata_binary_t* s_binary, uint64_t addr) 
{
    uint64_t target = eval_target((uint8_t* )addr, s_binary);
    if (-1 == target) {
        fprintf(stderr, "FATAL eval_target \n");
        fatal_dump(s_binary);
    }

    if (DEBUG) {
        fprintf(s_binary->debug_stream, "cflow target: 0x%lx\n", target);
    }

    return target;
}

uint64_t _get_bbl_base(mdata_binary_t* s_binary) 
{
    switch (s_binary->dbi_handler->curr_instr_mode) {
        case INSTRUMENT_BBL:
            return br_emulation(s_binary, *s_binary->dbi_handler->curr_hook);

        case INSTRUMENT_ADDR:
            if (!opcodes_cflow(s_binary->dbi_handler->request->address, s_binary, true)) {
                // we check if that's the end of a basic block if so we emulate the br instruction
                return br_emulation(s_binary, *s_binary->dbi_handler->curr_hook);
            } else {
                // else we're in a basic block so the begin of the new bbl the right after the last executed instruction 
                return *s_binary->dbi_handler->curr_hook;
            }

        case INSTRUMENT_ADDR_ONLY:
            if (!opcodes_cflow(s_binary->dbi_handler->request->address, s_binary, true)) {
                // we check if that's the end of a basic block if so we emulate the br instruction
                return br_emulation(s_binary, *s_binary->dbi_handler->curr_hook);
            } else {
                // else we're in a basic block so the begin of the new bbl the right after the last executed instruction
                fprintf(s_binary->debug_stream, "curr_hook: 0x%lx\n", *s_binary->dbi_handler->curr_hook);
                return *s_binary->dbi_handler->curr_hook;
            }            

        default:
            return -1;
    }
}

void _dispatcher(mdata_binary_t* s_binary) 
{
    if (-1 == save_fs_gs(&s_binary->dbi_handler->instrumented_fs, &s_binary->dbi_handler->instrumented_gs)) {
        fprintf(stderr, "FATAL arch_prctl\n");
        fatal_dump(s_binary);
    } else if (-1 == set_fs_gs((void* )s_binary->dbi_handler->host_state->fs, (void* )s_binary->dbi_handler->host_state->gs)) {
        fprintf(stderr, "FATAL arch_prctl\n");
        fatal_dump(s_binary);
    }
    
    s_binary->dbi_handler->u_handler(s_binary);

    if (s_binary->dbi_handler->restore->jmp) {
        if (-1 == restore_bytes(s_binary->dbi_handler->restore, s_binary) \
            || (s_binary->dbi_handler->restore->to_unmap && (-1 == unmap(s_binary->dbi_handler->restore->to_unmap, PAGE_SZ)))) {
            fprintf(stderr, "FATAL restore_bytes # restore\n");
            fatal_dump(s_binary);
        }
    }
    s_binary->dbi_handler->restore->to_unmap = 0x0;

    if (DEBUG) {
        fprintf(s_binary->debug_stream, ".\n");
    }

    if (-1 == restore_bytes(s_binary->dbi_handler->dump, s_binary) \
        || (s_binary->dbi_handler->dump->to_unmap && (-1 == unmap(s_binary->dbi_handler->dump->to_unmap, PAGE_SZ)))) {
        fprintf(stderr, "FATAL restore_bytes # dump\n");
        fatal_dump(s_binary);
    }
    s_binary->dbi_handler->dump->to_unmap = 0x0;

    uint64_t base_bbl = _get_bbl_base(s_binary);
    if (-1 == base_bbl) {
        fprintf(stderr, "FATAL _get_bbl_base\n");
        fatal_dump(s_binary);
    }

    if (-1 == instrument_request(s_binary, base_bbl)) {
        fprintf(stderr, "FATAL _instrument_bbl # dump hook\n");
        fatal_dump(s_binary);
    }

    s_binary->dbi_handler->state->rip = base_bbl - s_binary->dbi_handler->restore->length;

    fflush(s_binary->debug_stream);
    continue_exec(s_binary);
}

void continue_exec(mdata_binary_t* s_binary) 
{
    if (set_fs_gs((void* )s_binary->dbi_handler->instrumented_fs, (void* )s_binary->dbi_handler->instrumented_gs)) {
        fprintf(stderr, "FATAL arch_prctl\n");
    }

    __asm__ __volatile__ (
        "vzeroall\n"
        "mov %0, %%rax\n"
        "jmp *%%rax\n" // shitty at&t
        :: "r"(s_binary->dbi_handler->restore_stub):);
}
