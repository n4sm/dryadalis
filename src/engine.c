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

// =-=-=-=-=--

int set_fs_gs(void* fs, void* gs) {
    return arch_prctl(ARCH_SET_FS, fs) || arch_prctl(ARCH_SET_GS, gs);
}

int save_fs_gs(uint64_t* fs, uint64_t* gs) {
    if (-1 == arch_prctl(ARCH_GET_FS, fs) || -1 == arch_prctl(ARCH_GET_GS, gs)) {
        return -1;
    }
    return 0;
}

int arch_prctl(int func, void *ptr) {
    return syscall(__NR_arch_prctl, func, ptr);
}

void default_dtor(void) {
    fprintf(stdout, "End of the program !\n");
    exit(0);
}

void fatal_dump(mdata_binary_t* s_binary) {
    log_regs(s_binary);
    log_map(s_binary->memory_map);

    fprintf(stderr, "[FATAL] exit(-1)\n");

    exit(-1); 
}

int make_readable(mdata_binary_t* s_binary, uint64_t address, ssize_t size) {
    int curr_prot = prot(address, s_binary);

    if (mprotect((void* )PAGE_ALIGN(address), size, PROT_READ | PROT_EXEC)) {
        return -1;
    }

    return curr_prot;
}

int restore_prot(mdata_binary_t* s_binary, uint64_t address, ssize_t size, int curr_prot) {
    if (mprotect((void* )PAGE_ALIGN(address), size, curr_prot | PROT_EXEC)) {
        return -1;
    }

    return 0;
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

_Bool is_endbr64(uint8_t* s) {
    return !memcmp(s, "\xf3\x0f\x1e\xfa", 4);
}

//==

uint64_t mxcsr;

void save_mxcsr() {
    mxcsr = _mm_getcsr();
}


void restore_mxcsr() {
    __builtin_ia32_ldmxcsr(mxcsr);
}

//==

// returns how much byte there is up to the first cflow instruction, returns -1 if it fails
int opcodes_cflow(uint64_t addr, mdata_binary_t* s_binary, _Bool beg, int opt) {
    csh handle;
    uint8_t insn_buffer[PAGE_SZ] = {0};
    uint64_t saved_addr = addr;
    uint8_t* insn_buf = insn_buffer;
    
    size_t size = PAGE_SZ;
    int n = 0;

    if (opt == OPCODES_CFLOW_FULL) {
        if (!is_mapped(addr + size -1, s_binary)) {
            fprintf(stderr, "FATAL addr + size (%lx + %lx) is not mapped\n", addr, size-1);
            return -1;
        }

        if (!is_mapped(addr, s_binary)) {
            fprintf(stderr, "0x%lx is not mapped\n", addr);
            return -1;
        }        
    }

    int curr_prot = make_readable(s_binary, addr, (PAGE_OFFT(addr) + size) > PAGE_SZ ? PAGE_SZ*2 : PAGE_SZ);

    memcpy(insn_buf, (uint8_t* )addr, size);

    if (-1 == restore_prot(s_binary, addr, (PAGE_OFFT(addr) + size) > PAGE_SZ ? PAGE_SZ*2 : PAGE_SZ, curr_prot)) {
        return -1;
    }

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "FATAL capstone\n");
        return -1;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn *insn = cs_malloc(handle);

    if (!insn) {
        fatal_dump(s_binary);
    }

    while(cs_disasm_iter(handle, (const uint8_t **)&insn_buf, &size, &addr, insn)) {
        // if (insn->id == X86_INS_XSAVEC) {
        //     int test = 0;
        // }

        if (DEBUG) {
            fprintf(stdout, "0x%lx\t%s %s\n", insn->address, insn->mnemonic, insn->op_str);
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
        return opcodes_cflow(addr, s_binary, false, opt);
    }

    cs_free(insn, 1);
    fprintf(stderr, "FATAL found nothing\n");
    return -1;
}

// =====

int map_page(uintptr_t addr, int _prot, mdata_binary_t* s_binary) {
    if (MAP_FAILED == mmap((void* )PAGE_ALIGN(addr), PAGE_SZ, _prot, MAP_ANON | MAP_FIXED | MAP_PRIVATE, -1, 0x0)) {
        return -1;
    }

    list_add_map(s_binary, _prot, PAGE_ALIGN(addr), PAGE_SZ);
    return 0;
}

int unmap(uintptr_t addr, size_t sz) {
    if (-1 == munmap((void* )addr, sz)) {
        return -1;
    }

    return 0;
}

// ====

// returns the length of the instruction for which target points to
off_t insn_len(uint64_t target, mdata_binary_t* s_binary) {
    csh handle;
	cs_insn *insn;
    ssize_t count;
    char buf_insn[16] = {0};

    if (!is_mapped(target, s_binary)) {
        return -1;
    }

    int curr_prot = make_readable(s_binary, target, (PAGE_OFFT(target) + 15) > PAGE_SZ ? PAGE_SZ*2 : PAGE_SZ);

    memcpy(buf_insn, (void* )target, ~(PAGE_OFFT(target)) > 15 ? 15 : ~(PAGE_OFFT(target)));

    if (-1 == restore_prot(s_binary, target, (PAGE_OFFT(target) + 15) > PAGE_SZ ? PAGE_SZ*2 : PAGE_SZ, curr_prot)) {
        return -1;
    }

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return -1;
    }

    count = cs_disasm(handle, (const uint8_t *)buf_insn, 15, 0, 0, &insn);

    off_t ret = insn[0].size;

    cs_free(insn, count);
    return ret;
}

// =-=-=-=-=--

int restore_hook(uint8_t* patch, mdata_binary_t* s_binary) {
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
int dump_hook(uint8_t* patch, mdata_binary_t* s_binary) {
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

// =-=-=-=-=--

// returns the newly mmapped shellcode that dumps the state of the guest into the state struct
uint64_t craft_hook(mdata_binary_t* s_binary) {
    ks_engine *ks;
    ks_err err;
    size_t count;
    uint8_t *encode = mmap((void* )STUB_ADDR_DUMP, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
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

uint64_t craft_restore_stub(mdata_binary_t* s_binary) {
    ks_engine *ks;
    ks_err err;
    size_t count;
    uint8_t *encode = mmap((void* )STUB_ADDR_RESTORE, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
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

int host_save_state(state_rtime_t* state) {
    __asm__ __volatile__ (
        "mov %%fs, %0\n"
        "mov %%cs, %1\n"
        "mov %%gs, %2\n"
        "mov %%ds, %3\n"
        "mov %%ss, %4\n"
        :"=m"(state->fs), "=m"(state->cs), "=m"(state->gs), "=m"(state->ds), "=m"(state->ss): :);

    return 0;
}

// =-=-=-=-=--

_Bool parse_request(mdata_binary_t* s_binary, request_t* request, uint64_t base_bbl) {
    switch (request->type) {
        case INSTRUMENT_ADDR:
            return ((request->address >= base_bbl) && (request->address <= s_binary->dbi_handler->dump->jmp)) ? true : false;

        case INSTRUMENT_BBL:
            return false;

        default:
            return false;
    }
}

int set_dump_hook(mdata_binary_t* s_binary) {
    s_binary->dbi_handler->dump->code = calloc(1, 256);
    ssize_t size_trampoline = (ssize_t)dump_hook(s_binary->dbi_handler->dump->code, s_binary);
    if (-1 == size_trampoline) {
        fprintf(stderr, "FATAL set_dump_hook\n");
        return -1;
    }
    if (!(s_binary->dbi_handler->dump->code = realloc(s_binary->dbi_handler->dump->code, size_trampoline+1))) {
        fprintf(stderr, "FATAL set_dump_hook\n");
        return -1;
    }
    s_binary->dbi_handler->dump->length = size_trampoline;
    s_binary->dbi_handler->dump->jmp = 0x0; // no hook for now

    return 0;
}

int set_restore_hook(mdata_binary_t* s_binary) {
    s_binary->dbi_handler->restore->code = calloc(1, 256);
    ssize_t size_trampoline_restore = restore_hook(s_binary->dbi_handler->restore->code, s_binary);
    if (-1 == size_trampoline_restore) {
        fprintf(stderr, "FATAL set_restore_hook\n");
        return -1;
    }
    if (!(s_binary->dbi_handler->restore->code = realloc(s_binary->dbi_handler->restore->code, size_trampoline_restore))) {
        fprintf(stderr, "FATAL set_restore_hook\n");
        return -1;
    }
    s_binary->dbi_handler->restore->length = size_trampoline_restore;

    return 0;
}

int log_persistent_hook(mdata_binary_t* s_binary, uint64_t address) {
    s_binary->dbi_handler->persistent_hook->state = PERSISTENT_FIND_SPACE;
    s_binary->dbi_handler->persistent_hook->address = address;

    return 0;
}

int instrument_persistent(mdata_binary_t* s_binary, persistent_t* persistent_hook) {
    off_t offt_cflow = opcodes_cflow(*s_binary->dbi_handler->curr_hook, s_binary, false, OPCODES_CFLOW_RAW);

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
int instrument_request(mdata_binary_t* s_binary, uint64_t base_bbl) {
    if (s_binary->dbi_handler->persistent_hook->state) {
        if (-1 == instrument_persistent(s_binary, s_binary->dbi_handler->persistent_hook)) {
            fprintf(stdout, "FATAL instrument_persistent\n");
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
            if (-1 == restore_bytes(s_binary->dbi_handler->dump, s_binary) || (s_binary->dbi_handler->dump->to_unmap && (-1 == unmap(s_binary->dbi_handler->dump->to_unmap, PAGE_SZ)))) {
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
int instrument(mdata_binary_t* s_binary) {
    s_binary->dbi_handler->curr_hook = calloc(1, sizeof(uint64_t));
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

    // rsp is already set in the mapper
    exec_binary(s_binary);
    // no return
    return 0;
}

// write hook->code to hook->jmp saving orginal bytes in hook->orig_bytes
int write_hook(mdata_binary_t* s_binary, hook_t* hook, int opt) {
    int prot_curr, prot_next = 0x0;
    size_t mprotect_size = (PAGE_OFFT(hook->jmp) + hook->length) > PAGE_SZ ? PAGE_SZ*2 : PAGE_SZ;

    // if (opt == WRITE_HOOK_FULL) {
    if (!is_mapped(hook->jmp, s_binary)) {
        fprintf(stderr, "%lx isn't mapped # write_hook\n", hook->jmp);
        
        if (-1 == map_page(hook->jmp, PROT_EXEC | PROT_READ, s_binary)) {
            fprintf(stderr, "map_page failed\n");
            fatal_dump(s_binary);
        }

        hook->to_unmap = PAGE_ALIGN(hook->jmp);
    } else if (!is_mapped(hook->jmp + hook->length, s_binary)) {
        fprintf(stderr, "%lx isn't mapped # write_hook\n", hook->jmp + hook->length);
        
        if (-1 == map_page(hook->jmp + hook->length, PROT_EXEC | PROT_READ, s_binary)) {
            fprintf(stderr, "map_page failed\n");
            fatal_dump(s_binary);
        }

        hook->to_unmap = PAGE_ALIGN(hook->jmp + hook->length);
    }
    
    prot_curr = prot(hook->jmp, s_binary);
    prot_next = prot(hook->jmp + PAGE_SZ, s_binary);

    if (-1 == prot_curr || -1 == prot_next) {
        fprintf(stderr, "write_hook # failed to get the protections corresponding to %lx\n", hook->jmp);
        fatal_dump(s_binary);
    }

    if (mprotect_size > PAGE_SZ && !is_mapped(hook->jmp + PAGE_SZ, s_binary)) {
        fprintf(stderr, "PAGE IS NOT MAPPED\n");
        return -1;
    }

    // } else if (opt == WRITE_HOOK_RAW) {
    //     prot_curr = PROT_READ | PROT_WRITE | PROT_EXEC;
    //     prot_next = PROT_READ | PROT_WRITE | PROT_EXEC;
    // }

    if (mprotect((void* )PAGE_ALIGN((hook->jmp)), mprotect_size, PROT_READ)) {
        return -1;
    }

    memcpy(hook->orig_bytes, (void* )(hook->jmp), hook->length);
    if (mprotect((void* )PAGE_ALIGN((hook->jmp)), mprotect_size, PROT_READ | PROT_WRITE)) {
        return -1;
    }

    memcpy((void* )(hook->jmp), hook->code, hook->length);

    if (mprotect((void* )PAGE_ALIGN((hook->jmp)), PAGE_SZ, prot_curr | PROT_EXEC)) {
        return -1;
    } else if (mprotect((void* )PAGE_ALIGN((hook->jmp+PAGE_SZ)), PAGE_SZ, prot_next))  {
        return -1;
    }

    return 0;
}

// internal part, returns the offset right after the cflow instruction, updates automatically hook->jmp
uint64_t _instrument_bbl(mdata_binary_t* s_binary, hook_t* hook, uint64_t base) {
    off_t off_cflow = opcodes_cflow(base, s_binary, true, OPCODES_CFLOW_FULL);

    if (-1 == off_cflow) {
        fprintf(stderr, "FATAL opcodes_cflow\n");
        return -1;
    }

    s_binary->dbi_handler->dump->jmp = base + off_cflow;
    s_binary->dbi_handler->length_cflow = insn_len(base + off_cflow, s_binary);
    if (write_hook(s_binary, hook, WRITE_HOOK_FULL)) {
        return -1;
    }

    return off_cflow;
}

// restore the hook->orig_bytes at hook->curr_hook
int restore_bytes(hook_t* hook, mdata_binary_t* s_binary) {
    size_t mprotect_size = (PAGE_OFFT(hook->jmp) + hook->length) > PAGE_SZ ? PAGE_SZ*2 : PAGE_SZ;
    int prot_curr = prot(hook->jmp, s_binary);
    int prot_next = prot(hook->jmp + PAGE_SZ, s_binary);

    if (!is_mapped(hook->jmp, s_binary)) {
        fprintf(stderr, "restore_bytes # %lx isn't mapped\n", hook->jmp);
        fatal_dump(s_binary);
    }

    if (-1 == prot_curr || -1 == prot_next) {
        fprintf(stderr, "restore_bytes # failed to get the protections corresponding to %lx\n", hook->jmp);

        fatal_dump(s_binary);
    }

    if (-1  == mprotect((void* )PAGE_ALIGN(hook->jmp), mprotect_size, PROT_WRITE | PROT_READ)) {
        return -1;
    }

    for (size_t i = 0; i < hook->length; i++) {
        ((uint8_t* )hook->jmp)[i] = hook->orig_bytes[i];
    }

    if (-1  == mprotect((void* )PAGE_ALIGN(hook->jmp), PAGE_SZ, prot_curr)) {
        return -1;
    }

    if (mprotect_size > PAGE_SZ && mprotect((void* )PAGE_ALIGN((hook->jmp + PAGE_SZ)), PAGE_SZ, prot_next)) {
        return -1;
    }

    return 0;
}

uint64_t br_emulation(mdata_binary_t* s_binary, uint64_t addr) {
    uint64_t target = eval_target((uint8_t* )addr, s_binary);
    if (-1 == target) {
        fprintf(stderr, "FATAL eval_target \n");
        fatal_dump(s_binary);
    }

    if (DEBUG) {
        fprintf(stdout, "cflow target: 0x%lx\n", target);
    }

    return target;
}

uint64_t _get_bbl_base(mdata_binary_t* s_binary) {
    switch (s_binary->dbi_handler->curr_instr_mode) {
        case INSTRUMENT_BBL:
            return br_emulation(s_binary, *s_binary->dbi_handler->curr_hook);

        case INSTRUMENT_ADDR:
            if (!opcodes_cflow(s_binary->dbi_handler->request->address, s_binary, false, OPCODES_CFLOW_RAW)) {
                // we check if that's the end of a basic block if so we emulate the br instruction
                return br_emulation(s_binary, *s_binary->dbi_handler->curr_hook);
            } else {
                // else we're in a basic block so the begin of the new bbl the right after the last executed instruction 
                return *s_binary->dbi_handler->curr_hook;
            }

        case INSTRUMENT_ADDR_ONLY:
            if (!opcodes_cflow(s_binary->dbi_handler->request->address, s_binary, false, OPCODES_CFLOW_RAW)) {
                // we check if that's the end of a basic block if so we emulate the br instruction
                return br_emulation(s_binary, *s_binary->dbi_handler->curr_hook);
            } else {
                // else we're in a basic block so the begin of the new bbl the right after the last executed instruction
                fprintf(stdout, "curr_hook: 0x%lx\n", *s_binary->dbi_handler->curr_hook);
                return *s_binary->dbi_handler->curr_hook;
            }            

        default:
            return -1;
    }
}

void _dispatcher(mdata_binary_t* s_binary) {
    if (-1 == save_fs_gs(&s_binary->dbi_handler->instrumented_fs, &s_binary->dbi_handler->instrumented_gs)) {
        fprintf(stderr, "FATAL arch_prctl\n");
        fatal_dump(s_binary);
    } else if (-1 == set_fs_gs((void* )s_binary->dbi_handler->host_state->fs, (void* )s_binary->dbi_handler->host_state->gs)) {
        fprintf(stderr, "FATAL arch_prctl\n");
        fatal_dump(s_binary);
    }

    if (s_binary->dbi_handler->take_callback) {
        s_binary->dbi_handler->u_handler(s_binary);
    }

    if (s_binary->dbi_handler->restore->jmp) {
        if (-1 == restore_bytes(s_binary->dbi_handler->restore, s_binary) || (s_binary->dbi_handler->restore->to_unmap && (-1 == unmap(s_binary->dbi_handler->restore->to_unmap, PAGE_SZ)))) {
            fprintf(stderr, "FATAL restore_bytes # restore\n");
            fatal_dump(s_binary);
        }
    }
    s_binary->dbi_handler->restore->to_unmap = 0x0;

    if (DEBUG) {
        fprintf(stdout, ".\n");
    }

    if (-1 == restore_bytes(s_binary->dbi_handler->dump, s_binary) || (s_binary->dbi_handler->dump->to_unmap && (-1 == unmap(s_binary->dbi_handler->dump->to_unmap, PAGE_SZ)))) {
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

    fflush(stdout);
    continue_exec(s_binary);
}
//== internal functions used by eval_target

// Does the instruction tests flags ?
_Bool is_test(uint64_t cs_eflags) {
    return (cs_eflags & (X86_EFLAGS_TEST_AF | X86_EFLAGS_TEST_CF | X86_EFLAGS_TEST_DF | X86_EFLAGS_TEST_IF | X86_EFLAGS_TEST_OF | X86_EFLAGS_TEST_SF | X86_EFLAGS_TEST_TF | X86_EFLAGS_TEST_ZF)) != 0;
}

// return true if the target flag is set in @eflags
_Bool is_set(mdata_binary_t* s_binary, int flag) {
    if (DEBUG) {
        fprintf(stdout, "eflags & flag: %lx & %x = %lx\n", read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap), flag, (read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap) & flag));
    }

    uint64_t eflags = read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap);
    
    if (-1 == eflags) {
        fprintf(stderr, "FATAL read eflags\n");
        fatal_dump(s_binary);
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
            return  ((!(read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap) & SF)) == (!(read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap) & OF)));

        case X86_INS_JL:
            return (!(read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap) & SF)) != (!(read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap) & OF));
        case X86_INS_JLE:
            return is_set(s_binary, ZF) || (!(read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap) & SF)) != (!(read_reg(X86_REG_EFLAGS, s_binary->dbi_handler->hashmap) & OF));

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
            fprintf(stderr, "not found cflow\n");
            fatal_dump(s_binary);
            // not reached
            return -1;
    }
}

long sign_extend(size_t size, uint64_t value) {
    return (((value & (1 << ((size*8) - 1))) << (63-(size-1))) | ((value & ~(0 << ((size*8)-1)))));
}

uint64_t __eval_target(cs_insn* insn, mdata_binary_t* s_binary, uint64_t instruction) {
    cs_detail* details = insn->detail;
    cs_x86* x86 = &(details->x86);
    _Bool achieve = false;

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

                    *(uint64_t* )s_binary->dbi_handler->state->rsp = s_binary->dbi_handler->state->rip + insn->size;
                    achieve = true;
                }

                switch (operand->type) {
                    uint64_t base, index;
                    case X86_OP_REG:
                        return read_reg(operand->reg, s_binary->dbi_handler->hashmap);
                    case X86_OP_IMM:
                        return (uint64_t)(sign_extend(operand->size, operand->imm) + s_binary->dbi_handler->state->rip);
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

                            return *((uint64_t* )(base + index * operand->mem.scale + operand->mem.disp));
                        }

                        fprintf(stderr, "failed to read registers, base [ %x ] => [ %lx ], index [ %x ] => [ %lx ]\n", operand->mem.base, base, operand->mem.index, index);
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

                return (uint64_t)(instruction + insn->size);
            }
        } else if (is_ret(details->groups[i])) {
            s_binary->dbi_handler->state->rsp += 8;
            return *((uint64_t* )(read_reg(X86_REG_RSP, s_binary->dbi_handler->hashmap)-8));
        } else if (is_interrupt(details->groups[i])) {
            hook_syscall sys_callback = NULL;
            uint64_t ret = 0x0;
            size_t sz = insn->size;

            if ((hook_syscall)-1 != (sys_callback = get_syscall_hook(s_binary->dbi_handler->state->rax, s_binary))) {

                if (set_fs_gs((void* )s_binary->dbi_handler->instrumented_fs, (void* )s_binary->dbi_handler->instrumented_gs)) {
                    fprintf(stderr, "FATAL arch_prctl\n");
                }
                
                ret = sys_callback(s_binary);

                if (set_fs_gs((void* )s_binary->dbi_handler->host_state->fs, (void* )s_binary->dbi_handler->host_state->gs)) {
                    fprintf(stderr, "FATAL arch_prctl\n");
                }

                if (ret) {
                    // if the control flow is broken we jump on a particular location returned by sys_callback when the return value is != 0
                    return ret;
                }

                return (uint64_t)(instruction + sz);
            }

            return (uint64_t)instruction;
        }
    }

    // if that's not a return, a call or a jmp it can be an interrupt and we handle that by a diffrent way so we ignore it for now
    return (uint64_t)(instruction);
}

uint64_t eval_target(uint8_t* instruction, mdata_binary_t* s_binary) {
    csh handle;
	cs_insn *insn;
    char buf_insn[16] = {0};
    uint64_t target = 0;

    if (!instruction || !is_mapped((uint64_t)instruction, s_binary) || !is_mapped((uint64_t)instruction+15, s_binary)) {
        return -1;
    }

    int curr_prot = make_readable(s_binary, (uint64_t)instruction, (PAGE_OFFT((uint64_t)instruction) + 15) > PAGE_SZ ? PAGE_SZ*2 : PAGE_SZ);

    memcpy(buf_insn, instruction, 15);
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "FATAL OPEN CAPSTONE\n");
        return -1;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_disasm(handle, (const uint8_t *)buf_insn, 16, 0, 1, &insn);

    target = __eval_target(insn, s_binary, (uint64_t)instruction);
    cs_free(insn, 1);  
    
    if (-1 == restore_prot(s_binary, (uint64_t)instruction, (PAGE_OFFT((uint64_t)instruction) + 15) > PAGE_SZ ? PAGE_SZ*2 : PAGE_SZ, curr_prot)) {
        return -1;
    }

    return target;
}

// =-=-=-=-

void continue_exec(mdata_binary_t* s_binary) {
    if (set_fs_gs((void* )s_binary->dbi_handler->instrumented_fs, (void* )s_binary->dbi_handler->instrumented_gs)) {
        fprintf(stderr, "FATAL arch_prctl\n");
    }

    // if (s_binary->dbi_handler->instrumented_fs) {
    //     int test = 0;
    // }

    __asm__ __volatile__ (
        "vzeroall\n"
        "mov %0, %%rax\n"
        "jmp *%%rax\n" // shitty at&t
        :: "r"(s_binary->dbi_handler->restore_stub):);
}