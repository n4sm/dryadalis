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


// ==

unsigned long hook_brk(state_rtime_t* state) {
    state->rax = syscall(__NR_brk, state->rdi);

    // if (DEBUG) {
    fprintf(stdout, "[ * ] brk(%lx) = %lx\n", state->rdi, state->rax);
    // }

    return 0;
}

unsigned long hook_arch_prctl(state_rtime_t* state) {
    int code = (int)state->rdi;
    unsigned long addr = state->rsi;

    char code_debug[64] = {0};

    switch (code) {
        case ARCH_GET_CPUID:
            memcpy(code_debug, "ARCH_GET_CPUID", strlen("ARCH_GET_CPUID\0"));
            break;
        
        case ARCH_GET_FS:
            memcpy(code_debug, "ARCH_GET_FS", strlen("ARCH_GET_FS\0"));
            break;
        
        case ARCH_GET_GS:
            memcpy(code_debug, "ARCH_GET_GS", strlen("ARCH_GET_GS\0"));
            break;
        
        case ARCH_SET_CPUID:
            memcpy(code_debug, "ARCH_SET_CPUID", strlen("ARCH_SET_CPUID\0"));
            break;
        
        case ARCH_SET_FS:
            memcpy(code_debug, "ARCH_SET_FS", strlen("ARCH_SET_FS\0"));
            code = INSTRUMENTED_FS;
            break;
        
        case ARCH_SET_GS:
            memcpy(code_debug, "ARCH_SET_GS", strlen("ARCH_SET_GS\0"));
            code = INSTRUMENTED_GS;
            break;

        case ARCH_MAP_VDSO_32:
            memcpy(code_debug, "ARCH_MAP_VDSO_32", strlen("ARCH_MAP_VDSO_32\0"));
            break;

        case ARCH_MAP_VDSO_64:
            memcpy(code_debug, "ARCH_MAP_VDSO_64", strlen("ARCH_MAP_VDSO_64\0"));
            break;

        case ARCH_MAP_VDSO_X32:
            memcpy(code_debug, "ARCH_MAP_VDSO_X32", strlen("ARCH_MAP_VDSO_X32\0"));
            break;

        default:
            memcpy(code_debug, "ARCH_???", strlen("ARCH_???\0"));
            // fprintf(stderr, "arch_prctl code [ %x ] unhandled\n", code);
            break;
    }

    state->rax = syscall(__NR_arch_prctl, code, addr);

    fprintf(stdout, "[ * ] arch_prctl(%s, %lx) = %lx\n", code_debug, addr, state->rax);

    return 0;
}

unsigned long hook_access(state_rtime_t* state) {
    const char* filename = (const char* )state->rdi;
    int mode = state->rsi;

    state->rax = syscall(__NR_access, filename, mode);
    fprintf(stdout, "[ * ] access(\"%s\", %x) = %lx\n", filename, mode, state->rax);

    return 0;
}

unsigned long hook_mmap(state_rtime_t* state) {
    unsigned long addr = state->rdi;
    size_t length = state->rsi;
    int prot = state->rdx;
    int flags = state->rcx;
    int fd = state->r8;
    int offt = state->r9;

    state->rax = syscall(__NR_mmap, addr, length, prot, flags, fd, offt);
    fprintf(stdout, "[ * ] mmap(%lx, %lx, %x, %x, %x)\n", addr, length, prot, fd, offt);
    
    return 0;
}

// ====

hook_syscall get_syscall_hook(int syscall_number, mdata_binary_t* s_binary) {
    switch (syscall_number)
    {
    case __NR_brk:
        return hook_brk;
    
    case __NR_arch_prctl:
        return hook_arch_prctl;
    
    case __NR_access:
        return hook_access;

    case __NR_mmap:
        return hook_mmap;

    default:
        fprintf(stderr, "syscall [ %x ] isn't handled\n", syscall_number);
        return (hook_syscall )-1;
    }
}