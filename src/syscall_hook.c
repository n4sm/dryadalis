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
#include <assert.h>

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <keystone/keystone.h>

#include "../include/dryadalis_x86.h"

// ==

#define ARCH_CET_STATUS 0x3001

_Bool must_change;

// :)
/*
    do_syscall macro - executes a syscall according to the given arguments, updates state->rax with the syscall's return value
    @__VA_ARGS__: syscall arguments
*/
#define do_syscall(...) \
    if (-1 == set_fs_gs((void* )s_binary->dbi_handler->instrumented_fs, (void* )s_binary->dbi_handler->instrumented_gs)) { \
        fprintf(stderr, "FATAL arch_prctl\n"); \
        fatal_dump(s_binary); \
    } \
    \
    state->rax = syscall(__VA_ARGS__); \
    \
    if (-1 == set_fs_gs((void* )s_binary->dbi_handler->host_state->fs, (void* )s_binary->dbi_handler->host_state->gs)) { \
        fprintf(stderr, "FATAL arch_prctl\n"); \
        fatal_dump(s_binary); \
    } \

extern int errno;

/* 
    hook_brk - nothing to do except if it allocates a page, if this is the case we allocate one more page in the virtual memory map
*/
uint64_t hook_brk(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;
    uint64_t _brk_base = (uint64_t)s_binary->dbi_handler->vbrk;
    // printf("base: %lx\n", (uint64_t)s_binary->dbi_handler->vbrk);

    if (!state->rdi) {
        state->rax = _brk_base;
    } else {
        assert(state->rdi > _brk_base);
        uint32_t _brk_size = state->rdi - _brk_base;

        if (_brk_size + PAGE_OFFT(_brk_base) > PAGE_SZ) {
            if (MAP_FAILED == mmap((void* )PAGE_ALIGN(_brk_base), PAGE_ROUND(_brk_size) + 1, PROT_READ | PROT_WRITE, MAP_FIXED | MAP_PRIVATE | MAP_ANON, -1, 0)) {
                fprintf(stderr, "> @hook_brk > @mmap(%lx, %x)\n", _brk_base, PAGE_ROUND(_brk_size) + 1);

                fprintf(stderr, "Error mmap: %s\n", strerror( errno ));
                fatal_dump(s_binary);
            } else {
                _brk_base = state->rdi;
            }
        }

        state->rax = _brk_base;
        s_binary->dbi_handler->vbrk = (uint8_t* )_brk_base;
    }

    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] brk (%lx) = %lx\n", state->rdi, state->rax);

    return 0;
}

uint64_t hook_arch_prctl(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;
    dbi_instr_t* dbi_handler = s_binary->dbi_handler;

    int code = (int)state->rdi;
    uint64_t addr = state->rsi;

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
            dbi_handler->instrumented_fs = addr;
            must_change = true;
            break;
    
        case ARCH_SET_GS:
            memcpy(code_debug, "ARCH_SET_GS", strlen("ARCH_SET_GS\0"));
            dbi_handler->instrumented_gs = addr;
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

        case ARCH_CET_STATUS:
            memcpy(code_debug, "ARCH_CET_STATUS", strlen("ARCH_MAP_VDSO_X32\0"));
            break;

        default:
            memcpy(code_debug, "ARCH_???", strlen("ARCH_???\0"));
            if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "arch_prctl code [ %x ] unhandled\n", code);
            break;
    }

    uint64_t try_ret = syscall(__NR_arch_prctl, code, addr);

    if (code == ARCH_SET_FS) {
        if (-1 == set_fs_gs((void* )dbi_handler->host_state->fs, (void* )dbi_handler->host_state->gs)) {
            fprintf(stderr, "FATAL set_fs_gs\n");
            exit(-1);
        }
    }

    state->rax = try_ret;
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] arch_prctl (%s, %lx) = %ld\n", code_debug, addr, try_ret); // I guess it works

    return 0;
}

uint64_t hook_access(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    const char* filename = (const char* )state->rdi;
    int mode = state->rsi;

    do_syscall(__NR_access, filename, mode);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] access (\"%s\", %x) = %ld\n", filename, mode, state->rax);

    return 0;
}

uint64_t hook_mmap(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    uint64_t addr = state->rdi;
    size_t length = state->rsi;
    int prot = state->rdx;
    int flags = state->rcx;
    int fd = state->r8;
    int offt = state->r9;

    do_syscall(__NR_mmap, addr, length, prot, flags, fd, offt);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] mmap (%lx, %lx, %x, %d, %x) = %lx\n", addr, length, prot, fd, offt, state->rax);

    // if (-1 != state->rax && (!state->rdi || !is_mapped_range(s_binary, state->rdi, length))) {
    //     list_add_map(s_binary, prot, state->rax, PAGE_ROUND(length) + 1);
    // } else if (-1 != state->rax && (state->rcx & MAP_FIXED)) {
    //     if (-1 == update_vprot(s_binary, addr, PAGE_ROUND(length)+1, prot)) {
    //         fprintf(stderr, "> @hook_munmap: update_vprot failed: address: %lx, size: %lx, prot: %x\n", addr, length, prot);
    //         fatal_dump(s_binary);
    //     }
    // }

    // parse_maps(s_binary);

    return 0;
}

uint64_t hook_writev(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_writev, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] writev (%lx, %lx, %lx)\n", state->rdi, state->rsi, state->rdx);
    
    return 0;
}

uint64_t hook_exit(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;
    dbi_instr_t* dbi_handler = s_binary->dbi_handler;

    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] exit (%lx)\n", state->rdi);
    dbi_handler->dtor();
    
    return 0;
}

uint64_t hook_exit_grp(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;
    dbi_instr_t* dbi_handler = s_binary->dbi_handler;

    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] exit_grp (%lx)\n", state->rdi);
    dbi_handler->dtor();

    return 0;
}

uint64_t hook_openat(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_openat, state->rdi, state->rsi, state->rdx, state->r10);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] openat (%lx, \"%s\", %lx, %lx) = %ld\n", (long)state->rdi, (const char* )state->rsi, state->rdx, state->r10, state->rax);

    return 0;
}

uint64_t hook_fstat(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_fstat, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] fstat (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_close(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    // if it attempts to close stdout, we do not close it
    if (state->rdi == STDOUT_FILENO) {
        if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "> The guest attempts to close stdout, state->rax = 0\n");

        state->rax = 0;
    } else {
        do_syscall(__NR_close, state->rdi);
    }

    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] close (%lx) = %ld\n", state->rdi, state->rax);

    return 0;
}

uint64_t hook_read(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_read, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] read (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_mprotect(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_mprotect, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] mprotect (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_pread64(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_pread64, state->rdi, state->rsi, state->rdx, state->r10);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] pread64 (%lx, %lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->r10, state->rax);

    return 0;
}

uint64_t hook_munmap(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_munmap, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] munmap (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_set_tid_address(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_set_tid_address, state->rdi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] set_tid_address (%lx) = %ld\n", state->rdi, state->rax);

    return 0;
}

uint64_t hook_set_robust_list(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_set_robust_list, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] set_robust_list (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_rt_sigaction(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_rt_sigaction, state->rdi, state->rsi, state->rdx, state->r10);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] set_rt_sigaction (%lx, %lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->r10, state->rax);

    return 0;
}

uint64_t hook_rt_sigprocmask(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_rt_sigprocmask, state->rdi, state->rsi, state->rdx, state->r10);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] set_rt_sigprocmask (%lx, %lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->r10, state->rax);

    return 0;
}

uint64_t hook_prlimit64(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_prlimit64, state->rdi, state->rsi, state->rdx, state->r10);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] prlimit64 (%lx, %lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->r10, state->rax);

    return 0;
}

uint64_t hook_statfs(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_statfs, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] statfs (\"%s\", %lx) = %ld\n", (const char* )state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_stat(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_stat, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] statfs (\"%s\", %lx) = %ld\n", (const char* )state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_getuid(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_getuid, state->rdi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] getuid () = %ld\n", state->rax);

    return 0;
}

uint64_t hook_geteuid(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_geteuid, state->rdi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] geteuid () = %ld\n", state->rax);

    return 0;
}

uint64_t hook_getegid(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_getegid, state->rdi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] getegid () = %ld\n", state->rax);

    return 0;
}

uint64_t hook_getgid(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_getgid, state->rdi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] getgid () = %ld\n", state->rax);

    return 0;
}

uint64_t hook_futex(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_futex, state->rdi, state->rsi, state->rdx, state->r10, state->r8, state->r9);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] futex (%lx, %lx, %lx, %lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->r10, state->r8, state->r9, state->rax);

    return 0;
}

uint64_t hook_getpid(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_getpid);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] getpid () = %ld\n", state->rax);

    return 0;
}

uint64_t hook_gettid(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_gettid);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] gettid () = %ld\n", state->rax);

    return 0;
}

uint64_t hook_tgkill(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_tgkill, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] tgkill (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_socket(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_socket, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] socket (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_connect(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_connect, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] connect (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_write(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_write, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] write (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_sigaltstack(mdata_binary_t* s_binary) 
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_sigaltstack, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] sigaltstack (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_newfstatat(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_newfstatat, state->rdi, state->rsi, state->rdx, state->r10, state->r8);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] newfstatat (%lx, %s, %lx, %lx, %lx) = %ld\n", state->rdi, (const char* )state->rsi, state->rdx, state->r10, state->r8, state->rax);

    return 0;
}

uint64_t hook_getppid(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_getppid);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] getppid () = %ld\n", state->rax);

    return 0;
}

uint64_t hook_ioctl(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_ioctl, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] ioctl (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_execve(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_execve, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] execve (%s, %lx, %lx) = %ld\n", (const char* )state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_vfork(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_vfork);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] vfork () = %ld\n", state->rax);

    return 0;
}

uint64_t hook_uname(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_uname, state->rdi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] uname (%lx) = %ld\n", state->rdi, state->rax);

    return 0;
}

uint64_t hook_fcntl(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_fcntl, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] fnctl (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_getpgrp(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_getpgrp);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] getpgrp () = %ld\n", state->rax);

    return 0;
}

uint64_t hook_setpgid(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_setpgid, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] setpgid (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_getdents64(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_getdents64, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] getdents64 (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_statx(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_statx, state->rdi, state->rsi, state->rdx, state->r10, state->r8);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] statx (%lx, %lx, %lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->r10, state->r8, state->rax);

    return 0;
}

uint64_t hook_lgetxattr(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_lgetxattr, state->rdi, state->rsi, state->rdx, state->r10);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] lgetxattr (%lx, %lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->r10, state->rax);

    return 0;
}

uint64_t hook_fadvise64(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_fadvise64, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] fadvise64 (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_readlink(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_readlink, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] readlink (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_setitimer(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_setitimer, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] setitimer (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_readv(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_readv, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] readv (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_lseek(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_lseek, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] lseek (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_gettimeofday(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_gettimeofday, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] gettimeofday (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_clone(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_clone, state->rdi, state->rsi, state->rdx, state->r10);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] clone (%lx, %lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->r10, state->rax);

    return 0;
}

uint64_t hook_wait4(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_wait4, state->rdi, state->rsi, state->rdx, state->r10);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] clone (%lx, %lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->r10, state->rax);

    return 0;
}

uint64_t hook_lstat(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_lstat, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] lstat (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_fanotify_mark(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_fanotify_mark, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] fanotify_mark (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_msgsnd(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_msgsnd, state->rdi, state->rsi, state->rdx, state->r10);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] msgsnd (%lx, %lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->r10, state->rax);

    return 0;
}

uint64_t hook_seccomp(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_seccomp, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] seccomp (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_io_submit(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_io_submit, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] io_submit (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_time(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_time, state->rdi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] time (%lx) = %ld\n", state->rdi, state->rax);

    return 0;
}

uint64_t hook_clock_getres(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_clock_getres, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] clock_getres (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_clock_gettime(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_clock_gettime, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] clock_gettime (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_epoll_create1(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_epoll_create1, state->rdi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] epoll_create1 (%lx) = %ld\n", state->rdi, state->rax);

    return 0;
}

uint64_t hook_eventfd2(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_eventfd2, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] eventfd2 (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_pipe2(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_pipe2, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] pipe2 (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_getcwd(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_getcwd, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] getcwd (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_chdir(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_chdir, state->rdi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] chdir (%lx) = %ld\n", state->rdi, state->rax);

    return 0;
}

uint64_t hook_umask(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_umask, state->rdi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] umask (%lx) = %ld\n", state->rdi, state->rax);

    return 0;
}

uint64_t hook_mkdir(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_mkdir, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] mkdir (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_bind(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_bind, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] bind (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_listen(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_listen, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] listen (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_setsockopt(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_setsockopt, state->rdi, state->rsi, state->rdx, state->r10, state->r8);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] setsockopt (%lx, %lx, %lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->r10, state->r8, state->rax);

    return 0;
}

uint64_t hook_accept4(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_accept4, state->rdi, state->rsi, state->rdx, state->r10);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] accept4 (%lx, %lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->r10, state->rax);

    return 0;
}

uint64_t hook_poll(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_poll, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] poll (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_shmat(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_shmat, state->rdi, state->rsi, state->rdx);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] shmat (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_shutdown(mdata_binary_t* s_binary)
{
    state_rtime_t* state = s_binary->dbi_handler->state;

    do_syscall(__NR_shutdown, state->rdi, state->rsi);
    if (DEBUG & LOG_SYSCALL) fprintf(s_binary->debug_stream, "[ . ] shutdown (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

// ====

hook_syscall get_syscall_hook(int syscall_number, mdata_binary_t* s_binary) 
{
    switch (syscall_number) {
        case __NR_brk:
            return hook_brk;
        
        case __NR_arch_prctl:
            return hook_arch_prctl;
        
        case __NR_access:
            return hook_access;

        case __NR_mmap:
            return hook_mmap;

        case __NR_writev:
            return hook_writev;

        case __NR_exit:
            return hook_exit;

        case __NR_exit_group:
            return hook_exit_grp;

        case __NR_openat:
            return hook_openat;

        case __NR_fstat:
            return hook_fstat;

        case __NR_close:
            return hook_close;

        case __NR_read:
            return hook_read;

        case __NR_mprotect:
            return hook_mprotect;

        case __NR_pread64:
            return hook_pread64;

        case __NR_munmap:
            return hook_munmap;

        case __NR_set_tid_address:
            return hook_set_tid_address;
        
        case __NR_set_robust_list:
            return hook_set_robust_list;

        case __NR_rt_sigaction:
            return hook_rt_sigaction;

        case __NR_rt_sigprocmask:
            return hook_rt_sigprocmask;

        case __NR_prlimit64:
            return hook_prlimit64;

        case __NR_statfs:
            return hook_statfs;

        case __NR_stat:
            return hook_stat;

        case __NR_getuid:
            return hook_getuid;

        case __NR_geteuid:
            return hook_geteuid;

        case __NR_getegid:
            return hook_getegid;

        case __NR_getgid:
            return hook_getgid;

        case __NR_futex:
            return hook_futex;

        case __NR_getpid:
            return hook_getpid;

        case __NR_gettid:
            return hook_gettid;

        case __NR_tgkill:
            return hook_tgkill;

        case __NR_socket:
            return hook_socket;
        
        case __NR_connect:
            return hook_connect;

        case __NR_write:
            return hook_write;

        case __NR_sigaltstack:
            return hook_sigaltstack;

        case __NR_newfstatat:
            return hook_newfstatat;

        case __NR_getppid:
            return hook_getpid;

        case __NR_ioctl:
            return hook_ioctl;

        case __NR_execve:
            return hook_execve;

        case __NR_vfork:
            return hook_vfork;

        case __NR_uname:
            return hook_uname;

        case __NR_fcntl:
            return hook_fcntl;

        case __NR_getpgrp:
            return hook_getpgrp;

        case __NR_setpgid:
            return hook_setpgid;

        case __NR_getdents64:
            return hook_getdents64;

        case __NR_statx:
            return hook_statx;

        case __NR_lgetxattr:
            return hook_lgetxattr;

        case __NR_fadvise64:
            return hook_fadvise64;

        case __NR_readlink:
            return hook_readlink;

        case __NR_setitimer:
            return hook_setitimer;

        case __NR_readv:
            return hook_readv;

        case __NR_lseek:
            return hook_lseek;

        case __NR_gettimeofday:
            return hook_gettimeofday;

        case __NR_clone:
            return hook_clone;

        case __NR_wait4:
            return hook_wait4;

        case __NR_lstat:
            return hook_lstat;

        case __NR_fanotify_mark:
            return hook_fanotify_mark;

        case __NR_msgsnd:
            return hook_msgsnd;

        case __NR_seccomp:
            return hook_seccomp;

        case __NR_io_submit:
            return hook_io_submit;

        case __NR_time:
            return hook_time;

        case __NR_clock_getres:
            return hook_clock_getres;

        case __NR_clock_gettime:
            return hook_clock_gettime;

        case __NR_epoll_create1:
            return hook_epoll_create1;

        case __NR_eventfd2:
            return hook_eventfd2;

        case __NR_pipe2:
            return hook_pipe2;

        case __NR_getcwd:
            return hook_getcwd;

        case __NR_chdir:
            return hook_chdir;

        case __NR_umask:
            return hook_umask;

        case __NR_mkdir:
            return hook_mkdir;

        case __NR_bind:
            return hook_bind;

        case __NR_listen:
            return hook_listen;

        case __NR_setsockopt:
            return hook_setsockopt;

        case __NR_accept4:
            return hook_accept4;

        case __NR_poll:
            return hook_poll;

        case __NR_shmat:
            return hook_shmat;

        case __NR_shutdown:
            return hook_shutdown;

    default:
        fflush(stderr);
        fprintf(stderr, "syscall [ %x ] isn't handled\n", syscall_number);
        return (hook_syscall )-1;
    }
}
