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

#define ARCH_CET_STATUS 0x3001

_Bool must_change;

uint64_t hook_brk(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;
    uint64_t _brk_base = syscall(__NR_brk, 0x0);

    state->rax = syscall(__NR_brk, state->rdi);
    fprintf(s_binary->debug_stream, "[ . ] brk (%lx) = %lx\n", state->rdi, state->rax);

    if (PAGE_ALIGN(_brk_base) != PAGE_ALIGN(state->rax)) {
        if (-1 == list_add_map(s_binary, PROT_READ | PROT_WRITE, PAGE_ALIGN(_brk_base) + PAGE_SZ, PAGE_ROUND(((state->rax - _brk_base +1)))+1)) {
            fprintf(stderr, "> @hook_brk > @list_add_map: prot: %x, size: %lx, addr: %lx\n", PROT_READ | PROT_WRITE, PAGE_ALIGN(state->rax), PAGE_ROUND(((state->rax - _brk_base) + 1)));
            fatal_dump(s_binary);
        }
    }

    return 0;
}

uint64_t hook_arch_prctl(mdata_binary_t* s_binary) {
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
            fprintf(s_binary->debug_stream, "arch_prctl code [ %x ] unhandled\n", code);
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
    fprintf(s_binary->debug_stream, "[ . ] arch_prctl (%s, %lx) = %ld\n", code_debug, addr, try_ret); // I guess it works

    return 0;
}

uint64_t hook_access(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    const char* filename = (const char* )state->rdi;
    int mode = state->rsi;

    state->rax = syscall(__NR_access, filename, mode);
    fprintf(s_binary->debug_stream, "[ . ] access (\"%s\", %x) = %ld\n", filename, mode, state->rax);

    return 0;
}

uint64_t hook_mmap(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    uint64_t addr = state->rdi;
    size_t length = state->rsi;
    int prot = state->rdx;
    int flags = state->rcx;
    int fd = state->r8;
    int offt = state->r9;

    state->rax = syscall(__NR_mmap, addr, length, prot, flags, fd, offt);
    fprintf(s_binary->debug_stream, "[ . ] mmap (%lx, %lx, %x, %d, %x) = %lx\n", addr, length, prot, fd, offt, state->rax);

    if (-1 != state->rax && (!state->rdi || !is_mapped_range(s_binary, state->rdi, length))) {
        list_add_map(s_binary, prot, state->rax, PAGE_ROUND(length) + 1);
    } else if (-1 != state->rax && (state->rcx & MAP_FIXED)) {
        if (-1 == update_vprot(s_binary, addr, PAGE_ROUND(length)+1, prot)) {
            fprintf(stderr, "> @hook_munmap: update_vprot failed: address: %lx, size: %lx, prot: %x\n", addr, length, prot);
            fatal_dump(s_binary);
        }
    }

    return 0;
}

uint64_t hook_writev(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_writev, state->rdi, state->rsi, state->rdx);
    fprintf(s_binary->debug_stream, "[ . ] writev (%lx, %lx, %lx)\n", state->rdi, state->rsi, state->rdx);
    
    return 0;
}

uint64_t hook_exit(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;
    dbi_instr_t* dbi_handler = s_binary->dbi_handler;

    // state->rax = syscall(__NR_exit, state->rdi);
    fprintf(s_binary->debug_stream, "[ . ] exit (%lx)\n", state->rdi);
    dbi_handler->dtor();
    
    return 0;
}

uint64_t hook_exit_grp(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;
    dbi_instr_t* dbi_handler = s_binary->dbi_handler;

    fprintf(s_binary->debug_stream, "[ . ] exit_grp (%lx)\n", state->rdi);
    dbi_handler->dtor();

    return 0;
}

uint64_t hook_openat(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_openat, state->rdi, state->rsi, state->rdx, state->r10);
    fprintf(s_binary->debug_stream, "[ . ] openat (%lx, \"%s\", %lx, %lx) = %ld\n", (long)state->rdi, (const char* )state->rsi, state->rdx, state->r10, state->rax);

    return 0;
}

uint64_t hook_fstat(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_fstat, state->rdi, state->rsi);
    fprintf(s_binary->debug_stream, "[ . ] fstat (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_close(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_close, state->rdi);
    fprintf(s_binary->debug_stream, "[ . ] close (%lx) = %ld\n", state->rdi, state->rax);

    return 0;
}

uint64_t hook_read(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_read, state->rdi, state->rsi, state->rdx);
    fprintf(s_binary->debug_stream, "[ . ] read (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_mprotect(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_mprotect, state->rdi, state->rsi, state->rdx);
    fprintf(s_binary->debug_stream, "[ . ] mprotect (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    if (-1 == update_vprot(s_binary, state->rdi, state->rsi, state->rdx)) {
        fprintf(stderr, "> @hook_mprotect: failed to update_vprot\n");
        fatal_dump(s_binary);
    }

    return 0;
}

uint64_t hook_pread64(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_pread64, state->rdi, state->rsi, state->rdx, state->r10);
    fprintf(s_binary->debug_stream, "[ . ] pread64 (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_munmap(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_munmap, state->rdi, state->rsi);
    fprintf(s_binary->debug_stream, "[ . ] munmap (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    list_del_map(s_binary, PAGE_ALIGN(state->rdi), PAGE_ROUND(state->rsi) + 1);

    return 0;
}

uint64_t hook_set_tid_address(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_set_tid_address, state->rdi);
    fprintf(s_binary->debug_stream, "[ . ] set_tid_address (%lx) = %ld\n", state->rdi, state->rax);

    return 0;
}

uint64_t hook_set_robust_list(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_set_robust_list, state->rdi, state->rsi);
    fprintf(s_binary->debug_stream, "[ . ] set_robust_list (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_rt_sigaction(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_rt_sigaction, state->rdi, state->rsi, state->rdx, state->r10);
    fprintf(s_binary->debug_stream, "[ . ] set_rt_sigaction (%lx, %lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->r10, state->rax);

    return 0;
}

uint64_t hook_rt_sigprocmask(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_rt_sigprocmask, state->rdi, state->rsi, state->rdx, state->r10);
    fprintf(s_binary->debug_stream, "[ . ] set_rt_sigprocmask (%lx, %lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->r10, state->rax);

    return 0;
}

uint64_t hook_prlimit64(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_prlimit64, state->rdi, state->rsi, state->rdx, state->r10);
    fprintf(s_binary->debug_stream, "[ . ] prlimit64 (%lx, %lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->r10, state->rax);

    return 0;
}

uint64_t hook_statfs(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_statfs, state->rdi, state->rsi);
    fprintf(s_binary->debug_stream, "[ . ] statfs (\"%s\", %lx) = %ld\n", (const char* )state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_stat(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_stat, state->rdi, state->rsi);
    fprintf(s_binary->debug_stream, "[ . ] statfs (\"%s\", %lx) = %ld\n", (const char* )state->rdi, state->rsi, state->rax);

    return 0;
}

uint64_t hook_getuid(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_getuid, state->rdi);
    fprintf(s_binary->debug_stream, "[ . ] getuid () = %ld\n", state->rax);

    return 0;
}

uint64_t hook_geteuid(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_geteuid, state->rdi);
    fprintf(s_binary->debug_stream, "[ . ] geteuid () = %ld\n", state->rax);

    return 0;
}

uint64_t hook_getegid(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_getegid, state->rdi);
    fprintf(s_binary->debug_stream, "[ . ] getegid () = %ld\n", state->rax);

    return 0;
}

uint64_t hook_getgid(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_getgid, state->rdi);
    fprintf(s_binary->debug_stream, "[ . ] getgid () = %ld\n", state->rax);

    return 0;
}

uint64_t hook_futex(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_futex, state->rdi, state->rsi, state->rdx, state->r10, state->r8, state->r9);
    fprintf(s_binary->debug_stream, "[ . ] futex (%lx, %lx, %lx, %lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->r10, state->r8, state->r9, state->rax);

    return 0;
}

uint64_t hook_getpid(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_getpid, state->rdi);
    fprintf(s_binary->debug_stream, "[ . ] getpid () = %ld\n", state->rax);

    return 0;
}

uint64_t hook_gettid(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_gettid, state->rdi);
    fprintf(s_binary->debug_stream, "[ . ] gettid () = %ld\n", state->rax);

    return 0;
}

uint64_t hook_tgkill(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_tgkill, state->rdi, state->rsi, state->rdx);
    fprintf(s_binary->debug_stream, "[ . ] tgkill (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_socket(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_socket, state->rdi, state->rsi, state->rdx);
    fprintf(s_binary->debug_stream, "[ . ] socket (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_connect(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_connect, state->rdi, state->rsi, state->rdx);
    fprintf(s_binary->debug_stream, "[ . ] connect (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_write(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_write, state->rdi, state->rsi, state->rdx);
    fprintf(s_binary->debug_stream, "[ . ] write (%lx, %lx, %lx) = %ld\n", state->rdi, state->rsi, state->rdx, state->rax);

    return 0;
}

uint64_t hook_sigaltstack(mdata_binary_t* s_binary) {
    state_rtime_t* state = s_binary->dbi_handler->state;

    state->rax = syscall(__NR_sigaltstack, state->rdi, state->rsi);
    fprintf(s_binary->debug_stream, "[ . ] sigaltstack (%lx, %lx) = %ld\n", state->rdi, state->rsi, state->rax);

    return 0;
}

// ====

hook_syscall get_syscall_hook(int syscall_number, mdata_binary_t* s_binary) {
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

    default:
        fprintf(s_binary->debug_stream, "syscall [ %x ] isn't handled\n", syscall_number);
        return (hook_syscall )-1;
    }
}
