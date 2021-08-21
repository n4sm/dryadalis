#ifndef DRYADALIS_H_
#define DRYADALIS_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libelf.h>
#include <elf.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <sys/syscall.h>
#include <asm/ldt.h>   
#include <asm/prctl.h>
#include <sys/prctl.h>
#include <immintrin.h>

#include "kernel_list.h"

// define

#define OPT_BBL 0x0
#define OPT_SINGLE_STEP 0x1
#define OPT_CFLOW 0x2

#define LENGTH_STUB 0x1000
#define PAGE_SZ 0x1000
#define ELF_MIN_ALIGN PAGE_SZ

#define STUB_ADDR_DUMP 0xff1d000
#define STUB_ADDR_RESTORE 0xdf1d000

#define INSTRUMENTED_FS 0x14f0000
#define INSTRUMENTED_GS 0x15f000

#define STACK_SZ 0x50000
#define DEBUG true 

// eflags

#define CF (1 << 0)
#define PF (1 << 2)
#define AF (1 << 4)
#define ZF (1 << 6)
#define SF (1 << 7)
#define TF (1 << 8)
#define IF (1 << 9)
#define DF (1 << 10)
#define OF (1 << 11)
#define NT (1 << 14)
#define RF (1 << 16)
#define AC (1 << 18)

// structures

typedef struct args_syscall_s {
    unsigned long rdi;
    unsigned long rsi;
    unsigned long rdx;
    unsigned long rcx;
    unsigned long r8;
    unsigned long r9;
} args_syscall_t;

typedef int (*u_callback_t) (void* s_binary);
typedef void (*destructor_t) (void);

typedef struct hashmap_s {
    unsigned long** value;
} hashmap_t;

_Bool must_change;

/* Registers on entry:
 * rax  system call number
 * rcx  return address
 * r11  saved rflags (note: r11 is callee-clobbered register in C ABI)
 * rdi  arg0
 * rsi  arg1
 * rdx  arg2
 * r10  arg3 (needs to be moved to rcx to conform to C ABI)
 * r8   arg4
 * r9   arg5
 * (note: r12-r15, rbp, rbx are callee-preserved in C ABI)
 *
 * Only called from user space.
*/

typedef struct sse_s {
    __m128i xmm0 __attribute__((packed, aligned(16)));
    __m128i xmm1 __attribute__((packed, aligned(16)));
    __m128i xmm2 __attribute__((packed, aligned(16)));
    __m128i xmm3 __attribute__((packed, aligned(16)));
    __m128i xmm4 __attribute__((packed, aligned(16)));
    __m128i xmm5 __attribute__((packed, aligned(16)));
    __m128i xmm6 __attribute__((packed, aligned(16)));
    __m128i xmm7 __attribute__((packed, aligned(16)));
    __m128i xmm8 __attribute__((packed, aligned(16)));
    __m128i xmm9 __attribute__((packed, aligned(16)));
    __m128i xmm10 __attribute__((packed, aligned(16)));
    __m128i xmm11 __attribute__((packed, aligned(16)));
    __m128i xmm12 __attribute__((packed, aligned(16)));
    __m128i xmm13 __attribute__((packed, aligned(16)));
    __m128i xmm14 __attribute__((packed, aligned(16)));
    __m128i xmm15 __attribute__((packed, aligned(16)));
} __attribute__((packed, aligned(16))) sse_t;

typedef struct avx2_s {
    __m256i ymm0 __attribute__((aligned(32)));
    __m256i ymm1 __attribute__((aligned(32)));
    __m256i ymm2 __attribute__((aligned(32)));
    __m256i ymm3 __attribute__((aligned(32)));
    __m256i ymm4 __attribute__((aligned(32)));
    __m256i ymm5 __attribute__((aligned(32)));
    __m256i ymm6 __attribute__((aligned(32)));
    __m256i ymm7 __attribute__((aligned(32)));
    __m256i ymm8 __attribute__((aligned(32)));
    __m256i ymm9 __attribute__((aligned(32)));
    __m256i ymm10 __attribute__((aligned(32)));
    __m256i ymm11 __attribute__((aligned(32)));
    __m256i ymm12 __attribute__((aligned(32)));
    __m256i ymm13 __attribute__((aligned(32)));
    __m256i ymm14 __attribute__((aligned(32)));
    __m256i ymm15 __attribute__((aligned(32)));
} __attribute__((aligned(32))) avx2_t;

typedef struct avx512_s {
    __m512i zmm0;
    __m512i zmm2;
    __m512i zmm3;
    __m512i zmm4;
    __m512i zmm5;
    __m512i zmm6;
    __m512i zmm7;
    __m512i zmm8;
    __m512i zmm9;
    __m512i zmm10;
    __m512i zmm11;
    __m512i zmm12;
    __m512i zmm13;
    __m512i zmm14;
    __m512i zmm15;
    __m512i zmm16;
    __m512i zmm17;
    __m512i zmm18;
    __m512i zmm19;
    __m512i zmm20;
    __m512i zmm21;
    __m512i zmm22;
    __m512i zmm23;
    __m512i zmm24;
    __m512i zmm25;
    __m512i zmm26;
    __m512i zmm27;
    __m512i zmm28;
    __m512i zmm29;
    __m512i zmm30;
    __m512i zmm31;
} avx512_t;

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

    sse_t* sse;
    avx2_t* avx2;
    avx512_t* avx512;

    unsigned long null_entry;
} state_rtime_t;

typedef struct arg_s {
    int argc;
    char** argv;
} arg_t;

typedef struct hook_s {
    unsigned char* code;
    unsigned char* orig_bytes;
    ssize_t length;
    unsigned long jmp;
    uintptr_t to_unmap;
} hook_t;

typedef struct dbi_instr_s {
    _Bool take_callback;
    state_rtime_t* state;
    state_rtime_t* host_state;
    u_callback_t u_handler;
    hook_t* dump;
    hook_t* restore;
    destructor_t dtor;
    unsigned char* dump_stub;
    unsigned char* restore_stub;
    unsigned long* curr_hook;
    unsigned long *host_rsp;
    hashmap_t* hashmap;
    unsigned long instrumented_fs;
    unsigned long instrumented_gs;
    int64_t length_cflow;
} dbi_instr_t;

typedef struct mem_map_s {
    struct list_head list;
    unsigned long addr;
    ssize_t size;
    int prot;
} mem_map_t;

typedef struct mdata_binary_s {
    unsigned char *fbinary; // malloc pointer to the binary
    unsigned long len_file;
    const char *filename;
    int fd; // fd of the binary
    Elf64_Phdr** s_ph; // list of pointer to the program header
    Elf64_Ehdr* eh;
    _Bool pie; // is pie ?
    struct mdata_binary_s *interp; // pointer to the real interp mapped
    unsigned char *base; // real base address of the manual mapped binary
    mem_map_t* memory_map;
    unsigned long dispatcher;
    dbi_instr_t* dbi_handler;
} mdata_binary_t;

typedef unsigned long (*hook_syscall) (mdata_binary_t* s_binary);

// macro

#define IS_INTERP(x) x->p_type == PT_INTERP
#define IS_LOAD(x) x->p_type == PT_LOAD
#define IS_DYNAMIC(x) x->p_type == PT_DYNAMIC

#define PAGE_ALIGN(x) (x & ~0xfff)
#define PAGE_ROUND(x) (PAGE_ALIGN(x)) + 0xfff
#define PAGE_OFFT(x) (x & 0xfff)
#define ELF_PAGEALIGN(_v) (((_v) + ELF_MIN_ALIGN - 1) & ~(ELF_MIN_ALIGN - 1)) - 1
// https://elixir.bootlin.com/linux/v4.8/source/fs/binfmt_elf.c#L82

#define _PROT_WRITE(x) (x & PF_W ? PROT_WRITE : false)
#define _PROT_EXEC(x) (x & PF_X ? PROT_EXEC : false)

#define group_make_link(hashmap, group_reg, reg) \
            for (int i = 0; i < (sizeof(group_reg) / sizeof(group_reg[0])); i++) { \
                make_link(hashmap, group_reg[i], reg);\
            }

#define make_link(hashmap, code_reg, reg) \
            hashmap->value[code_reg] = &(reg)

// elf parsing

_Bool is_elf(unsigned char *eh_ptr);
uint64_t search_base_addr(Elf64_Phdr *buffer_mdata_phdr[], Elf64_Ehdr *eh_ptr);
Elf64_Phdr *search_pt_dyn(Elf64_Phdr **buffer_mdata_ph, Elf64_Ehdr *eh_ptr);
int parse_phdr(Elf64_Ehdr *ptr, Elf64_Phdr *buffer_mdata_ph[]);
int parse_shdr(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[]);
char **parse_sh_name(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[], char **sh_name_buffer);
int init_struct(Elf64_Shdr *buffer_mdata_sh[], Elf64_Phdr *buffer_mdata_ph[], char **sh_name, Elf64_Ehdr *ptr);
mdata_binary_t *init_analysis(const char *s);
int end_analysis(mdata_binary_t *s_binary);
mdata_binary_t* alloc_binary();
int free_binary(mdata_binary_t *bi);
int add_auxvt(unsigned long id, unsigned long* origin, unsigned long *base_auxvt, unsigned long val);

// core_mapper

mdata_binary_t* map_binary(const char *filename, arg_t* arguments);
mdata_binary_t* load_interp(Elf64_Phdr* s_ph, mdata_binary_t* s_binary);
int map_load(Elf64_Phdr* s_ph, mdata_binary_t* s_binary);
unsigned long* setup_stack(char **argv, mdata_binary_t* s_binary, int argc);
void exec_binary(mdata_binary_t* s_binary);
int list_add_map(mdata_binary_t* s_binary, int prot, unsigned long addr, ssize_t size);
int free_memory_map(mem_map_t* memory_map);
int log_map(mem_map_t* memory_map);
mem_map_t* merge_address_space(mdata_binary_t* s_binary);
mem_map_t* mem_desc(unsigned long addr, mdata_binary_t* s_binary);
_Bool is_mapped(unsigned long addr, mdata_binary_t* s_binary);
_Bool is_rx(unsigned long addr, mdata_binary_t* s_binary);
_Bool is_ro(unsigned long addr, mdata_binary_t* s_binary);
_Bool is_rw(unsigned long addr, mdata_binary_t* s_binary);
_Bool is_rwx(unsigned long addr, mdata_binary_t* s_binary);

// returns the prot according to the address
int prot(unsigned long addr, mdata_binary_t* s_binary);
unsigned long* map_stack();
int merge_pages(mdata_binary_t* s_binary, int prot, unsigned long addr, ssize_t size);

// engine

// returns how many byte there is up to the first cflow instruction
int opcodes_cflow(unsigned long addr, mdata_binary_t* s_binary, _Bool beg);
// encodes the patch used as a trampoline in @patch to @target, returns -1 if it fails and else the length of the patch 
int dump_hook(unsigned char* patch, mdata_binary_t* s_binary);
// returns the newly mmapped shellcode that dumps the state of the guest into the state struct
unsigned long craft_hook(mdata_binary_t* s_binary);
int restore_hook(unsigned char* patch, mdata_binary_t* s_binary);

int instrument(mdata_binary_t* s_binary, u_callback_t callback);
unsigned long _instrument(mdata_binary_t* s_binary, hook_t* hook);

unsigned long eval_target(unsigned char* instruction, mdata_binary_t* s_binary);
void _dispatcher(mdata_binary_t* s_binary);

void alloc_state(mdata_binary_t* s_binary);
void continue_exec(mdata_binary_t* s_binary);
int restore_bytes(hook_t* hook, mdata_binary_t* s_binary);
int write_hook(mdata_binary_t* s_binary, hook_t* hook);
int host_save_state(state_rtime_t* state);

int arch_prctl(int func, void *ptr);
int set_fs_gs(void* fs, void* gs);
_Bool is_set(mdata_binary_t* s_binary, int flag);
_Bool is_jmp_taken(int id, mdata_binary_t* s_binary);

void default_dtor(void);
int set_fs_gs(void* fs, void* gs);

// state_runt

hashmap_t* init_hashmap(hashmap_t* hashmap, mdata_binary_t* s_binary);
int free_hashmap(hashmap_t* hashmap);
void update_reg(int key, hashmap_t* hashmap, unsigned long value);

_Bool is_8bits_right(int reg);
_Bool is_8bits_left(int reg);
_Bool is_16bits(int reg);
_Bool is_32bits(int reg);
_Bool is_64bits(int reg);
unsigned long read_reg(int key, hashmap_t* hashmap);

void log_regs(mdata_binary_t* s_binary);
void log_general(state_rtime_t* state);
void log_avx2(state_rtime_t* state);
void log_sse(state_rtime_t* state);

_Bool is_cf(unsigned long eflags);
_Bool is_pf(unsigned long eflags);
_Bool is_af(unsigned long eflags);
_Bool is_zf(unsigned long eflags);
_Bool is_sf(unsigned long eflags);
_Bool is_tf(unsigned long eflags);
_Bool is_if(unsigned long eflags);
_Bool is_df(unsigned long eflags);
_Bool is_of(unsigned long eflags);

// syscall_hook

hook_syscall get_syscall_hook(int syscall_number, mdata_binary_t* s_binary);

#endif