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

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include "kernel_list.h"

int insn_count;

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
#define DEBUG false 

#define INSTRUMENT_BBL 0x0
#define INSTRUMENT_ADDR 0x1
#define INSTRUMENT_ADDR_ONLY 0x2
#define INSTRUMEN_PERSISTENT_HOOK 0x3

#define PERSISTENT_NOT_SET 0x0
#define PERSISTENT_FIND_SPACE 0x4

#define PERSISTENT_SET_ORIG_HOOK 0x5
#define PERSISTENT_SET_BR_HOOK 0x6

#define WRITE_HOOK_RAW 0x0
#define WRITE_HOOK_FULL 0x1

#define OPCODES_CFLOW_RAW 0x0
#define OPCODES_CFLOW_FULL 0x1

#define INSTRUCTION_MAX_SZ 16 

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
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rdx;
    uint64_t rcx;
    uint64_t r8;
    uint64_t r9;
} args_syscall_t;

typedef int (*u_callback_t) (void* s_binary);
typedef void (*destructor_t) (void);

typedef struct request_s {
    int type;
    uint64_t address;
    u_callback_t callback;
} request_t;

typedef struct hashmap_s {
    uint64_t** value;
} hashmap_t;

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
    __m512i zmm0 __attribute__((aligned(64)));
    __m512i zmm2 __attribute__((aligned(64)));
    __m512i zmm3 __attribute__((aligned(64)));
    __m512i zmm4 __attribute__((aligned(64)));
    __m512i zmm5 __attribute__((aligned(64)));
    __m512i zmm6 __attribute__((aligned(64)));
    __m512i zmm7 __attribute__((aligned(64)));
    __m512i zmm8 __attribute__((aligned(64)));
    __m512i zmm9 __attribute__((aligned(64)));
    __m512i zmm10 __attribute__((aligned(64)));
    __m512i zmm11 __attribute__((aligned(64)));
    __m512i zmm12 __attribute__((aligned(64)));
    __m512i zmm13 __attribute__((aligned(64)));
    __m512i zmm14 __attribute__((aligned(64)));
    __m512i zmm15 __attribute__((aligned(64)));
    __m512i zmm16 __attribute__((aligned(64)));
    __m512i zmm17 __attribute__((aligned(64)));
    __m512i zmm18 __attribute__((aligned(64)));
    __m512i zmm19 __attribute__((aligned(64)));
    __m512i zmm20 __attribute__((aligned(64)));
    __m512i zmm21 __attribute__((aligned(64)));
    __m512i zmm22 __attribute__((aligned(64)));
    __m512i zmm23 __attribute__((aligned(64)));
    __m512i zmm24 __attribute__((aligned(64)));
    __m512i zmm25 __attribute__((aligned(64)));
    __m512i zmm26 __attribute__((aligned(64)));
    __m512i zmm27 __attribute__((aligned(64)));
    __m512i zmm28 __attribute__((aligned(64)));
    __m512i zmm29 __attribute__((aligned(64)));
    __m512i zmm30 __attribute__((aligned(64)));
    __m512i zmm31 __attribute__((aligned(64)));
} __attribute__((aligned(64))) avx512_t;

typedef struct state_rtime_s {
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t rbp;

    uint64_t rsp;
    uint64_t rip;
    uint64_t rflags;
    uint64_t cs;
    uint64_t ss;
    uint64_t gs;
    uint64_t es;
    uint64_t ds;
    uint64_t fs;

    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;

    sse_t* sse;
    avx2_t* avx2;
    avx512_t* avx512;

    uint64_t null_entry;
} state_rtime_t;

typedef struct arg_s {
    int argc;
    char** argv;
} arg_t;

typedef struct hook_s {
    uint8_t* code;
    uint8_t* orig_bytes;
    ssize_t length;
    uint64_t jmp;
    uintptr_t to_unmap;
    int prot_restore;
} hook_t;

typedef struct persistent_s {
    int state;
    uint64_t address;
} persistent_t;

typedef struct capstone_hanlder_s {
    csh handle;
    cs_insn *insn;
    uint8_t *instructions;
    size_t count;
} capstone_hanlder_t;

typedef struct dbi_instr_s {
    _Bool take_callback;
    state_rtime_t* state;
    state_rtime_t* host_state;
    u_callback_t u_handler;
    hook_t* dump;
    hook_t* restore;
    destructor_t dtor;
    uint8_t* dump_stub;
    uint8_t* restore_stub;
    uint64_t* curr_hook;
    uint64_t *host_rsp;
    hashmap_t* hashmap;
    uint64_t instrumented_fs;
    uint64_t instrumented_gs;
    int64_t length_cflow;
    request_t* request;
    persistent_t* persistent_hook;
    capstone_hanlder_t* cps_utils;
    int8_t curr_instr_mode;
} dbi_instr_t;

typedef struct mem_map_s {
    struct list_head list;
    uint64_t addr;
    ssize_t size;
    int prot;
    _Bool sync;
} mem_map_t;

typedef struct mdata_binary_s {
    uint8_t *fbinary; // malloc pointer to the binary
    uint64_t len_file;
    const char *filename;
    int fd; // fd of the binary
    Elf64_Phdr** s_ph; // list of pointer to the program header
    Elf64_Ehdr* eh;
    _Bool pie; // is pie ?
    struct mdata_binary_s *interp; // pointer to the real interp mapped
    uint8_t *base; // real base address of the manual mapped binary
    mem_map_t* memory_map;
    uint64_t dispatcher;
    dbi_instr_t* dbi_handler;
    uint64_t exec_entry;
    FILE* debug_stream;
} mdata_binary_t;

typedef uint64_t (*hook_syscall) (mdata_binary_t* s_binary);

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

_Bool is_elf(uint8_t *eh_ptr);
uint64_t search_base_addr(Elf64_Phdr *buffer_mdata_phdr[], Elf64_Ehdr *eh_ptr);
Elf64_Phdr *search_pt_dyn(Elf64_Phdr **buffer_mdata_ph, Elf64_Ehdr *eh_ptr);
int parse_phdr(Elf64_Ehdr *ptr, Elf64_Phdr *buffer_mdata_ph[]);
int parse_shdr(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[]);
char **parse_sh_name(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[], char **sh_name_buffer);
int init_struct(Elf64_Shdr *buffer_mdata_sh[], Elf64_Phdr *buffer_mdata_ph[], char **sh_name, Elf64_Ehdr *ptr);
mdata_binary_t *init_analysis(const char *s);
int end_analysis(mdata_binary_t *s_binary);
mdata_binary_t* alloc_binary();
int add_auxvt(uint64_t id, uint64_t *base_auxvt, uint64_t val);

// core_mapper

mdata_binary_t* map_binary(const char *filename, arg_t* arguments);
mdata_binary_t* load_interp(Elf64_Phdr* s_ph, mdata_binary_t* s_binary);
int map_load(Elf64_Phdr* s_ph, mdata_binary_t* s_binary);
uint64_t* setup_stack(char **argv, mdata_binary_t* s_binary, int argc);
void exec_binary(mdata_binary_t* s_binary);
int list_add_map(mdata_binary_t* s_binary, int prot, uint64_t addr, uint64_t size);
int free_memory_map(mem_map_t* memory_map);
int log_map(mem_map_t* memory_map, FILE* stream);
mem_map_t* merge_address_space(mdata_binary_t* s_binary);
mem_map_t* get_mem_desc(mdata_binary_t* s_binary, uint64_t addr);
int list_del_map(mdata_binary_t* s_binary, uint64_t addr, uint32_t size);
_Bool is_mapped(uint64_t addr, mdata_binary_t* s_binary);
_Bool is_mapped_range(mdata_binary_t* s_binary, uint64_t base, size_t range);
_Bool is_rx(uint64_t addr, mdata_binary_t* s_binary);
_Bool is_ro(uint64_t addr, mdata_binary_t* s_binary);
_Bool is_rw(uint64_t addr, mdata_binary_t* s_binary);
_Bool is_rwx(uint64_t addr, mdata_binary_t* s_binary);

// returns the prot according to the address
int prot(mdata_binary_t* s_binary, uint64_t addr);
uint64_t* map_stack();
int merge_pages(mdata_binary_t* s_binary, int prot, uint64_t addr, ssize_t size);
int update_vprot(mdata_binary_t* s_binary, uint64_t addr, uint64_t size, int new_prot);

// engine

// encodes the patch used as a trampoline in @patch to @target, returns -1 if it fails and else the length of the patch 
int dump_hook(uint8_t* patch, mdata_binary_t* s_binary);
// returns the newly mmapped shellcode that dumps the state of the guest into the state struct
uint64_t craft_hook(mdata_binary_t* s_binary);
int restore_hook(uint8_t* patch, mdata_binary_t* s_binary);

int instrument(mdata_binary_t* s_binary);
uint64_t _instrument_bbl(mdata_binary_t* s_binary, hook_t* hook, uint64_t base);

uint64_t br_emulation(mdata_binary_t* s_binary, uint64_t addr);
void _dispatcher(mdata_binary_t* s_binary);

void alloc_state(mdata_binary_t* s_binary);
void continue_exec(mdata_binary_t* s_binary);
int restore_bytes(hook_t* hook, mdata_binary_t* s_binary);
int write_hook(mdata_binary_t* s_binary, hook_t* hook, int opt);
int host_save_state(state_rtime_t* state);

int arch_prctl(int func, void *ptr);
int set_fs_gs(void* fs, void* gs);
uint64_t _get_bbl_base(mdata_binary_t* s_binary);

void default_dtor(void);
int set_fs_gs(void* fs, void* gs);
void fatal_dump(mdata_binary_t* s_binary);

// state_runt

hashmap_t* init_hashmap(hashmap_t* hashmap, mdata_binary_t* s_binary);
int free_hashmap(hashmap_t* hashmap);
void update_reg(int key, hashmap_t* hashmap, uint64_t value);

_Bool is_8bits_right(int reg);
_Bool is_8bits_left(int reg);
_Bool is_16bits(int reg);
_Bool is_32bits(int reg);
_Bool is_64bits(int reg);
uint64_t read_reg(int key, hashmap_t* hashmap);

void log_regs(mdata_binary_t* s_binary, FILE* stream);
void log_general(state_rtime_t* state, FILE* stream);
void log_avx2(state_rtime_t* state, FILE* stream);
void log_sse(state_rtime_t* state, FILE* stream);

_Bool is_cf(uint64_t eflags);
_Bool is_pf(uint64_t eflags);
_Bool is_af(uint64_t eflags);
_Bool is_zf(uint64_t eflags);
_Bool is_sf(uint64_t eflags);
_Bool is_tf(uint64_t eflags);
_Bool is_if(uint64_t eflags);
_Bool is_df(uint64_t eflags);
_Bool is_of(uint64_t eflags);



// analysis

/*
    opcodes_cflow - returns how many bytes there are up to the next control flow instruction
    @addr: address from which the analysis began
    @s_binary: object descriptor
    @beg: bool set to true when it's called for the first time
    @opt: useless
*/
int opcodes_cflow(uint64_t addr, mdata_binary_t* s_binary, _Bool beg);

/* insn_len - returns the length of the instruction for which target points to
    @target: address of the target instruction
    @s_binary: object descriptor
*/
off_t insn_len(uint64_t target, mdata_binary_t* s_binary);

/*
    is_jmp_taken - checks if a jmp is taken ot not
    @id: capstone id of the instruction
    @s_binary: object descriptor
*/
_Bool is_jmp_taken(int id, mdata_binary_t* s_binary);

/*
    is_test - checks if the instruction checks the eflags
    @cs_eflags: capstone eflags
*/
_Bool is_test(uint64_t cs_eflags);

/*
    is_set - checks if a particular flag is set in the eflags 
*/
_Bool is_set(mdata_binary_t* s_binary, int flag);

/*
    __eval_target - returns the actual target for the @insn
    @s_binary: object descriptor
    @insn: capstone instruction
    @instruction address
*/
uint64_t __eval_target(cs_insn* insn, mdata_binary_t* s_binary, uint64_t instruction);

/*
    eval_target - returns the actual target for the control flow instruction @instruction
    @instruction: pointer to the control flow instruction
    @s_binary: object descriptor
*/
uint64_t eval_target(uint8_t* instruction, mdata_binary_t* s_binary);





/* syscall_hook */

hook_syscall get_syscall_hook(int syscall_number, mdata_binary_t* s_binary);






/* memory */

/*
    Safe wrapper for mprotect with READ protections
    @s_binary: binary descriptor
    @addr: page we have to mprotect
    @size: size we would like to mprotect

    returns -1 if it fails, else 0
*/
mem_map_t* make_readable(mdata_binary_t* s_binary, uint64_t address, ssize_t size);

/*
    Safe wrapper for mprotect with PROT_READ | PROT_WRITE protections
    @s_binary: binary descriptor
    @addr: page we have to mprotect
    @size: size we would like to mprotect

    returns -1 if it fails, else 0
*/
mem_map_t* make_writable(mdata_binary_t* s_binary, uint64_t address, ssize_t size);

/*
    Safe wrapper for mprotect with PROT_READ | PROT_EXEC protections
    @s_binary: binary descriptor
    @addr: page we have to mprotect
    @size: size we would like to mprotect

    returns -1 if it fails, else 0
*/
mem_map_t* make_executable(mdata_binary_t* s_binary, uint64_t address, ssize_t size);

/*
    restore_vprot - Restore the virtual protections for one or more pages
    @s_binary: binary object
    @size: how much we restore
    @_mem_desc: the page descriptor from where we want to restore

    returns -1 if it fails else 0
*/
int restore_vprot(mdata_binary_t* s_binary, size_t size, mem_map_t* _mem_desc, off_t offset);

/*
    mem_read - read @size bytes from @from to @to
    @s_binary: object descriptor
    @to: buffer to get the bytes
    @from: pointer to which we read bytes
    @size: how many bytes we have to read
*/
int mem_read(mdata_binary_t* s_binary, void* to, uint64_t from, size_t size);

/*
    mem_write - write @size bytes at @to from @from
    @s_binary: object descriptor
    @to: memory area to write
    @from: pointer from which we have to write
    @size: how many bytes we have to write
*/
int mem_write(mdata_binary_t* s_binary, uint64_t to, void* from, size_t size);

#endif
