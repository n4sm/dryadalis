#ifndef ELF_PARSING_H_
#define ELF_PARSING_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libelf.h>
#include <elf.h>
#include <stdbool.h>
#include <sys/mman.h>

#include "kernel_list.h"
#include "engine.h"

// struct

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
    _Bool take_callback; // internal field
    struct mdata_binary_s *interp; // pointer to the real interp mapped
    unsigned char *base; // real base address of the manual mapped binary
    mem_map_t* memory_map;
    state_rtime_t* state;
    unsigned long *host_rsp;
    unsigned long dispatcher;
    u_callback_t u_handler;
    unsigned char* orig_bytes;
    ssize_t length_trampoline;
    unsigned long curr_hook;
} mdata_binary_t;

// functions

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

// macros

#define PAGE_SZ 0x1000
#define ELF_MIN_ALIGN PAGE_SZ

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

#endif