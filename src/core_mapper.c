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

#include "../include/dryadalis_x86.h"

/* Dieu et le Roy */

// *=*=*=*=*=*=*=

static char* s_weeb = "1337_wEeB_alW4yS_b4hiNd_tHe_ResEaRcHeR\0";
static char* s_arch = "x86_64\0"; 

// gen random base address
unsigned long base_address() {
    unsigned long ret = 0x0;
    int fd = 0;

    if (-1 == (fd = open("/dev/urandom", O_RDONLY))) {
        fprintf(stderr, "Error urandom");
        return -1;
    }

    read(fd, &ret, 0x5);
    return PAGE_ALIGN(ret);
}

// *=*=*=*=*=*=*=

// Load the interpreter
mdata_binary_t* load_interp(Elf64_Phdr* s_ph, mdata_binary_t* s_binary) {
    unsigned char* interp_str = s_binary->fbinary + (s_binary->pie ? s_ph->p_vaddr : s_ph->p_offset);
    mdata_binary_t* s_binary_interp = NULL;

    if (-1 == (long)(s_binary_interp = map_binary((const char* )interp_str, NULL)))
        return (mdata_binary_t*)-1;
    
    return s_binary_interp;
}

// *=*=*=*=*=*=*=

//manual mapping of a PT_LOAD segment
int map_load(Elf64_Phdr* s_ph, mdata_binary_t* s_binary) {
    unsigned long curr_map = 0x0;
    unsigned long sz = PAGE_ROUND((PAGE_ROUND((curr_map + s_ph->p_filesz)) - PAGE_ALIGN(curr_map)));

    if (!s_binary->base) {
        if (MAP_FAILED == (s_binary->base = mmap((void* )(s_binary->pie ? base_address() : s_ph->p_vaddr), sz, PROT_READ | PROT_WRITE | _PROT_EXEC(s_ph->p_flags), MAP_FIXED | MAP_PRIVATE, s_binary->fd, PAGE_ALIGN(s_ph->p_offset)))) {
            return -1;
        }
        list_add_map(s_binary, 
                PROT_READ | _PROT_EXEC(s_ph->p_flags) | _PROT_WRITE(s_ph->p_flags) | _PROT_EXEC(s_ph->p_flags),
                (unsigned long)s_binary->base,
                sz);
    } else {
        curr_map = (unsigned long)(s_binary->pie ? (unsigned long)s_binary->base + s_ph->p_vaddr : (unsigned long)s_ph->p_vaddr);
        if (MAP_FAILED == mmap((void *)PAGE_ALIGN(curr_map), PAGE_ROUND((PAGE_ROUND((curr_map + s_ph->p_filesz)) - PAGE_ALIGN(curr_map))), PROT_READ | PROT_WRITE | _PROT_EXEC(s_ph->p_flags), MAP_FIXED | MAP_PRIVATE, s_binary->fd, PAGE_ALIGN(s_ph->p_offset))) {
            return -1;
        }
        list_add_map(s_binary,
                PROT_READ | _PROT_EXEC(s_ph->p_flags) | _PROT_WRITE(s_ph->p_flags) | _PROT_EXEC(s_ph->p_flags),
                PAGE_ALIGN(curr_map),
                sz);
    }

    fprintf(stdout, 
            "[*] %lx - %lx %lx\n", 
            (unsigned long)(curr_map ? PAGE_ALIGN(curr_map) : (unsigned long)s_binary->base), 
            (unsigned long)((curr_map ? PAGE_ALIGN(curr_map) : (unsigned long)(s_binary->base)) + sz), 
            sz);

    if (s_ph->p_memsz > s_ph->p_filesz && curr_map) {
        unsigned long map_filesz = curr_map + s_ph->p_filesz;
        unsigned long map_end = PAGE_ROUND(map_filesz);

        unsigned long bss_end = PAGE_ROUND((curr_map + s_ph->p_memsz));

        // fprintf(stdout, "[+] %lx - %lx %lx\n", map_filesz, map_end, map_end-map_filesz);

        memset((void* )map_filesz,
               0x0,
               map_end - map_filesz);

        if (bss_end > map_end) {
            if (MAP_FAILED == mmap((void *)map_end+1, PAGE_ROUND((bss_end - map_end)), PROT_READ | _PROT_WRITE(s_ph->p_flags) | _PROT_EXEC(s_ph->p_flags), MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0x0)) {
                return -1;
            }
            fprintf(stdout, "[*] %lx - %lx %lx\n", map_end+1, map_end+1 + PAGE_ROUND((bss_end - map_end)), PAGE_ROUND((bss_end - map_end)));
            list_add_map(s_binary,
                    PROT_READ | PROT_WRITE,
                    map_end+1,
                    PAGE_ROUND((bss_end - map_end))); 
        }
    }

    // set the right permissions
    if (mprotect(curr_map ? (void *)PAGE_ALIGN(curr_map) : (void* )s_binary->base, PAGE_ROUND(s_ph->p_memsz), PROT_READ | _PROT_EXEC(s_ph->p_flags) | _PROT_WRITE(s_ph->p_flags) | _PROT_EXEC(s_ph->p_flags))) {
        return -1;
    }

    return 0;
}

// *=*=*=*=*=*=*=

// manual mapping of a binary from its filename
mdata_binary_t* map_binary(const char *filename, arg_t* arguments) {
    mdata_binary_t *s_binary = NULL;
    printf("[*] Loading %s\n", filename);

    if (-1 == (long)(s_binary = init_analysis(filename))) {
        fprintf(stderr, "Error init_analysis\n");
        return (mdata_binary_t*)-1;        
    }

    for (int i = 0; i < s_binary->eh->e_phnum; i++) {
        if (IS_INTERP(s_binary->s_ph[i])) {
            if (-1 == (long)(s_binary->interp = load_interp(s_binary->s_ph[i], s_binary))) {
                fprintf(stderr, "Error load interp\n");
                return (mdata_binary_t*)-1;
            }
        } else if (IS_LOAD(s_binary->s_ph[i])) {
            if (-1 == (long)map_load(s_binary->s_ph[i], s_binary)) {
                fprintf(stderr, "Error map_load, page: %lx\n", PAGE_ALIGN((unsigned long)(s_binary->s_ph[i]->p_vaddr + s_binary->base)));
                return (mdata_binary_t*)-1;
            }
        }
    }

    // we set rip 
    s_binary->dbi_handler->state->rip = (unsigned long)(s_binary->interp ? s_binary->interp->eh->e_entry + (s_binary->interp->base) : s_binary->eh->e_entry + (s_binary->pie ? s_binary->base : 0)); 
    
    // if there are arguments, we setup the stack
    if (arguments) {
        // it sets rsp
        setup_stack(arguments->argv, s_binary, arguments->argc);
    }

    fprintf(stdout, "[*] %s mapped\n", s_binary->filename);
    return s_binary;
}

// *=*=*=*=*=*=*=*=

// creates a stack
unsigned long* map_stack() {
    unsigned long* r = NULL;
    if (MAP_FAILED == (r = mmap(NULL, STACK_SZ, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0x0))) return (unsigned long*)-1;
    return (unsigned long* )(r+0x5000);
}

// maps values from argc to stack up to NULL byte
int map_val(unsigned long* arg, unsigned long* stack) {
    for(int i = 0; arg[i]; i++)    stack[i] = arg[i];
    return 0;
}

// maps auxvt from argc to stack up to NULL byte
int map_auxvt(unsigned long* arg, unsigned long* stack) {
    for(int i = 0; arg[i] || arg[i+1]; i++)    stack[i] = arg[i];
    return 0;
}

// get the axilary vector which corresponds to @id
unsigned long auxvt(unsigned long* orig, unsigned long id) {
    int i_orig = 0;
    for( ; orig[i_orig] != id && (orig[i_orig] || orig[i_orig+1]); i_orig++);
    return orig[i_orig+1];
}

// setup and returns a custom stack for the guest according to the arguments
unsigned long* setup_stack(char **argv, mdata_binary_t* s_binary, int argc) {
    unsigned long *iter = (unsigned long* )argv;
    unsigned long* stack = NULL;
    int idx = 0;

    if (-1 == (long)(stack = map_stack())) {
        return (unsigned long*)-1;
    }

    // we setup the rsp register directly in the structure, that's the only register setup by the mapping engine with rip
    s_binary->dbi_handler->state->rsp = (unsigned long)stack;
    list_add_map(s_binary, PROT_READ | PROT_WRITE, PAGE_ALIGN((s_binary->dbi_handler->state->rsp-0x5000)), PAGE_ROUND(STACK_SZ));

    stack[0] = argc-1;
    map_val(&iter[1], &stack[1]);
    idx++;// argv
    for ( ; iter[idx]; idx++);
    idx++;
    map_val(&iter[idx], &stack[idx]); // envp
    for ( ; iter[idx]; idx++);
    idx++;

    add_auxvt(AT_ENTRY, &iter[idx], &stack[idx], (unsigned long)(s_binary->base + s_binary->eh->e_entry));
    add_auxvt(AT_EXECFD, &iter[idx], &stack[idx], s_binary->fd);
    add_auxvt(AT_PHENT, &iter[idx], &stack[idx], s_binary->eh->e_phentsize);
    add_auxvt(AT_PHNUM, &iter[idx], &stack[idx], s_binary->eh->e_phnum);
    add_auxvt(AT_BASE, &iter[idx], &stack[idx], !s_binary->interp ? (unsigned long)s_binary->base : (unsigned long)(s_binary->interp->base));
    add_auxvt(AT_RANDOM, &iter[idx], &stack[idx], (unsigned long)&s_weeb);
    add_auxvt(AT_PHDR, &iter[idx], &stack[idx], (unsigned long)(s_binary->base + s_binary->eh->e_phoff));
    add_auxvt(AT_PLATFORM, &iter[idx], &stack[idx], (unsigned long)&s_arch);
    add_auxvt(AT_EGID, &iter[idx], &stack[idx], 1000);
    add_auxvt(AT_EUID, &iter[idx], &stack[idx], 1000);
    add_auxvt(AT_GID, &iter[idx], &stack[idx], 1000);
    add_auxvt(AT_UID, &iter[idx], &stack[idx], 1000);
    add_auxvt(AT_PAGESZ, &iter[idx], &stack[idx], 0x1000);
    add_auxvt(AT_EXECFN,  &iter[idx], &stack[idx], (unsigned long)(argv[1]));
    add_auxvt(AT_SYSINFO_EHDR,  &iter[idx], &stack[idx], auxvt(&iter[idx], AT_SYSINFO_EHDR));
    add_auxvt(AT_SECURE, &iter[idx], &stack[idx], 0x0);

    add_auxvt(AT_NULL, &iter[idx], &stack[idx], 0x0);

    //fprintf(stdout, "[*] vsdo @ %lx\n", auxvt(&iter[idx], AT_SYSINFO_EHDR));
    return stack;
}

// *=*=*=*=*=*=*=*=

mem_map_t* mem_desc(unsigned long addr, mdata_binary_t* s_binary) {
    mem_map_t* curr = NULL;

    list_for_each_entry(curr, &(s_binary->memory_map->list), list) {
        if (curr->addr <= PAGE_ALIGN(addr) && addr <= (curr->addr + curr->size)) {
            return curr;
        }
    }

    return (mem_map_t* )-1;
}

//==

// returns the prot according to the address
int prot(unsigned long addr, mdata_binary_t* s_binary) {
    mem_map_t* mem_descriptor = NULL;
    
    if (-1 == (long)(mem_descriptor = mem_desc(addr, s_binary))) {
        // if the address is not mapped it's not in read write lul
        return false;
    }

    return mem_descriptor->prot;
}

// is writable
int is_w(unsigned long addr, mdata_binary_t* s_binary) {
    mem_map_t* mem_descriptor = NULL;
    
    if (-1 == (long)(mem_descriptor = mem_desc(addr, s_binary))) {
        // if the address is not mapped it's not in read write lul
        return false;
    }

    return mem_descriptor->prot & PROT_WRITE;
}

// is read
int is_r(unsigned long addr, mdata_binary_t* s_binary) {
    mem_map_t* mem_descriptor = NULL;
    
    if (-1 == (long)(mem_descriptor = mem_desc(addr, s_binary))) {
        // if the address is not mapped it's not in read write lul
        return false;
    }

    return mem_descriptor->prot & PROT_READ;
}

// is executable
int is_x(unsigned long addr, mdata_binary_t* s_binary) {
    mem_map_t* mem_descriptor = NULL;
    
    if (-1 == (long)(mem_descriptor = mem_desc(addr, s_binary))) {
        // if the address is not mapped it's not in read write lul
        return false;
    }

    return mem_descriptor->prot & PROT_EXEC;
}

//==

_Bool is_ro(unsigned long addr, mdata_binary_t* s_binary) {
    mem_map_t* mem_descriptor = NULL;
    
    if (-1 == (long)(mem_descriptor = mem_desc(addr, s_binary))) {
        // if the address is not mapped it's not in read write lul
        return false;
    }

    return mem_descriptor->prot == PROT_READ;
}

_Bool is_rwx(unsigned long addr, mdata_binary_t* s_binary) {
    mem_map_t* mem_descriptor = NULL;
    
    if (-1 == (long)(mem_descriptor = mem_desc(addr, s_binary))) {
        // if the address is not mapped it's not in read write lul
        return false;
    }

    return mem_descriptor->prot & (PROT_READ | PROT_EXEC | PROT_READ);
}

_Bool is_rx(unsigned long addr, mdata_binary_t* s_binary) {
    mem_map_t* mem_descriptor = NULL;
    
    if (-1 == (long)(mem_descriptor = mem_desc(addr, s_binary))) {
        // if the address is not mapped it's not in read write lul
        return false;
    }

    return mem_descriptor->prot & (PROT_EXEC | PROT_READ);
}

//==

// check if @addr argument is in the doubly linked list memory_map 
_Bool is_mapped(unsigned long addr, mdata_binary_t* s_binary) {
    mem_map_t* curr = NULL;

    if (s_binary->memory_map->addr <= addr && s_binary->memory_map->addr + s_binary->memory_map->size > addr) {
        return true;
    }

    list_for_each_entry(curr, &(s_binary->memory_map->list), list) {
        if (curr->addr <= addr && (curr->addr + curr->size) > addr) {
            return true;
        }
    }

    return false;
}

// *=*=*=*=*=*=*=*=

// merge the address space of the target binary and its linker.
mem_map_t* merge_address_space(mdata_binary_t* s_binary) {
    mem_map_t* iter = NULL;

    if (s_binary->interp) {
        struct list_head* tmp = malloc(sizeof(struct list_head));
        tmp->next = s_binary->interp->memory_map->list.next;
        tmp->prev = &(s_binary->interp->memory_map->list);

        list_splice(tmp, &(s_binary->memory_map->list));
    }

    list_for_each_entry(iter, &(s_binary->memory_map->list), list) {
        merge_pages(s_binary, iter->prot, iter->addr, iter->size);
    }

    return s_binary->memory_map;
}

// free all the strcutures mem_map_t that belong to a binary
int free_memory_map(mem_map_t* memory_map) {
    mem_map_t* curr = NULL;

    list_for_each_entry(curr, &(memory_map->list), list) {
        free(container_of(curr->list.prev, mem_map_t, list));
    }

    free(memory_map->list.next);

    return 0;
} 

// adds a mem_map_t according to the new mapping's arguments
int list_add_map(mdata_binary_t* s_binary, int prot, unsigned long addr, ssize_t size) {
    mem_map_t* curr = malloc(sizeof(mem_map_t));
    curr->prot = prot;
    curr->addr = addr;
    curr->size = size;

    if (!s_binary->memory_map) {
        INIT_LIST_HEAD(&(curr->list));
    } else {
        list_add(&(curr->list), &(s_binary->memory_map->list));
    }

    s_binary->memory_map = curr;
    return 0;
}

int merge_pages(mdata_binary_t* s_binary, int prot, unsigned long addr, ssize_t size) {
    mem_map_t* iter = NULL;

    list_for_each_entry(iter, &(s_binary->memory_map->list), list) {
        if ((iter->addr + iter->size + 1) == addr && prot == iter->prot) {
            iter->size += size;
            return 0;
        }
    }
    return -1;
}

// Prints some mappings
int log_map(mem_map_t* memory_map) {
    mem_map_t* curr = NULL;

    list_for_each_entry(curr, &(memory_map->list), list) {
        fprintf(stdout, "[+] %lx %lx / %lx # %x\n", curr->addr, curr->addr + curr->size, curr->size, curr->prot);
    }

    fprintf(stdout, "[+] %lx %lx / %lx # %x\n", memory_map->addr, memory_map->addr + memory_map->size, memory_map->size, curr->prot);

    return 0;
}

// *=*=*=*=*=*=*=*=

// executes the binary
void exec_binary(mdata_binary_t* s_binary) {
    __asm__ __volatile__ (
        "mov %0, %%rax\n"
        "mov %1, %%rsp\n"
        "xor %%rbx, %%rbx\n"
        "xor %%rcx, %%rcx\n"
        "xor %%rdx, %%rdx\n"
        "xor %%rdi, %%rdi\n"
        "xor %%rsi, %%rsi\n"
        "xor %%r8, %%r8\n"
        "xor %%r9, %%r9\n"
        "xor %%r10, %%r10\n"
        "xor %%r11, %%r11\n"
        "xor %%r12, %%r12\n"
        "xor %%r13, %%r13\n"
        "xor %%r14, %%r14\n"
        "xor %%r15, %%r15\n"
        "xor %%rbp, %%rbp\n"
        "xorps %%xmm0, %%xmm0\n"
        "push %%rax\n"
        "xor %%rax, %%rax\n"
        "ret\n"
        :: "r"(s_binary->dbi_handler->state->rip), "r"(s_binary->dbi_handler->state->rsp) :);
}