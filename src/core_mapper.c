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
#include <sys/ioctl.h>

#include "../include/dryadalis_x86.h"

/* Dieu et le Roy */

static char* _random = "fae5fff9bdaa059af959baedeac94d30";
static char* s_arch = "x86_64\0"; 

// gen random base address
uint64_t base_address()
{
    uint64_t ret = 0x0;
    int fd = 0;

    if (-1 == (fd = open("/dev/urandom", O_RDONLY))) {
        fprintf(stderr, "Error urandom");
        return -1;
    }

    read(fd, &ret, 0x5);
    return PAGE_ALIGN(ret);
}

// Load the interpreter
mdata_binary_t* load_interp(Elf64_Phdr* s_ph, mdata_binary_t* s_binary) 
{
    uint8_t* interp_str = s_binary->fbinary + (s_binary->pie ? s_ph->p_vaddr : s_ph->p_offset);
    mdata_binary_t* s_binary_interp = NULL;

    if (-1 == (long)(s_binary_interp = map_binary((const char* )interp_str, NULL)))
        return (mdata_binary_t*)-1;
    
    return s_binary_interp;
}

//manual mapping of a PT_LOAD segment
int map_load(Elf64_Phdr* s_ph, mdata_binary_t* s_binary) 
{
    uint64_t curr_map = 0x0;
    uint64_t sz = PAGE_ROUND((PAGE_ROUND((curr_map + s_ph->p_filesz))));

    if (!s_binary->base) {
        if (MAP_FAILED == (s_binary->base = (uint8_t* )mmap((void* )(s_binary->pie ? base_address() : s_ph->p_vaddr), sz, PROT_READ | PROT_WRITE | _PROT_EXEC(s_ph->p_flags), MAP_FIXED | MAP_PRIVATE, s_binary->fd, PAGE_ALIGN(s_ph->p_offset)))) {
            return -1;
        }
        // list_add_map(s_binary, 
        //         PROT_READ | _PROT_EXEC(s_ph->p_flags) | _PROT_WRITE(s_ph->p_flags),
        //         (uint64_t)s_binary->base,
        //         sz + 1); // fff + 1
    } else {
        curr_map = (uint64_t)(s_binary->pie ? (uint64_t)s_binary->base + s_ph->p_vaddr : (uint64_t)s_ph->p_vaddr);
        if (MAP_FAILED == mmap((void *)PAGE_ALIGN(curr_map), PAGE_ROUND((PAGE_ROUND((curr_map + s_ph->p_filesz)) - PAGE_ALIGN(curr_map))), PROT_READ | PROT_WRITE | _PROT_EXEC(s_ph->p_flags), MAP_FIXED | MAP_PRIVATE, s_binary->fd, PAGE_ALIGN(s_ph->p_offset))) {
            return -1;
        }
        // list_add_map(s_binary,
        //         PROT_READ | _PROT_EXEC(s_ph->p_flags) | _PROT_WRITE(s_ph->p_flags),
        //         PAGE_ALIGN(curr_map),
        //         sz + 1); // fff + 1
    }

    if (DEBUG & LOG_MAP) fprintf(s_binary->debug_stream, 
                                "[>] %lx - %lx %lx\n", 
                                (uint64_t)(curr_map ? PAGE_ALIGN(curr_map) : (uint64_t)s_binary->base), 
                                (uint64_t)((curr_map ? PAGE_ALIGN(curr_map) : (uint64_t)(s_binary->base)) + sz), 
                                sz + 1); // fff + 1

    if (s_ph->p_memsz > s_ph->p_filesz && curr_map) {
        uint64_t map_filesz = curr_map + s_ph->p_filesz;
        uint64_t map_end = PAGE_ROUND(map_filesz);

        uint64_t bss_end = PAGE_ROUND((curr_map + s_ph->p_memsz));

        memset((void* )map_filesz,
               0x0,
               map_end - map_filesz);

        if (bss_end > map_end) {
            if (MAP_FAILED == mmap((void *)map_end+1, PAGE_ROUND((bss_end - map_end)) + 1, PROT_READ | _PROT_WRITE(s_ph->p_flags) | _PROT_EXEC(s_ph->p_flags), MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, -1, 0x0)) {
                return -1;
            }

            if (DEBUG & LOG_MAP) fprintf(s_binary->debug_stream, "[>] %lx - %lx %lx\n", map_end+1, map_end+1 + PAGE_ROUND((bss_end - map_end)), PAGE_ROUND((bss_end - map_end))+1);

            s_binary->dbi_handler->vbrk = (uint8_t* )((map_end + 1 + PAGE_ROUND((bss_end - map_end))) + 1);
            if (DEBUG & LOG_MAP) {
                fprintf(s_binary->debug_stream, "[>] s_binary->dbi_handler->vbrk: %lx\n", (uint64_t)s_binary->dbi_handler->vbrk);
            }
        } else {
            if (s_ph->p_flags & PF_W) {
                s_binary->dbi_handler->vbrk = (uint8_t* )((uint64_t)((curr_map ? PAGE_ALIGN(curr_map) : (uint64_t)(s_binary->base)) + sz) + 1);
                if (DEBUG & LOG_MAP) {
                    fprintf(s_binary->debug_stream, "[>] s_binary->dbi_handler->vbrk: %lx\n", (uint64_t)s_binary->dbi_handler->vbrk);
                }
            }
        }
    } else {
        if (s_ph->p_flags & PF_W) {
            s_binary->dbi_handler->vbrk = (uint8_t* )((uint64_t)((curr_map ? PAGE_ALIGN(curr_map) : (uint64_t)(s_binary->base)) + sz) + 1);
            if (DEBUG & LOG_MAP) {
                fprintf(s_binary->debug_stream, "[>] s_binary->dbi_handler->vbrk: %lx\n", (uint64_t)s_binary->dbi_handler->vbrk);
            }
        }
    }



    // set the right permissions
    if (mprotect(curr_map ? (void *)PAGE_ALIGN(curr_map) : (void* )s_binary->base, PAGE_ROUND(s_ph->p_memsz), PROT_READ | _PROT_EXEC(s_ph->p_flags) | _PROT_WRITE(s_ph->p_flags) | _PROT_EXEC(s_ph->p_flags))) {
        return -1;
    }

    return 0;
}

// manual mapping of a binary from its filename
mdata_binary_t* map_binary(const char *filename, arg_t* arguments) 
{
    mdata_binary_t *s_binary = NULL;
    if (DEBUG & LOG_MAP) printf("[+] Loading %s\n", filename);

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
                fprintf(stderr, "Error map_load, page: %lx\n", PAGE_ALIGN((uint64_t)(s_binary->s_ph[i]->p_vaddr + s_binary->base)));
                return (mdata_binary_t*)-1;
            }
        }
    }

    // if there are arguments, we setup the stack
    if (arguments) {
        // it sets rsp
        setup_stack(arguments->argv, s_binary, arguments->argc);
    }

    s_binary->exec_entry = (uint64_t)(s_binary->interp ? 
                                                        (uint64_t)(s_binary->interp->pie ? (uint64_t)(s_binary->interp->base + s_binary->interp->eh->e_entry) : (uint64_t)s_binary->interp->eh->e_entry) 
                                                       : (uint64_t)(s_binary->pie ? (uint64_t)(s_binary->base + s_binary->eh->e_entry) : (uint64_t)s_binary->eh->e_entry));

    if (DEBUG & LOG_MAP) fprintf(s_binary->debug_stream, "[+] %s mapped\n", s_binary->filename);
    return s_binary;
}

// creates a stack
uint64_t* map_stack() 
{
    uint64_t* r = NULL;
    if (MAP_FAILED == 
                  (r = (uint64_t* )mmap(NULL, 
                                        STACK_SZ, 
                                        PROT_READ | PROT_WRITE, 
                                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK | MAP_GROWSDOWN, 
                                        -1, 
                                        0x0))) return (uint64_t*)-1;
    return (uint64_t* )(r+0x5000);
}

// maps values from argc to stack up to NULL byte
int map_val(uint64_t* arg, uint64_t* stack) 
{
    for(int i = 0; arg[i]; i++)    stack[i] = arg[i];
    return 0;
}

// maps auxvt from argc to stack up to NULL byte
int map_auxvt(uint64_t* arg, uint64_t* stack) 
{
    for(int i = 0; arg[i] || arg[i+1]; i++)    stack[i] = arg[i];
    return 0;
}

// get the axilary vector which corresponds to @id
uint64_t auxvt(uint64_t* orig, uint64_t id) 
{
    int i_orig = 0;
    for( ; orig[i_orig] != id && (orig[i_orig] || orig[i_orig+1]); i_orig++);
    return orig[i_orig+1];
}

// setup and returns a custom stack for the guest according to the arguments
uint64_t* setup_stack(char **argv, mdata_binary_t* s_binary, int argc) 
{
    uint64_t *iter = (uint64_t* )argv;
    uint64_t* stack = NULL;
    int idx = 0;

    if (-1 == (long)(stack = map_stack())) {
        return (uint64_t*)-1;
    }

    // we setup the rsp register directly in the structure, that's the only register setup by the mapping engine with rip
    s_binary->dbi_handler->base_guest_stack = (uint64_t)stack - 0x200000;
    s_binary->dbi_handler->state->rsp = (uint64_t)stack;
    // list_add_map(s_binary, PROT_READ | PROT_WRITE, PAGE_ALIGN((s_binary->dbi_handler->state->rsp-0x5000)), PAGE_ROUND(STACK_SZ)+1);

    stack[0] = argc-1;
    map_val(&iter[1], &stack[1]);
    idx++;// argv
    for ( ; iter[idx]; idx++);
    idx++;
    map_val(&iter[idx], &stack[idx]); // envp
    for ( ; iter[idx]; idx++);
    idx++;

    add_auxvt(AT_ENTRY, &stack[idx], s_binary->pie ? (uint64_t)(s_binary->base + s_binary->eh->e_entry) : s_binary->eh->e_entry);
    add_auxvt(AT_EXECFD, &stack[idx], s_binary->fd);
    add_auxvt(AT_PHENT, &stack[idx], s_binary->eh->e_phentsize);
    add_auxvt(AT_PHNUM, &stack[idx], s_binary->eh->e_phnum);
    add_auxvt(AT_BASE, &stack[idx], !s_binary->interp ? (uint64_t)s_binary->base : (uint64_t)(s_binary->interp->base));
    add_auxvt(AT_RANDOM, &stack[idx], (uint64_t)&_random);
    add_auxvt(AT_PHDR, &stack[idx], (uint64_t)(s_binary->base + s_binary->eh->e_phoff));
    add_auxvt(AT_PLATFORM, &stack[idx], (uint64_t)&s_arch);
    add_auxvt(AT_EGID, &stack[idx],1000);
    add_auxvt(AT_EUID, &stack[idx], 1000);
    add_auxvt(AT_GID, &stack[idx], 1000);
    add_auxvt(AT_UID, &stack[idx], 1000);
    add_auxvt(AT_PAGESZ, &stack[idx], 0x1000);
    add_auxvt(AT_EXECFN, &stack[idx], (uint64_t)(argv[1]));
    // add_auxvt(AT_SYSINFO_EHDR, &stack[idx], AT_IGNORE);
    // You know why ..
    add_auxvt(AT_SECURE, &stack[idx], 0x0);

    add_auxvt(AT_NULL, &stack[idx], 0x0);

    // parse_maps(s_binary);

    return stack;
}

/*
    is_mapped_range - checks if a memory range is mapped  
    @s_binary: object descriptor
    @base: base address (aligned) of the range we're checkin
    @range: range we're checking from @base
*/
_Bool is_mapped_range(mdata_binary_t* s_binary, uint64_t base, size_t range) 
{
    for (size_t i = 0; i < PAGE_ROUND(range) + 1; i += PAGE_SZ) {
        if (!is_mapped(base + i, s_binary)) {
            fprintf(stderr, "> is_mapped_range > %lx not mapped\n", base + i);
            return false;
        }
    }

    return true;
}

/*
    get_mem_desc - returns the memory descriptor of the @addr unaligned address
    @s_binary: binary descriptor
    @addr: address for which we're looking for the page descripror, can be unaligned
*/
mem_map_t* get_mem_desc(mdata_binary_t* s_binary, uint64_t addr) 
{
    mem_map_t* curr = s_binary->memory_map ? s_binary->memory_map : s_binary->interp->memory_map;
    assert(curr);

    do {
        if (curr->addr == PAGE_ALIGN(addr)) return curr;
        curr = container_of(curr->list.next, mem_map_t, list);
    } while (curr != (s_binary->memory_map ? s_binary->memory_map : s_binary->interp->memory_map));

    if (DEBUG) fprintf(stderr, "> get_mem_desc: failed to get the memory descriptor for %lx\n", addr);
    assert(curr == (s_binary->memory_map ? s_binary->memory_map : s_binary->interp->memory_map));

    return (mem_map_t* )-1;
}

/*
    update_vprot - update the protections and the sync field of a memory descriptor

    @s_binary: binary object
    @addr: address we handle
    @size: size on which we're updating the protections from @addr
    @new_prot: new protections

    returns -1 if it fails else 0
*/
int update_vprot(mdata_binary_t* s_binary, uint64_t addr, uint64_t size, int new_prot) 
{
    mem_map_t* _mem_desc = NULL;

    if (size % PAGE_SZ || addr % PAGE_SZ) {
        fprintf(stderr, "Invalid size or addr > @update_vprot, size: %lx, addr: %lx\n", size, addr);
        return -1;
    }

    for (size_t i = 0; i < size; i += PAGE_SZ) {
        if (-1 == (long)(_mem_desc = get_mem_desc(s_binary, addr + i))) {
            fprintf(stderr, "> @update_vprot: %lx isn't mapped\n", addr);
            return -1;
        }

        _mem_desc->prot = new_prot;
        _mem_desc->sync = true;
    }

    return 0;
}

// returns the prot according to the address
int prot(mdata_binary_t* s_binary, uint64_t addr) 
{
    mem_map_t* mem_descriptor = NULL;
    
    if (-1 == (long)(mem_descriptor = get_mem_desc(s_binary, PAGE_ALIGN(addr)))) {
        // if the address is not mapped it's not in read write lul
        return -1;
    }

    return mem_descriptor->prot;
}

// is writable
int is_w(uint64_t addr, mdata_binary_t* s_binary) 
{
    mem_map_t* mem_descriptor = NULL;
    
    if (-1 == (long)(mem_descriptor = get_mem_desc(s_binary, addr))) {
        // if the address is not mapped it's not in read write lul
        return false;
    }

    return mem_descriptor->prot & PROT_WRITE;
}

// is read
int is_r(uint64_t addr, mdata_binary_t* s_binary) 
{
    mem_map_t* mem_descriptor = NULL;
    
    if (-1 == (long)(mem_descriptor = get_mem_desc(s_binary, addr))) {
        // if the address is not mapped it's not in read write lul
        return false;
    }

    return mem_descriptor->prot & PROT_READ;
}

// is executable
int is_x(uint64_t addr, mdata_binary_t* s_binary) 
{
    mem_map_t* mem_descriptor = NULL;
    
    if (-1 == (long)(mem_descriptor = get_mem_desc(s_binary, addr))) {
        // if the address is not mapped it's not in read write lul
        return false;
    }

    return mem_descriptor->prot & PROT_EXEC;
}

_Bool is_ro(uint64_t addr, mdata_binary_t* s_binary) 
{
    mem_map_t* mem_descriptor = NULL;
    
    if (-1 == (long)(mem_descriptor = get_mem_desc(s_binary, addr))) {
        // if the address is not mapped it's not in read write lul
        return false;
    }

    return mem_descriptor->prot == PROT_READ;
}

_Bool is_rwx(uint64_t addr, mdata_binary_t* s_binary) 
{
    mem_map_t* mem_descriptor = NULL;
    
    if (-1 == (long)(mem_descriptor = get_mem_desc(s_binary, addr))) {
        // if the address is not mapped it's not in read write lul
        return false;
    }

    return mem_descriptor->prot & (PROT_READ | PROT_EXEC | PROT_READ);
}

_Bool is_rx(uint64_t addr, mdata_binary_t* s_binary) 
{
    mem_map_t* mem_descriptor = NULL;
    
    if (-1 == (long)(mem_descriptor = get_mem_desc(s_binary, addr))) {
        // if the address is not mapped it's not in read write lul
        return false;
    }

    return mem_descriptor->prot & (PROT_EXEC | PROT_READ);
}

// check if @addr argument is in the doubly linked list memory_map 
_Bool is_mapped(uint64_t addr, mdata_binary_t* s_binary) 
{
    umaps_request_t req = {.addr = addr, .size = PAGE_SZ};

    if (-1 == ioctl(s_binary->dbi_handler->fd_umaps, UMAPS_IS_MAPPED, &req)) {
        fprintf(stderr, "> @is_mapped: failed to check if %lx is mapped\n", addr);
        fatal_dump(s_binary);
    }

    return (_Bool)req.result;
}

// // check if @addr argument is in the doubly linked list memory_map 
// _Bool is_mapped_flat(uint64_t addr, mdata_binary_t* s_binary) 
// {
//     mem_map_t* curr = NULL;

//     if (-1 == (long)(curr = get_mem_desc(s_binary, PAGE_ALIGN(addr)))) {
//         fprintf(stderr, "> failed @is_mapped_flat\n");
//         return false;
//     }

//     return true;
// }

// merge the address space of the target binary and its linker.
mem_map_t* merge_address_space(mdata_binary_t* s_binary) 
{
    // mem_map_t* iter = NULL;

    if (s_binary->interp) {
		struct list_head* prev_binary = s_binary->memory_map->list.prev;
		struct list_head* prev_interp = s_binary->interp->memory_map->list.prev;

		s_binary->memory_map->list.prev = prev_interp;
		prev_interp->next = &s_binary->memory_map->list;		

		s_binary->interp->memory_map->list.prev = prev_binary;
		prev_binary->next = &s_binary->interp->memory_map->list;
    }

    return s_binary->memory_map;
}

// free all the structures mem_map_t that belong to a binary
int free_memory_map(mem_map_t* memory_map) 
{
    struct list_head* next = NULL;
    mem_map_t* curr = memory_map;

    assert(curr);

    do {
        next = curr->list.next;
        free(curr);
        curr = container_of(next, mem_map_t, list);
    } while (curr != memory_map);

    return 0;
} 
/*
// adds a mem_map_t according to the new mapping's arguments
int list_add_map(mdata_binary_t* s_binary, int prot, uint64_t addr, uint64_t size) 
{
    mem_map_t* _tmp_desc = NULL;
    if (size % PAGE_SZ || addr % PAGE_SZ) {
        fprintf(stderr, "Invalid size or addr > @list_add_map, size: %lx, addr: %lx\n", size, addr);
        return -1;
    }    

    for (uint64_t i = 0; i < size; i += PAGE_SZ) {
        if (s_binary->memory_map && -1 != (_tmp_desc = get_mem_desc(s_binary, addr + i))) {
            if (_tmp_desc->prot != prot) {
                _tmp_desc->prot = prot;
            } else {
                continue;
            }
        }

        mem_map_t* curr = (mem_map_t* )malloc(sizeof(mem_map_t));
        curr->addr = PAGE_ALIGN(addr) + i;
        curr->size = PAGE_SZ;
        curr->prot = prot;
        curr->sync = true;

        if (DEBUG) {
            fprintf(s_binary->debug_stream, "[K=%lx] ++ %lx -- %lx | %x\n", i, curr->addr, curr->addr + PAGE_SZ-1, PAGE_SZ);
        }

        if (!s_binary->memory_map) {
            s_binary->memory_map = curr;

            if (DEBUG) fprintf(s_binary->debug_stream, "[K] size: %lx ++ %lx -- %lx | %x\n", size, curr->addr, curr->addr + PAGE_SZ-1, PAGE_SZ);
            curr->list.next = &curr->list;
            curr->list.prev = &curr->list;
        } else {
            s_binary->memory_map->list.prev->next = &curr->list;
            curr->list.prev = s_binary->memory_map->list.prev;

            s_binary->memory_map->list.prev = &curr->list;
            curr->list.next = &s_binary->memory_map->list;
        }
    }

    return 0;
}
*/

int list_del_map(mdata_binary_t* s_binary, uint64_t addr, uint32_t size) 
{
    mem_map_t* _mem_desc = NULL;

    if (size % PAGE_SZ || addr % PAGE_SZ) {
        fprintf(stderr, "Invalid size or addr > @list_del_map, size: %x, addr: %lx\n", size, addr);
        exit(-1);
    }

    for (size_t i = 0; i < size; i += PAGE_SZ) {      
        if (-1 == (long)(_mem_desc = get_mem_desc(s_binary, addr + i))) {
            return false;
        }

        _mem_desc->list.next->prev = _mem_desc->list.prev;
        _mem_desc->list.prev->next = _mem_desc->list.next;
        free(_mem_desc);
    }

    return 0;
}

// Prints some mappings
int log_map(mem_map_t* memory_map, FILE* stream) 
{
    mem_map_t* curr = memory_map;

    uint64_t g_addr = curr->addr;
    int g_prot = curr->prot;
    size_t g_size = curr->size;

    assert(curr);

    do {
        if (g_size == PAGE_SZ) {
            g_addr = curr->addr;
            g_prot = curr->prot;
            g_size = curr->size;            
        }

        if (curr->addr + curr->size == container_of(curr->list.next, mem_map_t, list)->addr
            && curr->prot == container_of(curr->list.next, mem_map_t, list)->prot) {
            g_size += PAGE_SZ;
        } else {
            fprintf(stream, "[+] %lx %lx / %lx # %x\n", g_addr, g_addr + g_size-1, g_size, g_prot);
            g_size = curr->size;
        }

        // fprintf(stream, "[+] %lx %lx / %lx # %x\n", curr->addr, curr->addr + curr->size-1, curr->size, curr->prot);

        curr = container_of(curr->list.next, mem_map_t, list);
    } while (curr != memory_map);

    return 0;
}

// executes the binary
void exec_binary(mdata_binary_t* s_binary) 
{
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
        "vzeroall\n"
        "push %%rax\n"
        "xor %%rax, %%rax\n"
        "ret\n"
        :: "r"(s_binary->dbi_handler->state->rip), "r"(s_binary->dbi_handler->state->rsp) :);
}
