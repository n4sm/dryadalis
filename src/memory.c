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
#include <sys/ioctl.h>

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include <keystone/keystone.h>

#include "../include/dryadalis_x86.h"


int parse_maps(mdata_binary_t* s_binary)
{
    // request_t request = {}

    // uint64_t base, end = 0;
    // int prot = 0;
    // // char is_r, is_w, is_x, is_p, is_s = 0;
    // char is_r, is_w, is_x, is_p = 0;

    // fclose (s_binary->dbi_handler->fd_maps);
    // s_binary->dbi_handler->fd_maps = fopen("/proc/self/maps", "r");

    // while (fscanf(s_binary->dbi_handler->fd_maps, "%lx-%lx %c%c%c%c %*[^\n]\n", &base, &end, &is_r, &is_w, &is_x, &is_p) != EOF) {
    //     // is_s = is_p == 's';

    //     prot |= is_r == 'r' ? PROT_READ : 0;
    //     prot |= is_x == 'x' ? PROT_EXEC : 0;
    //     prot |= is_w == 'w' ? PROT_WRITE : 0;

    //     list_add_map(s_binary, prot, base, end - base);
    // }

    return 0;
}

/*
    get_prot: Get the protection of a memory region
    @s_binary: The binary to get the protection from
    @addr: The address to get the protection from
    Return: The protection of the memory region, -1 if not found
*/
int get_prot(mdata_binary_t* s_binary, uint64_t addr)
{
    umaps_request_t request = {.pid = getpid(), .addr = addr, .size = PAGE_SZ};

    if (-1 == ioctl(s_binary->dbi_handler->fd_umaps, UMAPS_GET_PROT, &request)) {
        fprintf(stderr, "> @getprot > @ioctl failed\n");
        return -1;
    }

    return request.result;
}

/*
    Safe wrapper for mprotect, the protections are only for the first page
    @s_binary: binary descriptor
    @addr: page we have to mprotect
    @size: size we would like to mprotect
    @_prot: protections we have to apply

    returns the memory descriptor if it fails, else -1
*/
int w_mem_protect(mdata_binary_t* s_binary, uint64_t addr, size_t size, int _prot) 
{

    if (!is_mapped_range(s_binary, addr, size)) {
        fprintf(stderr, "> @w_mem_protect: addr %lx / %lx + %lx not mapped\n", addr, addr, size);
        return -1;
    }

    if (-1 == mprotect((void*)addr, size, _prot)) {
        fprintf(stderr, "> @w_mem_protect: addr %lx / %lx + %lx failed\n", addr, addr, size);
        return -1;
    }

    return get_prot(s_binary, addr);
}

/*
    Safe wrapper for mprotect with READ protections
    @s_binary: binary descriptor
    @addr: page we have to mprotect
    @size: size we would like to mprotect

    returns -1 if it fails, else protections of the mapped page
*/
int make_readable(mdata_binary_t* s_binary, uint64_t address, ssize_t size) 
{
    return w_mem_protect(s_binary, address, size, PROT_READ);    
}

/*
    Safe wrapper for mprotect with PROT_READ | PROT_WRITE protections
    @s_binary: binary descriptor
    @addr: page we have to mprotect
    @size: size we would like to mprotect

    returns -1 if it fails, else prot of the mapped page
*/
int make_writable(mdata_binary_t* s_binary, uint64_t address, ssize_t size) 
{
    return w_mem_protect(s_binary, address, size, PROT_READ | PROT_WRITE);
}

/*
    Safe wrapper for mprotect with PROT_READ | PROT_EXEC protections
    @s_binary: binary descriptor
    @addr: page we have to mprotect
    @size: size we would like to mprotect

    returns -1 if it fails, else prot of the mapped page
*/
int make_executable(mdata_binary_t* s_binary, uint64_t address, ssize_t size) 
{
    return w_mem_protect(s_binary, address, size, PROT_READ | PROT_EXEC);
}

/*
    restore_vprot - Restore the virtual protections for one page
    @s_binary: binary object
    @size: how much we restore
    @_mem_desc: the page descriptor from where we want to restore

    returns -1 if it fails else protections of the mapped page
*/
int restore_vprot(mdata_binary_t* s_binary, size_t size, uint64_t addr, off_t offset) 
{
    // int prot = get_prot(s_binary, addr + offset);

    return 0;
}

/*
    mem_read - read @size bytes from @from to @to, if all the range is not mapped it reads all the mapped datas, returns the number of bytes readen
    @s_binary: object descriptor
    @to: buffer to get the bytes
    @from: pointer to which we read bytes
    @size: how many bytes we have to read
*/
int mem_read(mdata_binary_t* s_binary, void* to, uint64_t from, size_t size) 
{
    int prot = 0;
    int k = 0;
    // memset(to, 0x90, size);

    if (!is_mapped_range(s_binary, PAGE_ALIGN(from), size + PAGE_OFFT(from))) {
        fprintf(stderr, "> is_mapped_range > mem_read: %lx -> %lx\n", PAGE_ALIGN(from), size + PAGE_OFFT(from));
        return -1;
    }

    prot = get_prot(s_binary, from);

    if (prot == -1) {
        fprintf(stderr, "> @get_prot > @mem_read: %lx -> %lx\n", PAGE_ALIGN(from), size + PAGE_OFFT(from));
        return -1;
    }

    if (!(prot & PROT_READ)) {
        if (-1 == mprotect((void*)PAGE_ALIGN(from), PAGE_SZ, PROT_READ)) {
            fprintf(stderr, "> @mprotect > @mem_read: %lx\n", PAGE_ALIGN(from));
            return -1;
        }
    }

    memcpy(to, (void*)from, PAGE_SZ - PAGE_OFFT(from) <= size ? PAGE_SZ - PAGE_OFFT(from) : size);

    if (-1 == mprotect((void*)PAGE_ALIGN(from), PAGE_SZ, prot)) {
        fprintf(stderr, "> @mprotect > @mem_read: %lx\n", PAGE_ALIGN(from));
        return -1;
    }

    k = PAGE_SZ - PAGE_OFFT(from);

    while (k < size && k) {
        printf("> %lx, size: %lx\n", k, size);
        prot = get_prot(s_binary, from + k);

        if (prot == -1) {
            fprintf(stderr, "> @get_prot > @mem_read: %lx\n", PAGE_ALIGN((from + k)));
            return -1;
        }

        if (!(prot & PROT_READ)) {
            if (-1 == mprotect((void*)PAGE_ALIGN((from + k)), PAGE_SZ, PROT_READ)) {
                fprintf(stderr, "> @mprotect > @mem_read: %lx\n", PAGE_ALIGN((from + k)));
                return -1;
            }
        }

        memcpy((void*)to + k, (void*)from + k, PAGE_SZ - PAGE_OFFT((from + k)) <= size - k ? PAGE_SZ - PAGE_OFFT((from + k)) : size - k);

        if (-1 == mprotect((void*)PAGE_ALIGN((from + k)), PAGE_SZ, prot)) {
            fprintf(stderr, "> @mprotect > @mem_read: %lx\n", PAGE_ALIGN((from + k)));
            return -1;
        }

        k += k + PAGE_SZ > size ? size - k : PAGE_SZ;
    }

    return size;
}

/*
    mem_write - write @size bytes at @to from @from
    @s_binary: object descriptor
    @to: memory area to write
    @from: pointer from which we have to write
    @size: how many bytes we have to write
*/
int mem_write(mdata_binary_t* s_binary, uint64_t to, void* from, size_t size) 
{
    int prot = 0;
    int k = 0;

    if (!is_mapped_range(s_binary, PAGE_ALIGN(to), size + PAGE_OFFT(to))) {
        fprintf(stderr, "> is_mapped_range > mem_read: %lx -> %lx\n", PAGE_ALIGN(to), size + PAGE_OFFT(to));
        return -1;
    }

    prot = get_prot(s_binary, to);

    if (-1 == prot) {
        fprintf(stderr, "> @get_prot > @mem_read: %lx -> %lx\n", PAGE_ALIGN(to), size + PAGE_OFFT(to));
        return -1;
    }

    if (!(prot & PROT_WRITE)) {
        if (-1 == mprotect((void*)PAGE_ALIGN(to), PAGE_SZ, PROT_WRITE)) {
            fprintf(stderr, "> @mprotect > @mem_read: %lx\n", PAGE_ALIGN(to));
            return -1;
        }
    }

    memcpy((void*)to, (void*)from, PAGE_SZ - PAGE_OFFT(to) <= size ? PAGE_SZ - PAGE_OFFT(to) : size);

    if (-1 == mprotect((void*)PAGE_ALIGN(to), PAGE_SZ, prot)) {
        fprintf(stderr, "> @mprotect > @mem_read: %lx\n", PAGE_ALIGN(to));
        return -1;
    }

    k = PAGE_SZ - PAGE_OFFT(to);

    while (k < size && k) {
        printf("> write %lx, size: %lx\n", k, size);
        prot = get_prot(s_binary, to + k);

        if (prot == -1) {
            fprintf(stderr, "> @get_prot > @mem_read: %lx\n", PAGE_ALIGN((to + k)));
            return -1;
        }

        if (!(prot & PROT_READ)) {
            if (-1 == mprotect((void*)PAGE_ALIGN((to + k)), PAGE_SZ, PROT_READ)) {
                fprintf(stderr, "> @mprotect > @mem_read: %lx\n", PAGE_ALIGN((to + k)));
                return -1;
            }
        }

        memcpy((void*)to + k, (void*)from + k, PAGE_SZ - PAGE_OFFT((to + k)) <= size - k ? PAGE_SZ - PAGE_OFFT((to + k)) : size - k);

        if (-1 == mprotect((void*)PAGE_ALIGN((to + k)), PAGE_SZ, prot)) {
            fprintf(stderr, "> @mprotect > @mem_read: %lx\n", PAGE_ALIGN((to + k)));
            return -1;
        }

        k += k + PAGE_SZ > size ? size - k : PAGE_SZ;
    }

    return size;
}

/*
    map_page - maps a page @addr with @_prot
    @addr: location we'd like to map
    @_prot: protections
    @s_binary: object descriptor  
*/
int map_page(uintptr_t addr, int _prot, mdata_binary_t* s_binary) 
{
    if (MAP_FAILED == mmap((void* )PAGE_ALIGN(addr), PAGE_SZ, _prot, MAP_ANON | MAP_FIXED | MAP_PRIVATE, -1, 0x0)) {
        fprintf(stderr, "> map_page: addr: %lx\n", PAGE_ALIGN(addr));
        fatal_dump(s_binary);
    }

    // list_add_map(s_binary, _prot, PAGE_ALIGN(addr), PAGE_SZ);
    // parse_maps(s_binary);
    return 0;
}
