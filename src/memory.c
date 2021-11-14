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

/*
    Safe wrapper for mprotect, updates the sync field to false because that are internal operations, not guest mprotect
    @s_binary: binary descriptor
    @addr: page we have to mprotect
    @size: size we would like to mprotect
    @_prot: protections we have to apply

    returns the memory descriptor if it fails, else -1
*/
mem_map_t* w_mem_protect(mdata_binary_t* s_binary, uint64_t addr, size_t size, int _prot) {
    mem_map_t* _mem_desc = get_mem_desc(s_binary, addr);
    mem_map_t* mem_desc_return = _mem_desc;

    if (-1 == (long)_mem_desc) {
        fprintf(stderr, "> @w_mem_protect > @get_mem_desc: failed to get the memory descriptor for %lx\n", addr);
        return (mem_map_t* )-1;
    }

    size_t i = 0;
    do {
        if (i) {
            _mem_desc = container_of(_mem_desc->list.next, mem_map_t, list);
        }

        if (mprotect((void* )PAGE_ALIGN(addr) + i*512, PAGE_SZ, _prot)) {
            fprintf(stderr, "> @w_mem_protect: failed to mprotect, addr: %lx, size: %x, prot: %x\n", PAGE_ALIGN(addr) + i*512, PAGE_SZ, _prot);
            return (mem_map_t* )-1;
        }

        _mem_desc->sync = false;
        i += 8;
    } while ( i*512 < PAGE_ROUND((size + (PAGE_OFFT(addr)))) + 1 \
              && _mem_desc->addr + _mem_desc->size == (container_of(_mem_desc->list.next, mem_map_t, list))->addr);
    // we check if the next page descriptor is contiguous to the current page descriptor

    return mem_desc_return;
}

/*
    Safe wrapper for mprotect with READ protections
    @s_binary: binary descriptor
    @addr: page we have to mprotect
    @size: size we would like to mprotect

    returns -1 if it fails, else 0
*/
mem_map_t* make_readable(mdata_binary_t* s_binary, uint64_t address, ssize_t size) {
    return w_mem_protect(s_binary, address, size, PROT_READ);    
}

/*
    Safe wrapper for mprotect with PROT_READ | PROT_WRITE protections
    @s_binary: binary descriptor
    @addr: page we have to mprotect
    @size: size we would like to mprotect

    returns -1 if it fails, else 0
*/
mem_map_t* make_writable(mdata_binary_t* s_binary, uint64_t address, ssize_t size) {
    return w_mem_protect(s_binary, address, size, PROT_READ | PROT_WRITE);
}

/*
    Safe wrapper for mprotect with PROT_READ | PROT_EXEC protections
    @s_binary: binary descriptor
    @addr: page we have to mprotect
    @size: size we would like to mprotect

    returns -1 if it fails, else 0
*/
mem_map_t* make_executable(mdata_binary_t* s_binary, uint64_t address, ssize_t size) {
    return w_mem_protect(s_binary, address, size, PROT_READ | PROT_EXEC);
}

/*
    restore_vprot - Restore the virtual protections for one or more pages
    @s_binary: binary object
    @size: how much we restore
    @_mem_desc: the page descriptor from where we want to restore

    returns -1 if it fails else 0
*/
int restore_vprot(mdata_binary_t* s_binary, size_t size, mem_map_t* _mem_desc, off_t offset) {
    size_t i = 0;

    do {
        if (i) {
            _mem_desc = container_of(_mem_desc->list.next, mem_map_t, list);
        }

        if (mprotect((void* )PAGE_ALIGN(_mem_desc->addr), PAGE_SZ, _mem_desc->prot)) {
            fprintf(stderr, "> @restore_vprot: failed to mprotect, addr: %lx, size: %x, prot: %x\n", PAGE_ALIGN(_mem_desc->addr), PAGE_SZ, _mem_desc->prot);
            return -1;
        }

        _mem_desc->sync = true;
        i += 8;
    } while ( i*512 < PAGE_ROUND((size + offset)) + 1 \
              && (_mem_desc->addr + _mem_desc->size) == (container_of(_mem_desc->list.next, mem_map_t, list))->addr \
              && !(container_of(_mem_desc->list.next, mem_map_t, list))->sync);
    // we check if the next page descriptor is contiguous to the current page descriptor

    return 0;
}

/*
    mem_read - read @size bytes from @from to @to, if all the range is not mapped it reads all the mapped datas
    @s_binary: object descriptor
    @to: buffer to get the bytes
    @from: pointer to which we read bytes
    @size: how many bytes we have to read
*/
int mem_read(mdata_binary_t* s_binary, void* to, uint64_t from, size_t size) {
    mem_map_t* _mem_desc = NULL;

	if (!is_mapped_range(s_binary, from, size) && is_mapped_range(s_binary, PAGE_ALIGN(from), size)) {
        size = PAGE_OFFT(size) ? size - PAGE_OFFT(size) : size - (PAGE_SZ - PAGE_OFFT(from));
	}

    if (-1 == (long)(_mem_desc = make_readable(s_binary, from, size))) {
    	fprintf(stderr, "> @mem_read > @make_readable, from: %lx, size: %lx\n", from, size);
	    fatal_dump(s_binary);
    }

    memcpy(to, (void* )from, size);

    if (-1 == restore_vprot(s_binary, size, _mem_desc, PAGE_OFFT(from))) {
		fprintf(stderr, "> @mem_read > @restore_vprot, from: %lx, size: %lx, prot: %x\n", from, size, _mem_desc->prot);
		fatal_dump(s_binary);
	}	

    return 0;
}

/*
    mem_write - write @size bytes at @to from @from
    @s_binary: object descriptor
    @to: memory area to write
    @from: pointer from which we have to write
    @size: how many bytes we have to write
*/
int mem_write(mdata_binary_t* s_binary, uint64_t to, void* from, size_t size) {
    mem_map_t* _mem_desc = NULL;
    
	if (!is_mapped(PAGE_ALIGN(to), s_binary)) {
        fprintf(stderr, "> @mem_write > @is_mapped, from: %lx, size: %lx\n", to, size);
        fatal_dump(s_binary);
	}

    if (-1 == (long)(_mem_desc = make_writable(s_binary, to, size))) {
   		fprintf(stderr, "> @mem_write > @make_readable, from: %lx, size: %lx, prot: %x\n", (uint64_t)from, size, _mem_desc->prot);
		fatal_dump(s_binary);
	}

    memcpy((void* )to, from, size);

    if (-1 == restore_vprot(s_binary, size, _mem_desc, PAGE_OFFT(to))) {
        fprintf(stderr, "> @mem_write > @restore_vprot, from: %lx, size: %lx, prot: %x\n", (uint64_t)from, size, _mem_desc->prot);
        fatal_dump(s_binary);
	};

	return 0;
}
