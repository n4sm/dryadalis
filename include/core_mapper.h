#ifndef CORE_MAPPER_H_
#define CORE_MAPPER_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libelf.h>
#include <elf.h>

#include "elf_parsing.h"
#include "kernel_list.h"

// functions

mdata_binary_t *map_binary(const char *filename);
mdata_binary_t *load_interp(Elf64_Phdr* s_ph, mdata_binary_t* s_binary);
int map_load(Elf64_Phdr* s_ph, mdata_binary_t* s_binary);
void exec_binary(mdata_binary_t* s_binary, char **argv, int argc);
int list_add_map(mdata_binary_t* s_binary, int prot, unsigned long addr, ssize_t size);
int free_memory_map(mem_map_t* memory_map);
int log_map(mem_map_t* memory_map);
mem_map_t* merge_address_space(mdata_binary_t* s_binary);

#endif