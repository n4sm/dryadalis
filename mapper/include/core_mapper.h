#ifndef CORE_MAPPER_H_
#define CORE_MAPPER_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libelf.h>
#include <elf.h>

#include "elf_parsing.h"

mdata_binary_t *map_binary(const char *filename);
mdata_binary_t *load_interp(Elf64_Phdr* s_ph, mdata_binary_t* s_binary);
int map_load(Elf64_Phdr* s_ph, mdata_binary_t* s_binary);
void exec_binary(mdata_binary_t* s_binary, char **argv, int argc);


#endif