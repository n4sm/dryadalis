#ifndef ENGINE_H_
#define ENGINE_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libelf.h>
#include <elf.h>

#include "elf_parsing.h"
#include "kernel_list.h"
#include "core_mapper.h"

// returns how many byte there is up to the first cflow instruction
int opcodes_cflow(unsigned long addr, mdata_binary_t* s_binary);

#endif