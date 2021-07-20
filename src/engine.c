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
#include <capstone/capstone.h>

#include "../include/core_mapper.h"
#include "../include/elf_parsing.h"

// returns how much byte there is up to the first cflow instruction, returns -1 if it fails
int opcodes_cflow(unsigned long addr) {
    int n;
    csh handle;
	cs_insn *insn;
	size_t count;
    unsigned long page_offt = PAGE_OFFT(addr);

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return -1;
    }
		


    return n;
}