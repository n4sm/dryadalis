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

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include "../include/core_mapper.h"
#include "../include/elf_parsing.h"

// check if an instruction will change the control flow
_Bool is_cflow(cs_insn *insn) {
    return (insn->id & (X86_GRP_CALL | X86_GRP_INT | X86_GRP_JUMP | X86_GRP_RET)) != 0;
}

// returns how much byte there is up to the first cflow instruction, returns -1 if it fails
int opcodes_cflow(unsigned long addr, mdata_binary_t* s_binary) {
    int n = 0;
    csh handle;
	cs_insn *insn;
	size_t count;
    unsigned long page_offt = PAGE_OFFT(addr);
    unsigned long size;

    if (!is_mapped(addr, s_binary)) {
        return -1;
    }

    // We can handle cases where the instruction is overlapping between two pages
    if (is_mapped(PAGE_ALIGN(addr) + 0x1000, s_binary)) {
        size = PAGE_OFFT(~page_offt) + 0x1000;
    } else {
        size = PAGE_OFFT(~page_offt);
    }

    unsigned char* insn_buf = calloc(1, size);

    memcpy(insn_buf, (void* )addr, size);

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        return -1;
    }

    count = cs_disasm(handle, insn_buf, size, 0, 0, &insn);

    for (int i = 0 ; i < count ; i++ ) {
        n += insn[i].size;
        fprintf(stdout, "0x%"PRIx64":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic,
					insn[i].op_str);
        if (is_cflow(&(insn[i]))) {
            free(insn_buf);
            cs_free(insn, count);
            return n;
        }
    }

    if (is_mapped(PAGE_ALIGN(addr) + PAGE_SZ, s_binary)) {
        free(insn_buf);
        cs_free(insn, count);
        return opcodes_cflow(addr + n, s_binary);
    }

    return -1;
}