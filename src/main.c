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

#include "../include/dryadalis_x86.h"

int insn_count;

int test(void* s_binary) {
    unsigned long rip = ((mdata_binary_t* )s_binary)->dbi_handler->state->rip;
    fprintf(stdout, "rip: %lx, ", rip);
    // insn_count += 1;
    //fprintf(stdout, "insn_count: %x\n", insn_count);
    return 0;
}

int main(int argc, char **argv) {
    mdata_binary_t *s_binary = NULL;
    insn_count = 0;
    arg_t arguments = {.argc = argc, .argv = argv};
    if (-1 == (long)(s_binary = map_binary(argv[1], &arguments)))
        return -1;

    merge_address_space(s_binary);
    log_map(s_binary->memory_map);
    instrument(s_binary, test);
    return 0;
}