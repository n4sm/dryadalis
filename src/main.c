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
#include <immintrin.h>

#include "../include/dryadalis_x86.h"

int test(void* s_binary) 
{
    insn_count++;
    return 0;
}

int main(int argc, char **argv) 
{
    mdata_binary_t *s_binary = NULL;
    insn_count = 0;
    arg_t arguments = {.argc = argc, .argv = argv};
    request_t req = {.callback = test, .address = 0x0, .type = INSTRUMENT_BBL};
    // request_t req = {.callback = test, .address = 0x0, .type = INSTRUMENT_BBL};
    if (-1 == (long)(s_binary = map_binary(argv[1], &arguments))) {
        return -1;
    }

    req.address += (uint64_t)s_binary->base;
    s_binary->dbi_handler->request = &req;
    instrument(s_binary);
    return 0;
}