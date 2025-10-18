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

extern int bbl_count;


// basic callback that is dumping the registers state at the start of a new basic block
int test(void* s_binary) 
{
    bbl_count++;
    
//    fprintf(((mdata_binary_t*)s_binary)->debug_stream, "> @bbl: %d, rip: %lx\n", bbl_count, ((mdata_binary_t*)s_binary)->dbi_handler->state->rip);
//    log_regs(s_binary, ((mdata_binary_t*)s_binary)->debug_stream);   
 
    return 0;
}

int main(int argc, char **argv) 
{
    if (argc < 2) {
        return -1;
    }

    mdata_binary_t *s_binary = NULL;
    arg_t arguments = {.argc = argc, .argv = argv};
    request_t req = {.callback = test, .address = 0, .type = INSTRUMENT_BBL};
    if (-1 == (long)(s_binary = map_binary(argv[1], &arguments))) {
        return -1;
    }

    req.address += (uint64_t)s_binary->base;
    s_binary->dbi_handler->request = &req;
    instrument(s_binary);
    return 0;
}
