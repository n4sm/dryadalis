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

int insn_count;

int test(void* s_binary) {
    // unsigned xmm0 = *(unsigned long* )(&(((mdata_binary_t* )s_binary)->dbi_handler->state->sse->xmm0));
    // fprintf(stdout, "xmm0: %lx, ", (xmm0));
    insn_count += 1;
    // fprintf(stdout, "bbl_count: 0x%x\n", insn_count);

    // log_avx2(((mdata_binary_t* )s_binary)->dbi_handler->state);
    // log_regs(s_binary);
    fprintf(stdout, "test\n");
    return 0;
}

int main(int argc, char **argv) {
    mdata_binary_t *s_binary = NULL;
    insn_count = 0;
    arg_t arguments = {.argc = argc, .argv = argv};
    // request_t req = {.callback = test, .address = 0x3370, .type = INSTRUMENT_ADDR_ONLY};
    request_t req = {.callback = test, .address = 0x0, .type = INSTRUMENT_BBL};
    if (-1 == (long)(s_binary = map_binary(argv[1], &arguments)))
        return -1;

    merge_address_space(s_binary);
    log_map(s_binary->memory_map);
    req.address += (uint64_t)s_binary->base;
    s_binary->dbi_handler->request = &req;
    instrument(s_binary);
    return 0;
}