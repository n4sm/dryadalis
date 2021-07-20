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

#include "../include/core_mapper.h"
#include "../include/elf_parsing.h"

int main(int argc, char **argv) {
    mdata_binary_t *s_binary = NULL;
    if (-1 == (long)(s_binary = map_binary(argv[1])))
        return -1;

    log_map(s_binary->memory_map);
    merge_address_space(s_binary);
    fprintf(stdout, "\n");
    log_map(s_binary->memory_map);
    exec_binary(s_binary, argv, argc);
    return 0;
}