#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libelf.h>
#include <elf.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include <capstone/capstone.h>
#include <capstone/x86.h>

#include "../include/dryadalis_x86.h"

/*
    Sanity check to ensure the binary we plan to analyse is an ELF binary
*/
_Bool is_elf(uint8_t *eh_ptr) 
{
    if ((uint8_t)eh_ptr[EI_MAG0] != 0x7F ||
        (uint8_t)eh_ptr[EI_MAG1] != 'E' ||
        (uint8_t)eh_ptr[EI_MAG2] != 'L' || 
        (uint8_t)eh_ptr[EI_MAG3] != 'F') {
        return false;
    }

    return true;
}

/*
    Returns the program header for the PT_DYNAMIC segment
    @buffer_mdata_ph: array of program header
    @eh_ptr: executable header
*/
Elf64_Phdr *search_pt_dyn(Elf64_Phdr **buffer_mdata_ph, Elf64_Ehdr *eh_ptr) 
{
    for (int i = 0; i < eh_ptr->e_phnum; ++i) {
        if (buffer_mdata_ph[i]->p_type == PT_DYNAMIC) {
            return buffer_mdata_ph[i];
        }
    }

    return 0;
}
/*
    Check if a binary is PIE based
    @buffer_mdata_ph: array of program header
    @eh_ptr: executable header
*/
_Bool is_pie(Elf64_Phdr **buffer_mdata_ph, Elf64_Ehdr *eh_ptr) 
{
    return eh_ptr->e_type == ET_DYN;
}

/*
    Returns the base address of a binary
    @buffer_mdata_phdr: array of program header
    @eh_ptr: executable header
*/
uint64_t search_base_addr(Elf64_Phdr **buffer_mdata_phdr, Elf64_Ehdr *eh_ptr) 
{
    uint64_t min = buffer_mdata_phdr[0]->p_vaddr;

    for (int i = 0; i < eh_ptr->e_phnum; ++i) {
        if (buffer_mdata_phdr[i]->p_type == PT_LOAD
             && buffer_mdata_phdr[i]->p_vaddr < min) {
            min = buffer_mdata_phdr[i]->p_vaddr;
        }
    }

	return min;
}

/*
    Loop over the PHT (program header table) from the metadatas provided by the executable header to get each program header
    @buffer_mdata_ph: buffer which will contain pointers to each program header
    @ptr: pointer to the executable header
*/
int parse_phdr(Elf64_Ehdr *ptr, Elf64_Phdr *buffer_mdata_ph[]) 
{
	Elf64_Ehdr *ptr_2 = (Elf64_Ehdr *)ptr;

	for (size_t i = 0; i < ptr->e_phnum; i++) {
		buffer_mdata_ph[i]  = (Elf64_Phdr *) ((char *)ptr + (ptr_2->e_phoff + ptr_2->e_phentsize * i));
	}

	return 0;
}

/*
    Loop over the SHT (section header table) from the metadatas provided by the executable header to get each section header
    @buffer_mdata_sh: buffer which will contain pointers to each section header
    @ptr: pointer to the executable header
*/
int parse_shdr(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[]) 
{
	Elf64_Ehdr *ptr_2 = (Elf64_Ehdr *)ptr;

	for (size_t i = 0; i < ptr->e_shnum; i++) {
		buffer_mdata_sh[i]  = (Elf64_Shdr *) ((char *)ptr + (ptr_2->e_shoff + ptr_2->e_shentsize * i));
	}

	return 0;
}

/*
    Initialize the @sh_name_buffer array of pointer
    @buffer_mdata_sh: buffer which will contain pointers to each section header
    @buffer_mdata_ph: buffer which will contain pointers to each program header
    @sh_name: buffer to contain pointers to each section name
    @ptr: pointer to the executable header
*/
char **parse_sh_name(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[], char **sh_name_buffer) 
{
	Elf64_Shdr *shstrtab_header = (Elf64_Shdr *) ((char *)ptr + (ptr->e_shoff + ptr->e_shentsize * ptr->e_shstrndx));
	const char *shstrndx = (const char *)ptr + shstrtab_header->sh_offset;

	for (size_t i = 0; i < ptr->e_shnum; i++) {
		sh_name_buffer[i] = (char *)shstrndx + buffer_mdata_sh[i]->sh_name;
	}

	return sh_name_buffer;
}

/*
    Initialize some array of pointers if the array exists
    @buffer_mdata_sh: buffer to contain pointers to each section header
    @buffer_mdata_ph: buffer to contain pointers to each program header
    @sh_name: buffer to contain pointers to each section name
    @ptr: pointer to the executable header
*/
int init_struct(Elf64_Shdr *buffer_mdata_sh[], Elf64_Phdr *buffer_mdata_ph[], char **sh_name, Elf64_Ehdr *ptr) 
{
    if (buffer_mdata_ph && parse_phdr(ptr, buffer_mdata_ph)) {
        return -1;
    } else if (buffer_mdata_sh && parse_shdr(ptr, buffer_mdata_sh)) {
        return -1;
    } else if (sh_name && buffer_mdata_sh && !parse_sh_name(ptr, buffer_mdata_sh, sh_name)) {
        return -1;
    }

    return 0;
}

/*
    Allocate the mdata_binary_t structure
*/
mdata_binary_t* alloc_binary() 
{
    return (mdata_binary_t *)calloc(1, sizeof(mdata_binary_t));
}

/*
    Allocate an array of pointers to the program header
    @nr_phdr: number of program header
*/
Elf64_Phdr** alloc_ph(int nr_phdr) 
{
    return (Elf64_Phdr **)calloc(sizeof(Elf64_Phdr *), nr_phdr);
}

/*
    Analyses from an input path binary
    @s: pointer to the binary's path
*/
mdata_binary_t* init_analysis(const char *s) 
{
    struct stat st;

    __builtin_cpu_init();
    mdata_binary_t *s_binary = alloc_binary();

    if ((s_binary->fd = open(s, O_RDONLY)) == -1) {
        fprintf(stderr, "[ERROR] Open: %s: \n", s);
        return (mdata_binary_t* )-1;
    }

    if (fstat(s_binary->fd, &st)) {
        fprintf(stderr, "[ERROR] fstat has failed\n");
        return (mdata_binary_t* )-1;
    }

    s_binary->len_file = st.st_size;
    s_binary->fbinary = (uint8_t* )malloc(s_binary->len_file);
    read(s_binary->fd, s_binary->fbinary, s_binary->len_file);

    s_binary->dbi_handler = (dbi_instr_t* )calloc(1, sizeof(dbi_instr_t));

    s_binary->dbi_handler->state = (state_rtime_t* )calloc(1, sizeof(state_rtime_t));

    // useless init
    s_binary->dbi_handler->state->avx2 = NULL;
    s_binary->dbi_handler->state->avx512 = NULL;
    s_binary->dbi_handler->state->sse = NULL;
    if (__builtin_cpu_supports("sse") && !__builtin_cpu_supports("avx2")) {
        s_binary->dbi_handler->state->sse = (sse_t* )_mm_malloc(sizeof(sse_t), 128);
    } else if (__builtin_cpu_supports("avx2") && !__builtin_cpu_supports("avx512f")) {
        s_binary->dbi_handler->state->avx2 = (avx2_t* )_mm_malloc(sizeof(avx2_t), 256);
        memset(s_binary->dbi_handler->state->avx2, 0x0, sizeof(avx2_t));
    } else if (__builtin_cpu_supports("avx512f")) {
        s_binary->dbi_handler->state->avx512 = (avx512_t* )_mm_malloc(sizeof(avx512_t), 512);
    }

    s_binary->dbi_handler->host_state = (state_rtime_t* )calloc(1, sizeof(state_rtime_t));
    s_binary->dbi_handler->hashmap = (hashmap_t* )calloc(1, sizeof(hashmap_t));
    s_binary->dbi_handler->hashmap = init_hashmap(s_binary->dbi_handler->hashmap, s_binary);

    s_binary->filename = s;
    s_binary->eh = (Elf64_Ehdr* )s_binary->fbinary;
    s_binary->s_ph = alloc_ph(s_binary->eh->e_phnum);
    s_binary->interp = NULL; //useless
    s_binary->base = NULL; // because it's allocated with the use of calloc of
    s_binary->memory_map = NULL;
    s_binary->dbi_handler->host_rsp = NULL;

    s_binary->dbi_handler->dump = (hook_t* )calloc(1, sizeof(hook_t));
    s_binary->dbi_handler->dump->orig_bytes = (uint8_t* )calloc(1, 64);
    s_binary->dbi_handler->dump->length = 0x0;
    s_binary->dbi_handler->dump->code = NULL;
    s_binary->dbi_handler->dump->jmp = 0x0;
    s_binary->dbi_handler->dump->to_unmap = 0x0;
    s_binary->dbi_handler->dump->prot_restore = 0x0;

    s_binary->dbi_handler->restore = (hook_t* )calloc(1, sizeof(hook_t));
    s_binary->dbi_handler->restore->orig_bytes = (uint8_t* )calloc(1, 64);
    s_binary->dbi_handler->restore->length = 0x0;
    s_binary->dbi_handler->restore->code = NULL;
    s_binary->dbi_handler->restore->jmp = 0x0;
    s_binary->dbi_handler->restore->to_unmap = 0x0;
    s_binary->dbi_handler->restore->prot_restore = 0x0;

    s_binary->dispatcher = 0x0;
    s_binary->dbi_handler->u_handler = NULL;
    s_binary->dbi_handler->curr_hook = NULL;
    s_binary->dbi_handler->state->null_entry = 0x0; // useless

    s_binary->dbi_handler->instrumented_fs = 0;
    s_binary->dbi_handler->instrumented_gs = 0;
    s_binary->dbi_handler->dtor = default_dtor;
    s_binary->dbi_handler->length_cflow = 0x0;

    s_binary->dbi_handler->persistent_hook = (persistent_t* )calloc(1, sizeof(persistent_t));

    s_binary->exec_entry = 0x0;
    s_binary->debug_stream = stdout;

    s_binary->dbi_handler->cps_utils = (capstone_hanlder_t* )calloc(1, sizeof(capstone_hanlder_t));
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &s_binary->dbi_handler->cps_utils->handle) != CS_ERR_OK) {
        fprintf(stderr, "@init_analysis > @cs_open\n");
        fatal_dump(s_binary);
    }

    cs_option(s_binary->dbi_handler->cps_utils->handle, CS_OPT_DETAIL, CS_OPT_ON);
    s_binary->dbi_handler->cps_utils->insn = cs_malloc(s_binary->dbi_handler->cps_utils->handle);
    s_binary->dbi_handler->cps_utils->instructions = NULL;

    s_binary->dbi_handler->fd_umaps = open("/dev/umaps", O_RDONLY);

    if (!s_binary->dbi_handler->cps_utils->insn) {
        fprintf(stderr, "> @init_analysis > @cs_malloc\n");
        return (mdata_binary_t* )-1;
    }

    if (false == is_elf(s_binary->fbinary)) {
        fprintf(stderr, "Not a valid elf file\n");
        return (mdata_binary_t* )-1;
    }

    if (-1 == init_struct(NULL, s_binary->s_ph, NULL, (Elf64_Ehdr *)s_binary->fbinary)) {
        fprintf(stderr, "Error init_struct\n");
        return (mdata_binary_t* )-1;        
    }


    if (is_pie(s_binary->s_ph, (Elf64_Ehdr *)s_binary->fbinary)) {
        s_binary->pie = true;
    }

    return s_binary;
}

/*
    Actual destructor for the mdata_binary_t object
*/
int end_analysis(mdata_binary_t *s_binary) 
{
    if (s_binary->dbi_handler->state) {
        if (s_binary->dbi_handler->state->sse) {
            _mm_free(s_binary->dbi_handler->state->sse);
        }

        if (s_binary->dbi_handler->state->avx2) {
            _mm_free(s_binary->dbi_handler->state->avx2);
        }

        if (s_binary->dbi_handler->state->avx512) {
            _mm_free(s_binary->dbi_handler->state->avx512);
        }
        
        free(s_binary->dbi_handler->state);
    }

    if (s_binary->dbi_handler->dump->code) {
        free(s_binary->dbi_handler->dump->code);
    }

    if (s_binary->dbi_handler->restore->code) {
        free(s_binary->dbi_handler->restore->code);
    }

    if (-1 == munmap(s_binary->dbi_handler->restore_stub, LENGTH_STUB)) {
        return -1;
    }

    if (-1 == munmap(s_binary->dbi_handler->dump_stub, LENGTH_STUB)) {
        return -1;
    }

    if (-1 == munmap(s_binary->dbi_handler->host_rsp, 0x10000)) {
        return -1;
    }

    // int fd = open("/proc/self/maps", O_RDONLY);
    // struct stat stat_maps = {0};

    // if (fstat(fd, &stat_maps)) {
    //     fprintf(stderr, "> @fstat has failed\n");
    //     return -1;
    // }

    // if (-1 == munmap(s_binary->dbi_handler->maps, stat_maps.st_size)) {
    //     return -1;
    // }

    free(s_binary->dbi_handler->host_state);
    free(s_binary->dbi_handler->dump);
    free(s_binary->dbi_handler->restore);
    free(s_binary->dbi_handler->curr_hook);
    free(s_binary->dbi_handler->hashmap);
    cs_free(s_binary->dbi_handler->cps_utils->insn, s_binary->dbi_handler->cps_utils->count);
    free(s_binary->dbi_handler->cps_utils);
    free(s_binary->dbi_handler);
    free(s_binary->fbinary);
    free(s_binary->s_ph);
    close(s_binary->fd);
    free_memory_map(s_binary->memory_map);

    if (s_binary->interp) end_analysis(s_binary->interp);
    free(s_binary);

    return 0;
}

/* 
    Add an auxilary vector to the zeroed @base_auxvt memory area
    @id: id field for the auxilary vector
    @base_auxvt: base address for the auxilary vector entries
    @val: value we want to write according to @id at the end of the auxvt array
*/
int add_auxvt(uint64_t id, uint64_t *base_auxvt, uint64_t val) 
{
    int i_target = 0;

    for ( ; base_auxvt[i_target] || base_auxvt[i_target+1]; i_target++);

    base_auxvt[i_target] = id;
    base_auxvt[i_target+1] = val;
    return 0;
}