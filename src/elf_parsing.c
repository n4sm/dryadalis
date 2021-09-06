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

#include "../include/dryadalis_x86.h"

// is elf ?
_Bool is_elf(uint8_t *eh_ptr) {
    if ((uint8_t)eh_ptr[EI_MAG0] != 0x7F ||
        (uint8_t)eh_ptr[EI_MAG1] != 'E' ||
        (uint8_t)eh_ptr[EI_MAG2] != 'L' || 
        (uint8_t)eh_ptr[EI_MAG3] != 'F') {
        return false;
    }

    return true;
}

// *=*=*=*=*=*=

Elf64_Phdr *search_pt_dyn(Elf64_Phdr **buffer_mdata_ph, Elf64_Ehdr *eh_ptr) {
    for (int i = 0; i < eh_ptr->e_phnum; ++i) {
        if (buffer_mdata_ph[i]->p_type == PT_DYNAMIC) {
            return buffer_mdata_ph[i];
        }
    }

    return 0;
}

// *=*=*=*=*=*=

_Bool is_pie(Elf64_Phdr **buffer_mdata_ph, Elf64_Ehdr *eh_ptr) {
    return eh_ptr->e_type == ET_DYN;
}

// *=*=*=*=*=*=

uint64_t search_base_addr(Elf64_Phdr *buffer_mdata_phdr[], Elf64_Ehdr *eh_ptr) {
    uint64_t min = buffer_mdata_phdr[0]->p_vaddr;

    for (int i = 0; i < eh_ptr->e_phnum; ++i) {
        if (buffer_mdata_phdr[i]->p_type == PT_LOAD
             && buffer_mdata_phdr[i]->p_vaddr < min) {
            min = buffer_mdata_phdr[i]->p_vaddr;
        }
    }

	return min;
}

// *=*=*=*=*=*=

int parse_phdr(Elf64_Ehdr *ptr, Elf64_Phdr *buffer_mdata_ph[]) {
	Elf64_Ehdr *ptr_2 = (Elf64_Ehdr *)ptr;

	for (size_t i = 0; i < ptr->e_phnum; i++) {
		buffer_mdata_ph[i]  = (Elf64_Phdr *) ((char *)ptr + (ptr_2->e_phoff + ptr_2->e_phentsize * i));
	}

	return 0;
}

// *=*=*=*=*=*=

int parse_shdr(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[]) {
	Elf64_Ehdr *ptr_2 = (Elf64_Ehdr *)ptr;

	for (size_t i = 0; i < ptr->e_shnum; i++) {
		buffer_mdata_sh[i]  = (Elf64_Shdr *) ((char *)ptr + (ptr_2->e_shoff + ptr_2->e_shentsize * i));
	}

	return 0;
}

// *=*=*=*=*=*=

// unused for now
char **parse_sh_name(Elf64_Ehdr *ptr, Elf64_Shdr *buffer_mdata_sh[], char *sh_name_buffer[ptr->e_shnum]) {
	Elf64_Shdr *shstrtab_header = (Elf64_Shdr *) ((char *)ptr + (ptr->e_shoff + ptr->e_shentsize * ptr->e_shstrndx));
	const char *shstrndx = (const char *)ptr + shstrtab_header->sh_offset;

	for (size_t i = 0; i < ptr->e_shnum; i++) {
		sh_name_buffer[i] = (char *)shstrndx + buffer_mdata_sh[i]->sh_name;
	}

	return sh_name_buffer;
}

// *=*=*=*=*=*=

// initializes the structures (executable header, section header table, program header table etc)
int init_struct(Elf64_Shdr *buffer_mdata_sh[], Elf64_Phdr *buffer_mdata_ph[], char **sh_name, Elf64_Ehdr *ptr) {
    if (buffer_mdata_ph && parse_phdr(ptr, buffer_mdata_ph))
        return -1;
    if (buffer_mdata_sh && parse_shdr(ptr, buffer_mdata_sh))
        return -1;
    if (sh_name && buffer_mdata_sh && !parse_sh_name(ptr, buffer_mdata_sh, sh_name))
        return -1;

    return 0;
}

// *=*=*=*=*=*=

mdata_binary_t* alloc_binary() {
    return (mdata_binary_t *)calloc(1, sizeof(mdata_binary_t));
}

Elf64_Phdr** alloc_ph(int nr_phdr) {
    return (Elf64_Phdr **)calloc(sizeof(Elf64_Phdr *), nr_phdr);
}

int free_binary(mdata_binary_t *bi) {
    free(bi->s_ph);
    free(bi->interp);
    free(bi);
    return 0;
}

// *=*=*=*=*=*=

// basic analysis routine
mdata_binary_t* init_analysis(const char *s) {
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
    s_binary->fbinary = malloc(s_binary->len_file);
    read(s_binary->fd, s_binary->fbinary, s_binary->len_file);

    s_binary->dbi_handler = calloc(1, sizeof(dbi_instr_t));

    s_binary->dbi_handler->state = calloc(1, sizeof(state_rtime_t));

    // useless init
    s_binary->dbi_handler->state->avx2 = NULL;
    s_binary->dbi_handler->state->avx512 = NULL;
    s_binary->dbi_handler->state->sse = NULL;
    if (__builtin_cpu_supports("sse") && !__builtin_cpu_supports("avx2")) {
        s_binary->dbi_handler->state->sse = _mm_malloc(sizeof(sse_t), 128);
    } else if (__builtin_cpu_supports("avx2") && !__builtin_cpu_supports("avx512f")) {
        s_binary->dbi_handler->state->avx2 = _mm_malloc(sizeof(avx2_t), 256);
        memset(s_binary->dbi_handler->state->avx2, 0x0, sizeof(avx2_t));
    } else if (__builtin_cpu_supports("avx512f")) {
        s_binary->dbi_handler->state->avx512 = _mm_malloc(sizeof(avx512_t), 512);
    }

    s_binary->dbi_handler->host_state = calloc(1, sizeof(state_rtime_t));
    s_binary->dbi_handler->hashmap = calloc(1, sizeof(hashmap_t));
    s_binary->dbi_handler->hashmap = init_hashmap(s_binary->dbi_handler->hashmap, s_binary);

    s_binary->filename = s;
    s_binary->eh = (Elf64_Ehdr* )s_binary->fbinary;
    s_binary->s_ph = alloc_ph(s_binary->eh->e_phnum);
    s_binary->interp = NULL; //useless
    s_binary->base = NULL; // because it's allocated with the use of calloc of
    s_binary->memory_map = NULL;
    s_binary->dbi_handler->host_rsp = NULL;

    s_binary->dbi_handler->dump = calloc(1, sizeof(hook_t));
    s_binary->dbi_handler->dump->orig_bytes = calloc(1, 64);
    s_binary->dbi_handler->dump->length = 0x0;
    s_binary->dbi_handler->dump->code = NULL;
    s_binary->dbi_handler->dump->jmp = 0x0;
    s_binary->dbi_handler->dump->to_unmap = 0x0;

    s_binary->dbi_handler->restore = calloc(1, sizeof(hook_t));
    s_binary->dbi_handler->restore->orig_bytes = calloc(1, 64);
    s_binary->dbi_handler->restore->length = 0x0;
    s_binary->dbi_handler->restore->code = NULL;
    s_binary->dbi_handler->restore->jmp = 0x0;
    s_binary->dbi_handler->restore->to_unmap = 0x0;

    s_binary->dispatcher = 0x0;
    s_binary->dbi_handler->u_handler = NULL;
    s_binary->dbi_handler->curr_hook = NULL;
    s_binary->dbi_handler->state->null_entry = 0x0; // useless

    s_binary->dbi_handler->instrumented_fs = 0;
    s_binary->dbi_handler->instrumented_gs = 0;
    s_binary->dbi_handler->dtor = default_dtor;
    s_binary->dbi_handler->length_cflow = 0x0;

    s_binary->dbi_handler->persistent_hook = calloc(1, sizeof(persistent_t));

    s_binary->exec_entry = 0x0;

    if (false == is_elf(s_binary->fbinary)) {
        fprintf(stderr, "Not a valid elf file\n");
        return (mdata_binary_t* )-1;
    }

    if (-1 == init_struct(NULL, s_binary->s_ph, NULL, (Elf64_Ehdr *)s_binary->fbinary)) {
        fprintf(stderr, "Error init_struct\n");
        return (mdata_binary_t* )-1;        
    }


    if (is_pie(s_binary->s_ph, (Elf64_Ehdr *)s_binary->fbinary))
        s_binary->pie = true;

    return s_binary;
}

int end_analysis(mdata_binary_t *s_binary) {
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

    free(s_binary->dbi_handler->host_state);
    free(s_binary->dbi_handler->dump);
    free(s_binary->dbi_handler->restore);
    free(s_binary->dbi_handler->curr_hook);
    free(s_binary->dbi_handler->hashmap);
    free(s_binary->dbi_handler);
    free(s_binary->fbinary);
    free(s_binary->s_ph);
    close(s_binary->fd);
    free_binary(s_binary);
    free_memory_map(s_binary->memory_map);
    return 0;
}

// *=*=*=*=*=*=*=*=s--

// add_auxvt adds a auxilary vector to the zeroed @base_auxvt memory area
int add_auxvt(uint64_t id, uint64_t* origin, uint64_t *base_auxvt, uint64_t val) {
    int i_target = 0;

    for ( ; base_auxvt[i_target] || base_auxvt[i_target+1]; i_target++);

    base_auxvt[i_target] = id;
    base_auxvt[i_target+1] = val;
    return 0;
}