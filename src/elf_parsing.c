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

#include "../include/elf_parsing.h"
#include "../include/core_mapper.h"

// is elf ?
_Bool is_elf(unsigned char *eh_ptr) {
    if ((unsigned char)eh_ptr[EI_MAG0] != 0x7F ||
        (unsigned char)eh_ptr[EI_MAG1] != 'E' ||
        (unsigned char)eh_ptr[EI_MAG2] != 'L' || 
        (unsigned char)eh_ptr[EI_MAG3] != 'F') {
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
    unsigned long min = buffer_mdata_phdr[0]->p_vaddr;

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

    s_binary->filename = s;
    s_binary->eh = (Elf64_Ehdr* )s_binary->fbinary;
    s_binary->s_ph = alloc_ph(s_binary->eh->e_phnum);
    s_binary->interp = NULL; //useless
    s_binary->base = NULL; // because it's allocated with the use of calloc of
    s_binary->memory_map = NULL;
    s_binary->state = NULL;
    s_binary->host_rsp = NULL;
    s_binary->orig_bytes = NULL;
    s_binary->dispatcher = 0x0;
    s_binary->u_handler = NULL;
    s_binary->curr_hook = 0x0;
    s_binary->length_trampoline = 0;

    s_binary->state = malloc(sizeof(state_rtime_t));
    s_binary->orig_bytes = calloc(1, 64); // arbitrary length

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
    if (s_binary->state) {
        free(s_binary->state);
    }

    if (s_binary->orig_bytes) {
        free(s_binary->orig_bytes);
    }

    free(s_binary->fbinary);
    free(s_binary->s_ph);
    close(s_binary->fd);
    free_binary(s_binary);
    free_memory_map(s_binary->memory_map);
    return 0;
}

// *=*=*=*=*=*=*=*=s--

// add_auxvt adds a auxilary vector to the zeroed @base_auxvt memory area
int add_auxvt(unsigned long id, unsigned long* origin, unsigned long *base_auxvt, unsigned long val) {
    int i_target = 0;

    for ( ; base_auxvt[i_target] || base_auxvt[i_target+1]; i_target++);

    base_auxvt[i_target] = id;
    base_auxvt[i_target+1] = val;
    return 0;
}