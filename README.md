Long time ago I started to write this DBI engine based on capstone and keystone. Currently it supports:
- AVX / AVX2
- statically linked binaries

For some reasons it is failing on recent dynamically linked binaries.

# Basic usage

The basic instrument engine is simply mappig the target binary in its own address space before submitting an instrument request to the engine and registering a callback called after basic block is executed:
```c
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
```

To compile it: `make`, to run it:
```
nasm@off:~$ sudo docker run -it nasmre/dryadalis:0.1 /bin/bash
[sudo] password for nasm: 
root@9ac8ce52bcc5:/# cd
root@9ac8ce52bcc5:~# cd dryadalis/
root@9ac8ce52bcc5:~/dryadalis# make
gcc -march=native -fPIE -pie src/*.c -g  -lcapstone -lkeystone -lm -lstdc++ -o main
root@9ac8ce52bcc5:~/dryadalis# ./main test/dbi_     
dbi_c_avx.c              dbi_c_avx_musl           dbi_c_avx_musl.stripped  dbi_test                 dbi_test.o               
root@9ac8ce52bcc5:~/dryadalis# ./main test/dbi_c_avx_musl
[+] Loading test/dbi_c_avx_musl
[>] 400000 - 401000 1000
[>] 401000 - 406000 5000
[>] 406000 - 407000 1000
[>] 407000 - 409000 2000
[>] s_binary->dbi_handler->vbrk: 409000
[+] test/dbi_c_avx_musl mapped
[ . ] arch_prctl (ARCH_SET_FS, 408658) = 0
[ . ] set_tid_address (408790) = 34
[ . ] ioctl (1, 5413, 7c5f98e18f10) = 0
11.000000 22.000000 33.000000 44.000000 55.000000 66.000000 77.000000 88.000000 
[ . ] writev (1, 7c5f98e18ea0, 2)
[ . ] exit_grp (0)
End of the program ! bbl count: 9bf
```

You can modify the level of verbosity by editing the `DEBUG` constant in `include/dryadalis_x86.h`:
```c
#define LOG_SYSCALL 0x1
#define LOG_INSN 0x10
#define LOG_JMP 0x100
#define LOG_MAP 0x1000
#define LOG_FULL (LOG_SYSCALL | LOG_INSN | LOG_JMP | LOG_MAP)
#define LOG_NONE 0x0

#define DEBUG (LOG_MAP | LOG_SYSCALL)
```

For example, `LOG_FULL` looks like this:
```
root@9ac8ce52bcc5:~/dryadalis# ./main test/dbi_test
[+] Loading test/dbi_test
[>] 400000 - 401000 1000
[>] 401000 - 402000 1000
[>] 402000 - 403000 1000
[>] s_binary->dbi_handler->vbrk: 403000
[+] test/dbi_test mapped
0x4010a4	mov eax, 1
0x4010a9	mov edi, 1
0x4010ae	lea rsi, [rip + 0xf4b]
0x4010b5	mov edx, 0x15
0x4010ba	syscall 
.
Hello from DBI test!
[ . ] write (1, 402000, 15) = 21
cflow target: 0x4010bc
0x4010bc	mov eax, 1
0x4010c1	mov edi, 1
0x4010c6	lea rsi, [rip + 0xf33]
0x4010cd	mov edx, 0x15
0x4010d2	syscall 
.
Hello from DBI test!
[ . ] write (1, 402000, 15) = 21
cflow target: 0x4010d4
0x4010d4	mov edi, 0x539
0x4010d9	mov esi, 7
0x4010de	call 0x401028
.
 taken cflow target: 0x401028
0x401028	push rbp
0x401029	mov rbp, rsp
0x40102c	mov rax, rdi
0x40102f	mov rbx, rsi
0x401032	imul rax, rbx
0x401036	add rax, 0x2a
0x40103a	xor rdx, rdx
0x40103d	test rbx, rbx
0x401040	jne 0x401045
.
eflags & flag: 202 & 40 = 0
 taken cflow target: 0x401045
0x401045	div rbx
0x401048	pop rbp
0x401049	ret 
.
cflow target: 0x4010e3
0x4010e3	mov qword ptr [rip + 0x10ae], rax
0x4010ea	mov edi, 0x7e9
0x4010ef	mov esi, 0x2a
0x4010f4	call 0x401028
.
 taken cflow target: 0x401028
0x401028	push rbp
0x401029	mov rbp, rsp
0x40102c	mov rax, rdi
0x40102f	mov rbx, rsi
0x401032	imul rax, rbx
0x401036	add rax, 0x2a
0x40103a	xor rdx, rdx
0x40103d	test rbx, rbx
0x401040	jne 0x401045
.
eflags & flag: 202 & 40 = 0
 taken cflow target: 0x401045
0x401045	div rbx
0x401048	pop rbp
0x401049	ret 
.
cflow target: 0x4010f9
0x4010f9	add qword ptr [rip + 0x1098], rax
0x401100	lea rdi, [rip + 0x104e]
0x401107	mov ecx, 0x40
0x40110c	mov byte ptr [rdi], 0x5a
0x40110f	inc rdi
0x401112	dec rcx
0x401115	jne 0x40110c
.
[loop]
.
eflags & flag: 202 & 40 = 0
 taken cflow target: 0x40110c
0x40110c	mov byte ptr [rdi], 0x5a
0x40110f	inc rdi
0x401112	dec rcx
0x401115	jne 0x40110c
.
eflags & flag: 246 & 40 = 40
 not taken cflow target: 0x401117
0x401117	lea rsi, [rip + 0xee2]
0x40111e	lea rdi, [rip + 0x1030]
0x401125	mov edx, 0x15
0x40112a	call 0x40104a
.
 taken cflow target: 0x40104a
0x40104a	mov rcx, rdx
0x40104d	rep movsb byte ptr [rdi], byte ptr [rsi]
0x40104f	ret 
.
cflow target: 0x40112f
0x40112f	mov eax, 1
0x401134	mov edi, 1
0x401139	lea rsi, [rip + 0x1015]
0x401140	mov edx, 0x15
0x401145	syscall 
.
Hello from DBI test!
[ . ] write (1, 402155, 15) = 21
cflow target: 0x401147
0x401147	call 0x401050
.
 taken cflow target: 0x401050
0x401050	push rbp
0x401051	mov rbp, rsp
0x401054	xor rax, rax
0x401057	mov eax, 1
0x40105c	xor ecx, ecx
0x40105e	cpuid 
0x401060	bt ecx, 0x1c
0x401064	jb 0x401068
.
eflags & flag: 247 & 1 = 1
 taken cflow target: 0x401068
0x401068	or al, 1
0x40106a	xor ecx, ecx
0x40106c	mov eax, 1
0x401071	cpuid 
0x401073	bt ecx, 0x1b
0x401077	jb 0x40107b
.
eflags & flag: 247 & 1 = 1
 taken cflow target: 0x40107b
0x40107b	xor ecx, ecx
0x40107d	xgetbv 
0x401080	test eax, 6
0x401085	jne 0x40108b
.
eflags & flag: 206 & 40 = 0
 taken cflow target: 0x40108b
0x40108b	mov eax, 7
0x401090	xor ecx, ecx
0x401092	cpuid 
0x401094	bt ebx, 5
0x401098	jb 0x40109c
.
eflags & flag: 247 & 1 = 1
 taken cflow target: 0x40109c
0x40109c	or al, 2
0x40109e	movzx rax, al
0x4010a2	pop rbp
0x4010a3	ret 
.
cflow target: 0x40114c
0x40114c	movzx rbx, al
0x401150	test bl, 1
0x401153	je 0x401247
.
eflags & flag: 246 & 40 = 40
 taken cflow target: 0x401247
0x401247	lea rsi, [rip + 0xde7]
0x40124e	mov edx, 0x12
0x401253	mov eax, 1
0x401258	mov edi, 1
0x40125d	syscall 
.
AVX not supported
[ . ] write (1, 402035, 12) = 18
cflow target: 0x40125f
0x40125f	mov eax, 0x3c
0x401264	xor rdi, rdi
0x401267	syscall 
.
[ . ] exit (0)
End of the program ! bbl count: 54
```

## Features

syscall emulation, branch instruction emulation. It is very slow, because of capstone I guess, tinyinst might have been better.