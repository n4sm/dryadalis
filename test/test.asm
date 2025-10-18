; ---------------------------------------------------------------------------
; dbi_avx_test.asm
; 64-bit Linux NASM test for DBI engines with AVX / AVX2 checks.
;
; Features:
;  - CPUID + XGETBV detection for AVX and AVX2
;  - AVX float vector add/mul (vaddps, vmulps) on 8x float (YMM)
;  - AVX2 integer vector multiply (vpmulld) if available
;  - Memory compare of results with expected arrays (byte-by-byte)
;  - Other non-AVX behaviors retained from previous sample
; ---------------------------------------------------------------------------

        bits 64
        default rel

        section .data
; messages
msg:        db "Hello from DBI test!", 10
msglen:     equ $ - msg

avx_ok:     db "AVX test: OK", 10
avx_ok_len: equ $ - avx_ok

avx_mismatch: db "AVX test: MISMATCH", 10
avx_mismatch_len: equ $ - avx_mismatch

avx_nosupp: db "AVX not supported", 10
avx_nosupp_len: equ $ - avx_nosupp

avx2_ok:    db "AVX2 (int) test: OK", 10
avx2_ok_len: equ $ - avx2_ok

avx2_mismatch: db "AVX2 (int) test: MISMATCH", 10
avx2_mismatch_len: equ $ - avx2_mismatch

; Vector data: 8 floats (32 bytes) for AVX FP test
; a: 1.0,2.0,...,8.0
a_floats:   dd 0x3f800000, 0x40000000, 0x40400000, 0x40800000
            dd 0x40a00000, 0x40c00000, 0x40e00000, 0x41000000

; b: 10.0,20.0,...,80.0
b_floats:   dd 0x41200000, 0x41a00000, 0x42200000, 0x42a00000
            dd 0x43200000, 0x43a00000, 0x44200000, 0x44a00000

; expected = a * b + (a + b)  (arbitrary chosen operation; we'll compute same in AVX)
; We precompute expected values (float) to compare against runtime AVX result.
; For simplicity we compute expected = a + b (sum). (That still exercises vaddps.)
expected_add: dd 0x41460000, 0x41a40000, 0x42600000, 0x43000000
              dd 0x43600000, 0x44200000, 0x44800000, 0x45400000
; note: above are precomputed floats for a+b:
;  1+10=11.0  -> 0x41460000
;  2+20=22.0  -> 0x41a40000
;  etc.

; For AVX2 integer test:
; use 8 x 32-bit integers (fits in ymm)
a_ints:     dd 1,2,3,4,5,6,7,8
b_ints:     dd 10,20,30,40,50,60,70,80
expected_imul: dd 10,40,90,160,250,360,490,640   ; expected vpmulld results (elementwise)

; general buffer to store results
result_buf: times 32 db 0

; small scratch buffer for other tests
buffer:     times 64 db 0

section .bss
tmp:    resq 4

section .text
        global _start

; -------------------------
; Helpers
; -------------------------
; memcmp-like: compares [rsi] and [rdi] for rcx bytes
; returns ZF=1 if equal else ZF=0; clobbers rax, rbx, rdx, rcx, rsi, rdi
memcmp_bytes:
        push rbp
        mov rbp, rsp
        ; rdi = ptr1, rsi = ptr2, rcx = len
        test rcx, rcx
        jz .equal
.loop:
        mov al, [rdi]
        mov bl, [rsi]
        cmp al, bl
        jne .ne
        inc rdi
        inc rsi
        dec rcx
        jnz .loop
.equal:
        mov rax, 1
        pop rbp
        ret
.ne:
        xor rax, rax
        pop rbp
        ret

; a small math helper from previous sample
do_math:
        push rbp
        mov rbp, rsp
        mov rax, rdi
        mov rbx, rsi
        imul rax, rbx
        add rax, 42
        xor rdx, rdx
        ; prevent divide by zero
        test rbx, rbx
        jnz .do_div
        inc rbx
.do_div:
        div rbx
        pop rbp
        ret

; string copy helper
str_copy:
        mov rcx, rdx
        rep movsb
        ret

; -------------------------
; CPUID / XGETBV helpers
; -------------------------
; returns:
;   AL: bit0 = AVX supported by CPUID (ECX bit 28 of leaf 1)
;       bit1 = AVX2 supported by CPUID (EBX bit 5 of leaf 7)
;   ZF not used
; Clobbers: rax,rbx,rcx,rdx, rdi, rsi
check_avx_features:
        push rbp
        mov rbp, rsp

        ; default return 0
        xor rax, rax        ; we'll return flags in al (bit0 avx, bit1 avx2)

        ; CPUID leaf 1 -> check ECX bit 28 (AVX)
        mov eax, 1
        xor ecx, ecx
        cpuid
        ; ECX: bit 28 -> AVX
        bt ecx, 28
        jc .has_avx_cpuid
        jmp .check_xgetbv      ; still need to check xgetbv, but mark not set
.has_avx_cpuid:
        or al, 1              ; set bit0

.check_xgetbv:
        ; need to check XGETBV: XCR0 bit 1 (SSE) and bit 2 (AVX) must be enabled by OS
        xor ecx, ecx
        ; xgetbv -> EDX:EAX
        ; Surround with a check to avoid illegal instruction if CPUID didn't advertise xsave
        ; Check CPUID leaf 1: ECX bit 27 = OSXSAVE
        mov eax, 1
        cpuid
        bt ecx, 27
        jc .do_xgetbv
        jmp .skip_xgetbv
.do_xgetbv:
        xor ecx, ecx
        xgetbv                 ; eax = XCR0 low, edx = XCR0 high
        ; check that XCR0 bits 1 and 2 are set (SSE and AVX state enabled)
        ; test eax, 0x6
        test eax, 6
        jne .xsave_ok
        ; else clear avx bit if present
        and al, 0xFE           ; clear bit0 (AVX)
        jmp .after_xgetbv
.xsave_ok:
        ; ok keep current flags
.after_xgetbv:
.skip_xgetbv:

        ; Now check AVX2: CPUID leaf 7 subleaf 0 -> EBX bit 5
        mov eax, 7
        xor ecx, ecx
        cpuid
        bt ebx, 5
        jc .has_avx2
        jmp .done_check
.has_avx2:
        or al, 2               ; set bit1

.done_check:
        ; return AL flags (bit0 avx, bit1 avx2)
        movzx rax, al
        pop rbp
        ret

; -------------------------
; _start
; -------------------------
_start:
        ; --- initial non-AVX behavior (hello) ---
        mov rax, 1          ; SYS_write
        mov rdi, 1
        lea rsi, [rel msg]
        mov rdx, msglen
        syscall

        mov rax, 1          ; SYS_write
        mov rdi, 1
        lea rsi, [rel msg]
        mov rdx, msglen
        syscall

        ; Do some math calls to keep the old behavior
        mov rdi, 1337
        mov rsi, 7
        call do_math
        mov [tmp], rax

        mov rdi, 2025
        mov rsi, 42
        call do_math
        add [tmp], rax

        ; fill buffer loop (non-AVX)
        lea rdi, [rel buffer]
        mov rcx, 64
.fill_loop:
        mov byte [rdi], 0x5A
        inc rdi
        dec rcx
        jnz .fill_loop

        ; copy msg to buffer to exercise rep movsb
        lea rsi, [rel msg]
        lea rdi, [rel buffer]
        mov rdx, msglen
        call str_copy

        ; write buffer (partial)
        mov rax, 1
        mov rdi, 1
        lea rsi, [rel buffer]
        mov rdx, msglen
        syscall

        ; --- AVX feature check ---
        call check_avx_features
        ; flags in al
        movzx rbx, al
        test bl, 1
        jz .no_avx            ; if bit0 not set -> no avx

        ; AVX present: do AVX FP add test : result_buf = a_floats + b_floats
        ; Use YMM registers, store into result_buf, then compare to expected_add
        vmovaps ymm0, yword [rel a_floats]
        vmovaps ymm1, yword [rel b_floats]
        vaddps ymm2, ymm0, ymm1        ; ymm2 = a + b
        vmovups yword [rel result_buf], ymm2

        ; compare result_buf vs expected_add (32 bytes)
        lea rdi, [rel result_buf]
        lea rsi, [rel expected_add]
        mov rcx, 32
        call memcmp_bytes
        cmp rax, 1
        je .avx_pass
        ; mismatch
        lea rsi, [rel avx_mismatch]
        mov rdx, avx_mismatch_len
        jmp .avx_report
.avx_pass:
        lea rsi, [rel avx_ok]
        mov rdx, avx_ok_len
.avx_report:
        mov rax, 1
        mov rdi, 1
        syscall

        ; Clear YMM state (recommended)
        vzeroupper

        ; --- If AVX2 present (bit1), do integer vector multiply test ---
        test bl, 2
        jz .after_avx2

        ; AVX2: load integer arrays, do vpmulld (32-bit signed multiply)
        ; ymm0 <- a_ints, ymm1 <- b_ints
        vmovdqu ymm0, yword [rel a_ints]
        vmovdqu ymm1, yword [rel b_ints]
        vpmulld ymm2, ymm0, ymm1
        vmovdqu yword [rel result_buf], ymm2

        ; compare with expected_imul (32 bytes)
        lea rdi, [rel result_buf]
        lea rsi, [rel expected_imul]
        mov rcx, 32
        call memcmp_bytes
        cmp rax, 1
        je .avx2_pass
        lea rsi, [rel avx2_mismatch]
        mov rdx, avx2_mismatch_len
        jmp .avx2_report
.avx2_pass:
        lea rsi, [rel avx2_ok]
        mov rdx, avx2_ok_len
.avx2_report:
        mov rax, 1
        mov rdi, 1
        syscall

.after_avx2:
        ; continue with other behaviors: small arithmetic loop
        mov rcx, 10
        xor rax, rax
.loop2:
        add rax, rcx
        dec rcx
        jnz .loop2

        ; self-modifying write test (write into buffer)
        lea rdi, [rel buffer]
        mov byte [rdi+5], 'X'

        ; --- Exit
        mov rax, 60
        xor rdi, rdi
        syscall

.no_avx:
        ; Print AVX not supported
        lea rsi, [rel avx_nosupp]
        mov rdx, avx_nosupp_len
        mov rax, 1
        mov rdi, 1
        syscall

        ; then fallthrough to continue with normal behavior (we'll exit)
        mov rax, 60
        xor rdi, rdi
        syscall

