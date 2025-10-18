// dbi_c_avx.c  (simple AVX intrinsic example)
#include <immintrin.h>
#include <stdio.h>

int main(void) {
    float a[8] = {1,2,3,4,5,6,7,8};
    float b[8] = {10,20,30,40,50,60,70,80};
    float out[8];

    __m256 A = _mm256_loadu_ps(a);
    __m256 B = _mm256_loadu_ps(b);
    __m256 C = _mm256_add_ps(A, B);
    _mm256_storeu_ps(out, C);

    for (int i = 0; i < 8; ++i) {
        printf("%f ", out[i]);
    }
    puts("");
    return 0;
}

