#include <stdio.h>
#include <stdint.h>

__attribute__((noinline)) int64_t check_madd(void) {
    int64_t a = 10, b = 20, c = 5;
    int64_t r1 = 0, r2 = 0;

    __asm__ volatile(
        "madd %[o1], %[a], %[b], %[c]\n"
        : [o1] "=r"(r1)
        : [a] "r"(a), [b] "r"(b), [c] "r"(c)
    );
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");

    __asm__ volatile(
        "madd %[o2], %[a], %[b], xzr\n"
        : [o2] "=r"(r2)
        : [a] "r"(a), [b] "r"(b)
    );
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop;");

    if (r1 == 205 && r2 == 200) return 1;
    return 0;
}

int main(void) {
    int64_t v = check_madd();
    if (v == 1) { printf("PASS:MADD\n"); return 0; }
    printf("FAIL:MADD r=%ld\n", v);
    return 1;
}
