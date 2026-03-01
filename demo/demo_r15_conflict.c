/*
 * demo_r15_conflict.c
 *
 * 测试 VMP 翻译器 R15 临时寄存器冲突
 *
 * 策略：通过高寄存器压力让 GCC 将 X15 分配为活跃变量。
 * 使用 -O2 编译时，GCC 需要大量寄存器来保存循环变量，
 * 当寄存器用尽时会使用 X15。
 *
 * 如果 VMP 翻译器错误地使用 R15 做临时计算，
 * X15 中保存的值会被覆盖，导致结果错误。
 *
 * 编译: aarch64-linux-gnu-gcc -O2 -static -o demo_r15 demo_r15_conflict.c
 * VMP:  ./vmpacker -elf demo_r15 -func compute_heavy -out demo_r15_vmp
 */

#include <stdint.h>
#include <stdio.h>


/*
 * 通过大量局部变量和交叉使用制造高寄存器压力，
 * 迫使 GCC 使用 X15 保存关键变量。
 * 函数体足够大，GCC 不得不征用全部可用寄存器。
 */
__attribute__((noinline)) uint64_t compute_heavy(uint64_t seed) {
  uint64_t a = seed;
  uint64_t b = seed ^ 0xDEADBEEF;
  uint64_t c = seed + 0x12345678;
  uint64_t d = seed - 0xABCDEF01;
  uint64_t e = seed * 3;
  uint64_t f = seed ^ (seed >> 7);
  uint64_t g = seed + (seed << 3);
  uint64_t h = seed ^ 0x55AA55AA;
  uint64_t i = seed + 0x11111111;
  uint64_t j = seed ^ 0x22222222;
  uint64_t k = seed + 0x33333333;
  uint64_t l = seed ^ 0x44444444;
  uint64_t m = seed + 0x55555555;
  uint64_t n = seed ^ 0x66666666;

  /* 多轮交叉运算，确保所有变量同时活跃 */
  for (int iter = 0; iter < 10; iter++) {
    a = a + b + c;
    b = b ^ d ^ e;
    c = c + f + g;
    d = d ^ h ^ i;
    e = e + j + k;
    f = f ^ l ^ m;
    g = g + n + a;
    h = h ^ b ^ c;
    i = i + d + e;
    j = j ^ f ^ g;
    k = k + h + i;
    l = l ^ j ^ k;
    m = m + l + a;
    n = n ^ m ^ b;
  }

  return a ^ b ^ c ^ d ^ e ^ f ^ g ^ h ^ i ^ j ^ k ^ l ^ m ^ n;
}

int main(void) {
  uint64_t result = compute_heavy(0x42);
  printf("result = 0x%016lx\n", result);

  /* 多组测试 */
  uint64_t r2 = compute_heavy(0x100);
  printf("result2 = 0x%016lx\n", r2);

  uint64_t r3 = compute_heavy(0xFFFF);
  printf("result3 = 0x%016lx\n", r3);

  return 0;
}
