/*
 * vmp_test_demo.c — VMP 方法论验证 demo
 *
 * 编译: aarch64-linux-gnu-gcc -O2 -static -o vmp_test_demo vmp_test_demo.c
 * 注意: 函数必须 > 72B 才能放下 VMP trampoline
 *       使用 volatile 防止编译器优化掉计算
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>


/* ---- 被测函数 A: 算术 + 循环 (足够大) ---- */
__attribute__((noinline)) int test_arith(int a, int b) {
  volatile int x = a + b;
  volatile int y = x * 3;
  volatile int z = y - 10;
  volatile int sum = 0;
  for (volatile int i = 0; i < 10; i++) {
    sum += z + i;
    if (sum > 1000)
      sum = sum - 500;
  }
  volatile int r = z + (sum & 0xFF);
  return r;
}

/* ---- 被测函数 B: 内存读写 + 大循环 ---- */
__attribute__((noinline)) int test_memory(int *arr, int n) {
  volatile int sum = 0;
  for (volatile int i = 0; i < n; i++) {
    volatile int val = arr[i];
    if (val > 0) {
      sum += val;
    } else {
      sum -= val;
    }
    volatile int tmp = sum * 2;
    sum = (tmp > 10000) ? tmp - 5000 : tmp;
    sum = sum / 2;
  }
  return sum;
}

/* ---- 被测函数 C: 条件分支密集 ---- */
__attribute__((noinline)) int test_branch(int val) {
  volatile int result = 0;
  if (val > 200) {
    result = val - 200;
    result *= 3;
  } else if (val > 100) {
    result = val - 100;
    result *= 2;
  } else if (val > 50) {
    result = val * 2;
    result += 10;
  } else if (val > 0) {
    result = val + 100;
    result -= 50;
  } else {
    result = -val;
    result += 1000;
  }
  volatile int check = result;
  if (check > 500)
    check = 500;
  return check;
}

/* ---- 被测函数 D: 结构体 + 字节操作 ---- */
typedef struct {
  uint32_t magic;
  uint16_t len;
  uint8_t data[16];
} TestHeader;

__attribute__((noinline)) int test_struct(TestHeader *h) {
  if (h->magic != 0xDEADBEEF)
    return -1;
  volatile int sum = 0;
  for (volatile int i = 0; i < h->len && i < 16; i++) {
    volatile uint8_t byte_val = h->data[i];
    sum += byte_val;
    if (byte_val > 128) {
      sum += 10;
    }
  }
  volatile int final_val = sum * 2 - h->len;
  return final_val;
}

int main(void) {
  int pass = 1;

  /* Test A: 结果确定性计算 */
  int ra = test_arith(5, 9);
  printf("A: %d\n", ra);

  /* Test B */
  int arr[] = {1, 2, 3, 4, 5};
  int rb = test_memory(arr, 5);
  printf("B: %d\n", rb);

  /* Test C */
  int rc = test_branch(150);
  printf("C: %d\n", rc);

  /* Test D */
  TestHeader hdr;
  hdr.magic = 0xDEADBEEF;
  hdr.len = 5;
  memset(hdr.data, 2, 16);
  int rd = test_struct(&hdr);
  printf("D: %d\n", rd);

  /* 验证：比较 VMP 前后结果是否一致 */
  printf("RESULTS: %d %d %d %d\n", ra, rb, rc, rd);
  return 0;
}
