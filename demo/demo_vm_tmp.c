/*
 * demo_vm_tmp.c — 验证 VM_R() 宏方案
 *
 * 模拟 VM 解释器中的寄存器访问：
 *   - R[0-31] = ARM64 寄存器空间
 *   - tmp[0-1] = 翻译器独立临时变量 (idx 32, 33)
 *
 * 编译: aarch64-linux-gnu-gcc -O2 -o demo_vm_tmp demo_vm_tmp.c
 * 运行: ./demo_vm_tmp
 */
#include <stdio.h>
#include <string.h>

/* ---- 类型 ---- */
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;
typedef short i16;

/* ---- VM 配置 ---- */
#define VM_REG_COUNT 32
#define VM_TMP_COUNT 2
#define VM_TMP1 32 /* 翻译器临时寄存器 1 的索引 */
#define VM_TMP2 33 /* 翻译器临时寄存器 2 的索引 */

/* ---- VM 上下文 ---- */
typedef struct {
  u64 R[VM_REG_COUNT];   /* ARM64 寄存器: R[0]-R[31] */
  u64 tmp[VM_TMP_COUNT]; /* 翻译器专用临时变量 (独立于 R[]) */
} vm_ctx_t;

/* ---- 统一寄存器访问宏 ---- */
/*
 * VM_R(vm, idx):
 *   idx 0-31  → vm->R[idx & 31]  (ARM64 寄存器)
 *   idx 32-33 → vm->tmp[idx - 32] (翻译器临时变量)
 *
 * 用法:
 *   读: u64 val = VM_R(vm, reg_idx);
 *   写: VM_R(vm, reg_idx) = val;
 */
static inline u64 *vm_reg_ptr(vm_ctx_t *vm, u8 idx) {
  if (__builtin_expect(idx >= VM_TMP1, 0))
    return &vm->tmp[(idx - VM_TMP1) & (VM_TMP_COUNT - 1)];
  return &vm->R[idx & 31];
}

#define VM_R(vm, idx) (*vm_reg_ptr((vm), (idx)))

/* ---- 模拟的 VM handler ---- */

/* 模拟 h_load8: LDRB Wd, [Xn, #off] */
static void sim_load8(vm_ctx_t *vm, u8 d, u8 n, i16 off) {
  u64 addr = VM_R(vm, n) + off;
  printf("  LOAD8: d=R%d n=R%d base=0x%llx addr=0x%llx\n", d, n, VM_R(vm, n),
         addr);
  VM_R(vm, d) = *(u8 *)addr;
  printf("  -> R%d = 0x%llx\n", d, VM_R(vm, d));
}

/* 模拟 h_mov_reg: MOV Xd, Xn */
static void sim_mov_reg(vm_ctx_t *vm, u8 d, u8 n) {
  printf("  MOV: R%d = R%d (0x%llx)\n", d, n, VM_R(vm, n));
  VM_R(vm, d) = VM_R(vm, n);
}

/* 模拟 h_add: ADD Xd, Xn, Xm */
static void sim_add(vm_ctx_t *vm, u8 d, u8 n, u8 m) {
  printf("  ADD: R%d = R%d + R%d = 0x%llx + 0x%llx\n", d, n, m, VM_R(vm, n),
         VM_R(vm, m));
  VM_R(vm, d) = VM_R(vm, n) + VM_R(vm, m);
  printf("  -> R%d = 0x%llx\n", d, VM_R(vm, d));
}

/* ---- 测试 ---- */
int main(void) {
  vm_ctx_t vm;
  memset(&vm, 0, sizeof(vm));

  /* 准备测试数据 */
  u8 test_buf[16] = {0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44};
  vm.R[0] = (u64)test_buf;  /* X0 = 测试缓冲区指针 */
  vm.R[1] = 0x1234;         /* X1 = 测试值 */
  vm.R[19] = (u64)test_buf; /* X19 = 另一个指针 */

  printf("=== Test 1: 正常寄存器访问 (R0-R31) ===\n");
  printf("R0=0x%llx R1=0x%llx R19=0x%llx\n", VM_R(&vm, 0), VM_R(&vm, 1),
         VM_R(&vm, 19));

  /* 正常 LDRB 操作 */
  sim_load8(&vm, 2, 0, 0); /* R2 = LDRB [R0+0] → 0xAA */
  sim_load8(&vm, 3, 0, 3); /* R3 = LDRB [R0+3] → 0xDD */

  printf("\nExpected: R2=0xAA, R3=0xDD\n");
  printf("Actual:   R2=0x%llx, R3=0x%llx\n", VM_R(&vm, 2), VM_R(&vm, 3));

  /* ---- Test 2: 翻译器临时寄存器 (VM_TMP1=32, VM_TMP2=33) ---- */
  printf("\n=== Test 2: 翻译器临时寄存器 (tmp[]) ===\n");
  printf("Before: tmp1=0x%llx tmp2=0x%llx\n", VM_R(&vm, VM_TMP1),
         VM_R(&vm, VM_TMP2));

  /* 模拟翻译器典型用法: MOV vmTmp, Xn; 操作 vmTmp; MOV Xd, vmTmp */
  sim_mov_reg(&vm, VM_TMP1, 0);      /* vmTmp = R0 (指针) */
  sim_load8(&vm, 5, VM_TMP1, 4);     /* R5 = LDRB [vmTmp+4] → 0x11 */
  sim_add(&vm, VM_TMP1, VM_TMP1, 1); /* vmTmp += R1 (0x1234) */

  printf("\nExpected: R5=0x11\n");
  printf("Actual:   R5=0x%llx\n", VM_R(&vm, 5));
  printf("tmp1=0x%llx (should be buf+0x1234)\n", VM_R(&vm, VM_TMP1));

  /* ---- Test 3: tmp 不影响 R0-R31 ---- */
  printf("\n=== Test 3: tmp 隔离性验证 ===\n");
  VM_R(&vm, VM_TMP1) = 0xDEADBEEF;
  VM_R(&vm, VM_TMP2) = 0xCAFEBABE;

  printf("R0=0x%llx (should be buf ptr, NOT 0xDEADBEEF)\n", VM_R(&vm, 0));
  printf("R1=0x%llx (should be 0x1234, NOT 0xCAFEBABE)\n", VM_R(&vm, 1));
  printf("tmp1=0x%llx (should be 0xDEADBEEF)\n", VM_R(&vm, VM_TMP1));
  printf("tmp2=0x%llx (should be 0xCAFEBABE)\n", VM_R(&vm, VM_TMP2));

  /* 验证 R[0]/R[1] 与 tmp 完全独立 */
  int pass = 1;
  if (VM_R(&vm, 0) == 0xDEADBEEF) {
    printf("FAIL: R0 aliased with tmp1!\n");
    pass = 0;
  }
  if (VM_R(&vm, 1) == 0xCAFEBABE) {
    printf("FAIL: R1 aliased with tmp2!\n");
    pass = 0;
  }
  if (VM_R(&vm, VM_TMP1) != 0xDEADBEEF) {
    printf("FAIL: tmp1 wrong!\n");
    pass = 0;
  }
  if (VM_R(&vm, VM_TMP2) != 0xCAFEBABE) {
    printf("FAIL: tmp2 wrong!\n");
    pass = 0;
  }
  if (VM_R(&vm, 2) != 0xAA) {
    printf("FAIL: R2 wrong!\n");
    pass = 0;
  }
  if (VM_R(&vm, 3) != 0xDD) {
    printf("FAIL: R3 wrong!\n");
    pass = 0;
  }
  if (VM_R(&vm, 5) != 0x11) {
    printf("FAIL: R5 wrong!\n");
    pass = 0;
  }

  printf("\n=== Result: %s ===\n", pass ? "ALL PASSED" : "FAILED");
  return pass ? 0 : 1;
}
