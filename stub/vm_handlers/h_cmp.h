/*
 * h_cmp.h — 比较指令 handler
 *
 * CMP Xn, Xm     [3B]    设置 FL (ZF/SF/CF)
 * CMP Xn, #imm32 [6B]
 */
#ifndef H_CMP_H
#define H_CMP_H

#include "../vm_decode.h"
#include "../vm_types.h"


/* 内部: 根据两个操作数设置标志位 */
static inline void vm_set_flags(vm_ctx_t *vm, u64 va, u64 vb) {
  vm->FL = 0;
  if (va == vb)
    vm->FL |= FL_ZERO; /* Z: 相等 */
  if ((i64)va < (i64)vb)
    vm->FL |= FL_SIGN; /* N: 有符号小于 */
  if (va < vb)
    vm->FL |= FL_CARRY; /* C: 无符号小于 */
}

/* CMP Xn, Xm      [3B: op | n | m] */
static inline u32 h_cmp(vm_ctx_t *vm) {
  u8 a = vm->bc[vm->pc + 1], b = vm->bc[vm->pc + 2];
  vm_set_flags(vm, vm->R[a & 31], vm->R[b & 31]);
  return 3;
}

/* CMP Xn, #imm32  [6B: op | n | imm32] */
static inline u32 h_cmp_imm(vm_ctx_t *vm) {
  u8 r = vm->bc[vm->pc + 1];
  u32 imm = rd32(&vm->bc[vm->pc + 2]);
  vm_set_flags(vm, vm->R[r & 31], (u64)imm);
  return 6;
}

#endif /* H_CMP_H */
