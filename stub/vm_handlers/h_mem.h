/*
 * h_mem.h — 内存访问指令 handler
 *
 * LDRB / LDR(32/64) / STRB / STR(32/64)
 * 编码: [op | d/base | n/src | offset16]  共 5B
 */
#ifndef H_MEM_H
#define H_MEM_H

#include "../vm_decode.h"
#include "../vm_types.h"


/* ---- 加载 (LDR) ---- */

/* LDRB Wd, [Xn, #off16] */
static inline u32 h_load8(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], n = vm->bc[vm->pc + 2];
  u16 off = rd16(&vm->bc[vm->pc + 3]);
  vm->R[d & 31] = *(u8 *)(vm->R[n & 31] + off);
  return 5;
}

/* LDR Wd, [Xn, #off16] */
static inline u32 h_load32(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], n = vm->bc[vm->pc + 2];
  u16 off = rd16(&vm->bc[vm->pc + 3]);
  vm->R[d & 31] = *(u32 *)(vm->R[n & 31] + off);
  return 5;
}

/* LDR Xd, [Xn, #off16] */
static inline u32 h_load64(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], n = vm->bc[vm->pc + 2];
  u16 off = rd16(&vm->bc[vm->pc + 3]);
  vm->R[d & 31] = *(u64 *)(vm->R[n & 31] + off);
  return 5;
}

/* ---- 存储 (STR) ---- */

/* STRB Wn, [Xb, #off16] */
static inline u32 h_store8(vm_ctx_t *vm) {
  u8 b = vm->bc[vm->pc + 1], n = vm->bc[vm->pc + 2];
  u16 off = rd16(&vm->bc[vm->pc + 3]);
  *(u8 *)(vm->R[b & 31] + off) = (u8)vm->R[n & 31];
  return 5;
}

/* STR Wn, [Xb, #off16] */
static inline u32 h_store32(vm_ctx_t *vm) {
  u8 b = vm->bc[vm->pc + 1], n = vm->bc[vm->pc + 2];
  u16 off = rd16(&vm->bc[vm->pc + 3]);
  *(u32 *)(vm->R[b & 31] + off) = (u32)vm->R[n & 31];
  return 5;
}

/* STR Xn, [Xb, #off16] */
static inline u32 h_store64(vm_ctx_t *vm) {
  u8 b = vm->bc[vm->pc + 1], n = vm->bc[vm->pc + 2];
  u16 off = rd16(&vm->bc[vm->pc + 3]);
  *(u64 *)(vm->R[b & 31] + off) = vm->R[n & 31];
  return 5;
}

#endif /* H_MEM_H */
