/*
 * h_alu.h — 算术/逻辑指令 handler
 *
 * 分两类:
 *   三寄存器: [4B: op | d | n | m]    ADD/SUB/MUL/EOR/AND/ORR/LSL/LSR/ASR/ROR
 *   寄存器+立即数: [7B: op | d | n | imm32]
 *   双寄存器: [3B: op | d | n]         MVN
 */
#ifndef H_ALU_H
#define H_ALU_H

#include "../vm_decode.h"
#include "../vm_types.h"

/* ========== 三寄存器 ALU (4B) ========== */

/* ADD Xd, Xn, Xm */
static inline u32 h_add(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], a = vm->bc[vm->pc + 2], b = vm->bc[vm->pc + 3];
  vm->R[d & 31] = vm->R[a & 31] + vm->R[b & 31];
  return 4;
}

/* SUB Xd, Xn, Xm */
static inline u32 h_sub(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], a = vm->bc[vm->pc + 2], b = vm->bc[vm->pc + 3];
  vm->R[d & 31] = vm->R[a & 31] - vm->R[b & 31];
  return 4;
}

/* MUL Xd, Xn, Xm */
static inline u32 h_mul(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], a = vm->bc[vm->pc + 2], b = vm->bc[vm->pc + 3];
  vm->R[d & 31] = vm->R[a & 31] * vm->R[b & 31];
  return 4;
}

/* EOR Xd, Xn, Xm */
static inline u32 h_xor(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], a = vm->bc[vm->pc + 2], b = vm->bc[vm->pc + 3];
  vm->R[d & 31] = vm->R[a & 31] ^ vm->R[b & 31];
  return 4;
}

/* AND Xd, Xn, Xm */
static inline u32 h_and(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], a = vm->bc[vm->pc + 2], b = vm->bc[vm->pc + 3];
  vm->R[d & 31] = vm->R[a & 31] & vm->R[b & 31];
  return 4;
}

/* ORR Xd, Xn, Xm */
static inline u32 h_or(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], a = vm->bc[vm->pc + 2], b = vm->bc[vm->pc + 3];
  vm->R[d & 31] = vm->R[a & 31] | vm->R[b & 31];
  return 4;
}

/* LSL Xd, Xn, Xm */
static inline u32 h_shl(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], a = vm->bc[vm->pc + 2], b = vm->bc[vm->pc + 3];
  vm->R[d & 31] = vm->R[a & 31] << (vm->R[b & 31] & 63);
  return 4;
}

/* LSR Xd, Xn, Xm */
static inline u32 h_shr(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], a = vm->bc[vm->pc + 2], b = vm->bc[vm->pc + 3];
  vm->R[d & 31] = vm->R[a & 31] >> (vm->R[b & 31] & 63);
  return 4;
}

/* ASR Xd, Xn, Xm (算术右移, 保留符号位) */
static inline u32 h_asr(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], a = vm->bc[vm->pc + 2], b = vm->bc[vm->pc + 3];
  vm->R[d & 31] = (u64)((i64)vm->R[a & 31] >> (vm->R[b & 31] & 63));
  return 4;
}

/* MVN Xd, Xn (按位取反) */
static inline u32 h_not(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], n = vm->bc[vm->pc + 2];
  vm->R[d & 31] = ~vm->R[n & 31];
  return 3;
}

/* ROR Xd, Xn, Xm (循环右移) */
static inline u32 h_ror(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], a = vm->bc[vm->pc + 2], b = vm->bc[vm->pc + 3];
  u64 v = vm->R[a & 31];
  u32 n = (u32)(vm->R[b & 31] & 63);
  if (n == 0) {
    vm->R[d & 31] = v;
  } else {
    vm->R[d & 31] = (v >> n) | (v << (64 - n));
  }
  return 4;
}

/* UMULH Xd, Xn, Xm (无符号高 64 位乘法) */
static inline u32 h_umulh(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], a = vm->bc[vm->pc + 2], b = vm->bc[vm->pc + 3];
  __uint128_t r = (__uint128_t)vm->R[a & 31] * (__uint128_t)vm->R[b & 31];
  vm->R[d & 31] = (u64)(r >> 64);
  return 4;
}

/* ========== 寄存器 + 立即数 ALU (7B) ========== */

/* ADD Xd, Xn, #imm32 */
static inline u32 h_add_imm(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], n = vm->bc[vm->pc + 2];
  u32 imm = rd32(&vm->bc[vm->pc + 3]);
  vm->R[d & 31] = vm->R[n & 31] + (u64)imm;
  return 7;
}

/* SUB Xd, Xn, #imm32 */
static inline u32 h_sub_imm(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], n = vm->bc[vm->pc + 2];
  u32 imm = rd32(&vm->bc[vm->pc + 3]);
  vm->R[d & 31] = vm->R[n & 31] - (u64)imm;
  return 7;
}

/* EOR Xd, Xn, #imm32 */
static inline u32 h_xor_imm(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], n = vm->bc[vm->pc + 2];
  u32 imm = rd32(&vm->bc[vm->pc + 3]);
  vm->R[d & 31] = vm->R[n & 31] ^ (u64)imm;
  return 7;
}

/* AND Xd, Xn, #imm32 */
static inline u32 h_and_imm(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], n = vm->bc[vm->pc + 2];
  u32 imm = rd32(&vm->bc[vm->pc + 3]);
  vm->R[d & 31] = vm->R[n & 31] & (u64)imm;
  return 7;
}

/* ORR Xd, Xn, #imm32 */
static inline u32 h_or_imm(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], n = vm->bc[vm->pc + 2];
  u32 imm = rd32(&vm->bc[vm->pc + 3]);
  vm->R[d & 31] = vm->R[n & 31] | (u64)imm;
  return 7;
}

/* MUL Xd, Xn, #imm32 */
static inline u32 h_mul_imm(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], n = vm->bc[vm->pc + 2];
  u32 imm = rd32(&vm->bc[vm->pc + 3]);
  vm->R[d & 31] = vm->R[n & 31] * (u64)imm;
  return 7;
}

/* LSL Xd, Xn, #imm32 */
static inline u32 h_shl_imm(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], n = vm->bc[vm->pc + 2];
  u32 imm = rd32(&vm->bc[vm->pc + 3]);
  vm->R[d & 31] = vm->R[n & 31] << (imm & 63);
  return 7;
}

/* LSR Xd, Xn, #imm32 */
static inline u32 h_shr_imm(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], n = vm->bc[vm->pc + 2];
  u32 imm = rd32(&vm->bc[vm->pc + 3]);
  vm->R[d & 31] = vm->R[n & 31] >> (imm & 63);
  return 7;
}

/* ASR Xd, Xn, #imm32 */
static inline u32 h_asr_imm(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], n = vm->bc[vm->pc + 2];
  u32 imm = rd32(&vm->bc[vm->pc + 3]);
  vm->R[d & 31] = (u64)((i64)vm->R[n & 31] >> (imm & 63));
  return 7;
}

/* UDIV Xd, Xn, Xm (无符号除法, 除零返回0 — ARM64 规范) */
static inline u32 h_udiv(vm_ctx_t *vm) {
  u8 d = vm->bc[vm->pc + 1], a = vm->bc[vm->pc + 2], b = vm->bc[vm->pc + 3];
  u64 divisor = vm->R[b & 31];
  vm->R[d & 31] = (divisor == 0) ? 0 : (vm->R[a & 31] / divisor);
  return 4;
}

#endif /* H_ALU_H */
