/*
 * h_branch.h — 分支指令 handler
 *
 * 所有分支指令编码 [5B: op | target32]
 * 返回 0 表示 pc 已被直接设置 (不需要外部 += adv)
 */
#ifndef H_BRANCH_H
#define H_BRANCH_H

#include "../vm_decode.h"
#include "../vm_types.h"

/* B target (无条件跳转) */
static inline u32 h_jmp(vm_ctx_t *vm) {
  vm->pc = rd32(&vm->bc[vm->pc + 1]);
  return 0; /* pc 已设置 */
}

/* B.EQ target (ZF=1) */
static inline u32 h_je(vm_ctx_t *vm) {
  u32 t = rd32(&vm->bc[vm->pc + 1]);
  vm->pc = (vm->FL & FL_ZERO) ? t : vm->pc + 5;
  return 0;
}

/* B.NE target (ZF=0) */
static inline u32 h_jne(vm_ctx_t *vm) {
  u32 t = rd32(&vm->bc[vm->pc + 1]);
  vm->pc = (!(vm->FL & FL_ZERO)) ? t : vm->pc + 5;
  return 0;
}

/* B.LT target (SF=1, 有符号小于) */
static inline u32 h_jl(vm_ctx_t *vm) {
  u32 t = rd32(&vm->bc[vm->pc + 1]);
  vm->pc = (vm->FL & FL_SIGN) ? t : vm->pc + 5;
  return 0;
}

/* B.GE target (SF=0, 有符号大于等于) */
static inline u32 h_jge(vm_ctx_t *vm) {
  u32 t = rd32(&vm->bc[vm->pc + 1]);
  vm->pc = (!(vm->FL & FL_SIGN)) ? t : vm->pc + 5;
  return 0;
}

/* B.GT target (!ZF && !SF) */
static inline u32 h_jgt(vm_ctx_t *vm) {
  u32 t = rd32(&vm->bc[vm->pc + 1]);
  vm->pc = (!(vm->FL & (FL_ZERO | FL_SIGN))) ? t : vm->pc + 5;
  return 0;
}

/* B.LE target (ZF || SF) */
static inline u32 h_jle(vm_ctx_t *vm) {
  u32 t = rd32(&vm->bc[vm->pc + 1]);
  vm->pc = (vm->FL & (FL_ZERO | FL_SIGN)) ? t : vm->pc + 5;
  return 0;
}

/* B.CC target (CF=1, 无符号小于) */
static inline u32 h_jb(vm_ctx_t *vm) {
  u32 t = rd32(&vm->bc[vm->pc + 1]);
  vm->pc = (vm->FL & FL_CARRY) ? t : vm->pc + 5;
  return 0;
}

/* B.CS target (CF=0, 无符号大于等于) */
static inline u32 h_jae(vm_ctx_t *vm) {
  u32 t = rd32(&vm->bc[vm->pc + 1]);
  vm->pc = (!(vm->FL & FL_CARRY)) ? t : vm->pc + 5;
  return 0;
}

/* B.LS target (CF||ZF, 无符号小于等于) */
static inline u32 h_jbe(vm_ctx_t *vm) {
  u32 t = rd32(&vm->bc[vm->pc + 1]);
  vm->pc = (vm->FL & (FL_CARRY | FL_ZERO)) ? t : vm->pc + 5;
  return 0;
}

/* B.HI target (!CF&&!ZF, 无符号大于) */
static inline u32 h_ja(vm_ctx_t *vm) {
  u32 t = rd32(&vm->bc[vm->pc + 1]);
  vm->pc = (!(vm->FL & (FL_CARRY | FL_ZERO))) ? t : vm->pc + 5;
  return 0;
}

#endif /* H_BRANCH_H */
