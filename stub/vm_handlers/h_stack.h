/*
 * h_stack.h — 栈操作指令 handler
 *
 * PUSH Xn  [2B: op | n]   将 R[n] 压入操作栈
 * POP  Xn  [2B: op | n]   从操作栈弹出到 R[n]
 */
#ifndef H_STACK_H
#define H_STACK_H

#include "../vm_types.h"

/* PUSH Xn */
static inline u32 h_push(vm_ctx_t *vm) {
  u8 r = vm->bc[vm->pc + 1];
  if (vm->sp < VM_STACK_SIZE)
    vm->stk[vm->sp++] = vm->R[r & 31];
  return 2;
}

/* POP Xn */
static inline u32 h_pop(vm_ctx_t *vm) {
  u8 r = vm->bc[vm->pc + 1];
  if (vm->sp > 0)
    vm->R[r & 31] = vm->stk[--vm->sp];
  return 2;
}

#endif /* H_STACK_H */
