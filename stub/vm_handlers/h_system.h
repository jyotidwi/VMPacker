/*
 * h_system.h — 系统/特殊指令 handler
 *
 * NOP / HALT / RET / CALL_NAT / VLD16 / VST16
 */
#ifndef H_SYSTEM_H
#define H_SYSTEM_H

#include "../vm_decode.h"
#include "../vm_types.h"


/* NOP  [1B] */
static inline u32 h_nop(vm_ctx_t *vm) {
  (void)vm;
  return 1;
}

/* CALL_NAT: BLR 绝对地址调用  [9B: op | addr64] */
static inline u32 h_call_nat(vm_ctx_t *vm) {
  u64 addr = rd64(&vm->bc[vm->pc + 1]);
  native_fn_t fn = (native_fn_t)addr;
  vm->R[0] = fn(vm->R[0], vm->R[1], vm->R[2], vm->R[3], vm->R[4], vm->R[5],
                vm->R[6], vm->R[7]);
  return 9;
}

/* VLD16: LD1 {Vn.16B}, [Xn]  [3B: op | rn | len] */
static inline u32 h_vld16(vm_ctx_t *vm) {
  u8 rn = vm->bc[vm->pc + 1];
  u8 len = vm->bc[vm->pc + 2];
  const u8 *src = (const u8 *)vm->R[rn & 31];
  for (int i = 0; i < len && i < VM_SIMD_BUF; i++)
    vm->vtmp[i] = src[i];
  return 3;
}

/* VST16: ST1 {Vn.16B}, [Xn]  [3B: op | rn | len] */
static inline u32 h_vst16(vm_ctx_t *vm) {
  u8 rn = vm->bc[vm->pc + 1];
  u8 len = vm->bc[vm->pc + 2];
  u8 *dst = (u8 *)vm->R[rn & 31];
  for (int i = 0; i < len && i < VM_SIMD_BUF; i++)
    dst[i] = vm->vtmp[i];
  return 3;
}

#endif /* H_SYSTEM_H */
