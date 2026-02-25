/*
 * vm_decode.h — 字节码读取工具函数
 *
 * 小端读取: 从字节码流中读取 16/32/64 位值。
 */
#ifndef VM_DECODE_H
#define VM_DECODE_H

#include "vm_types.h"

static inline u16 rd16(const u8 *p) { return (u16)p[0] | ((u16)p[1] << 8); }

static inline u32 rd32(const u8 *p) {
  return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

static inline u64 rd64(const u8 *p) {
  return (u64)rd32(p) | ((u64)rd32(p + 4) << 32);
}

#endif /* VM_DECODE_H */
