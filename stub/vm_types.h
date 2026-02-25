/*
 * vm_types.h — VM 类型定义 + CPU 上下文结构体
 *
 * 所有 VM 状态封装在 vm_ctx_t 中，方便传递和扩展。
 */
#ifndef VM_TYPES_H
#define VM_TYPES_H

/* ---- 基础类型 ---- */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef long long i64;

/* ---- VM 配置常量 ---- */
#define VM_REG_COUNT 32      /* X0-X30, X31=SP */
#define VM_STACK_SIZE 32     /* PUSH/POP 操作栈深度 */
#define VM_MEM_STACK 512     /* 内存栈 (SP 指向的空间) */
#define VM_BYTECODE_MAX 4096 /* 最大字节码长度 */
#define VM_SIMD_BUF 64       /* SIMD 临时缓冲大小 */

/* ---- 标志位 (NZCV 简化) ---- */
#define FL_ZERO 1  /* Z: 结果为零 */
#define FL_SIGN 2  /* N: 有符号小于 */
#define FL_CARRY 4 /* C: 无符号小于 */

/* ---- 原生函数指针类型 ---- */
typedef u64 (*native_fn_t)(u64, u64, u64, u64, u64, u64, u64, u64);

/* ---- VM CPU 上下文 ---- */
typedef struct {
  /* 寄存器文件: R[0]-R[30] = X0-X30, R[31] = SP */
  u64 R[VM_REG_COUNT];

  /* 条件标志 */
  u32 FL;

  /* 虚拟程序计数器 */
  u32 pc;

  /* 字节码 (解密后) */
  u8 *bc;
  u32 bc_len;

  /* PUSH/POP 操作栈 */
  u64 stk[VM_STACK_SIZE];
  int sp;

  /* 内存栈 (R[31] 指向这里的末尾) */
  u8 vm_stk[VM_MEM_STACK];

  /* SIMD 临时缓冲 */
  u8 vtmp[VM_SIMD_BUF];
} vm_ctx_t;

/* ---- VM 初始化 ---- */
static inline void vm_ctx_init(vm_ctx_t *vm, u64 arg0, u64 arg1, u8 *bytecode,
                               u32 len, u64 caller_fp, u64 caller_lr) {
  /* 清零所有寄存器 */
  for (int i = 0; i < VM_REG_COUNT; i++)
    vm->R[i] = 0;

  /* 设置参数寄存器 */
  vm->R[0] = arg0;       /* X0 = 第一个参数 */
  vm->R[1] = arg1;       /* X1 = 第二个参数 */
  vm->R[29] = caller_fp; /* X29 = FP */
  vm->R[30] = caller_lr; /* X30 = LR */

  /* SP 指向内存栈顶 */
  vm->R[31] = (u64)&vm->vm_stk[VM_MEM_STACK];

  /* 字节码 */
  vm->bc = bytecode;
  vm->bc_len = len;

  /* 状态初始化 */
  vm->FL = 0;
  vm->pc = 0;
  vm->sp = 0;
}

#endif /* VM_TYPES_H */
