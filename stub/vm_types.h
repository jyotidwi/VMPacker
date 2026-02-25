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
typedef short i16;

/* ---- VM 配置常量 ---- */
#define VM_REG_COUNT 32       /* X0-X30, X31=SP */
#define VM_STACK_SIZE 32      /* PUSH/POP 操作栈深度 */
#define VM_MEM_STACK 4096     /* 内存栈 (SP 指向的空间, 4KB) */
#define VM_BYTECODE_MAX 65536 /* 最大字节码长度 (64KB, 含映射表) */
#define VM_SIMD_BUF 64        /* SIMD 临时缓冲大小 */

/* ---- 标志位 (NZCV 简化) ---- */
#define FL_ZERO 1  /* Z: 结果为零 */
#define FL_SIGN 2  /* N: 有符号小于 */
#define FL_CARRY 4 /* C: 无符号小于 */

/* ---- 原生函数指针类型 ---- */
typedef u64 (*native_fn_t)(u64, u64, u64, u64, u64, u64, u64, u64);

/* ---- BR 间接跳转映射表条目 ---- */
typedef struct {
  u32 arm64_off; /* ARM64 函数内偏移 */
  u32 vm_off;    /* 对应的 VM 字节码偏移 */
} addr_map_entry_t;

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

  /* BR 间接跳转支持 */
  u64 func_addr;              /* 被保护函数的原始起始地址 */
  u32 func_size;              /* 被保护函数的大小 */
  addr_map_entry_t *addr_map; /* ARM64偏移→VM偏移 映射表 */
  u32 map_count;              /* 映射表条目数 */
} vm_ctx_t;

/* ---- VM 初始化 ---- */
static inline void vm_ctx_init(vm_ctx_t *vm, u64 *args, u8 *bytecode, u32 len) {
  /* 清零所有寄存器 */
  for (int i = 0; i < VM_REG_COUNT; i++)
    vm->R[i] = 0;

  /* 从 args 指针恢复参数寄存器 X0-X7 */
  for (int i = 0; i < 8; i++)
    vm->R[i] = args[i];

  vm->R[29] = args[8]; /* X29 = caller FP */
  vm->R[30] = args[9]; /* X30 = caller LR */

  /* SP 指向内存栈顶 */
  vm->R[31] = (u64)&vm->vm_stk[VM_MEM_STACK];

  /* 字节码 */
  vm->bc = bytecode;
  vm->bc_len = len;

  /* 状态初始化 */
  vm->FL = 0;
  vm->pc = 0;
  vm->sp = 0;

  /* BR 间接跳转映射表：默认无 */
  vm->func_addr = 0;
  vm->func_size = 0;
  vm->addr_map = 0;
  vm->map_count = 0;
}

#endif /* VM_TYPES_H */
