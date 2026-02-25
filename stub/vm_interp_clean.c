/*
 * vm_interp_clean.c — 模块化 VM 解释器 (ARM64 PIC blob)
 *
 * 架构:
 *   vm_types.h       → 类型 + vm_ctx_t 结构体
 *   vm_opcodes.h     → 操作码定义
 *   vm_decode.h      → 字节码读取工具
 *   vm_handlers/*.h  → 分模块指令 handler
 *
 * 编译 (交叉编译为 blob):
 *   aarch64-linux-gnu-gcc -c -Os -mcmodel=tiny -fno-stack-protector \
 *     -fno-builtin -nostdlib -march=armv8-a vm_interp_clean.c -o
 * vm_interp_clean.o
 */

/* ---- 基础设施 ---- */
#include "vm_decode.h"
#include "vm_opcodes.h"
#include "vm_types.h"

/* ---- 指令 Handler 模块 ---- */
#include "vm_handlers/h_alu.h" /* ADD/SUB/MUL/XOR/AND/OR/SHL/SHR/ASR/NOT/ROR + _IMM */
#include "vm_handlers/h_branch.h" /* JMP/JE/JNE/JL/JGE/JGT/JLE/JB/JAE */
#include "vm_handlers/h_cmp.h"    /* CMP, CMP_IMM */
#include "vm_handlers/h_mem.h"    /* LOAD/STORE 8/32/64 */
#include "vm_handlers/h_mov.h"    /* MOV_IMM, MOV_IMM32, MOV_REG */
#include "vm_handlers/h_stack.h"  /* PUSH, POP */

/* ---- DEBUG: syscall-based output (取消注释以启用) ---- */
static inline void dbg_write(const char *s, unsigned len) {
  register long x8 __asm__("x8") = 64; /* __NR_write */
  register long x0 __asm__("x0") = 2;  /* stderr */
  register long x1 __asm__("x1") = (long)s;
  register long x2r __asm__("x2") = len;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2r) : "memory");
}
static void dbg_hex(const char *prefix, u64 val) {
  char buf[32];
  int i = 0;
  for (const char *p = prefix; *p && i < 16; p++)
    buf[i++] = *p;
  for (int s = 60; s >= 0; s -= 4) {
    int d = (val >> s) & 0xF;
    buf[i++] = d < 10 ? '0' + d : 'a' + d - 10;
  }
  buf[i++] = '\n';
  dbg_write(buf, i);
}

/* h_system.h must be after dbg_hex (used by h_br_reg debug path) */
#include "vm_handlers/h_system.h" /* NOP, CALL_NAT, BR_REG, VLD16, VST16 */

/* ---- syscall: mmap (无 libc 依赖) ---- */
static inline void *sys_mmap(unsigned long size) {
  register long x8 __asm__("x8") = 222; /* __NR_mmap */
  register long x0 __asm__("x0") = 0;   /* addr = NULL */
  register long x1 __asm__("x1") = (long)size;
  register long x2 __asm__("x2") = 3;    /* PROT_READ | PROT_WRITE */
  register long x3 __asm__("x3") = 0x22; /* MAP_PRIVATE | MAP_ANONYMOUS */
  register long x4 __asm__("x4") = -1;   /* fd = -1 */
  register long x5 __asm__("x5") = 0;    /* offset = 0 */
  __asm__ volatile("svc #0"
                   : "+r"(x0)
                   : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                   : "memory");
  return (void *)x0;
}

/* ---- syscall: munmap ---- */
static inline void sys_munmap(void *addr, unsigned long size) {
  register long x8 __asm__("x8") = 215; /* __NR_munmap */
  register long x0 __asm__("x0") = (long)addr;
  register long x1 __asm__("x1") = (long)size;
  __asm__ volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1) : "memory");
}

/*
 * vm_entry — VM 解释器入口
 *
 * 参数:
 *   args    : 指向保存的 X0-X7, callerFP, callerLR (共10个u64)
 *   enc_bc  : XOR 加密的字节码
 *   bc_len  : 字节码长度
 *   xor_key : XOR 解密密钥
 *
 * 返回: R[0] (模拟 X0 返回值)
 */
__attribute__((section(".text.entry"))) u64 vm_entry(u64 *args, u8 *enc_bc,
                                                     u32 bc_len, u8 xor_key) {
  u64 ret = 0;

  /* ---- 1. 动态分配字节码缓冲区 (mmap, 替代栈上 64KB) ---- */
  if (bc_len > VM_BYTECODE_MAX)
    bc_len = VM_BYTECODE_MAX;
  u32 alloc_size = (bc_len + 4095u) & ~4095u; /* 页对齐向上取整 */
  u8 *bc_buf = (u8 *)sys_mmap(alloc_size);
  if ((long)bc_buf < 0)
    return 0; /* mmap 失败, 安全退出 */

  /* ---- 1b. XOR 解密 (8 字节加宽, ~8x 加速) ---- */
  u64 xk8 = (u64)xor_key;
  xk8 |= xk8 << 8;
  xk8 |= xk8 << 16;
  xk8 |= xk8 << 32;
  {
    u32 n8 = bc_len >> 3;
    u64 *d8 = (u64 *)bc_buf;
    const u64 *s8 = (const u64 *)enc_bc;
    for (u32 i = 0; i < n8; i++)
      d8[i] = s8[i] ^ xk8;
    for (u32 i = n8 << 3; i < bc_len; i++)
      bc_buf[i] = enc_bc[i] ^ xor_key;
  }

  /* ---- 2. 初始化 VM 上下文 ---- */
  vm_ctx_t vm;
  vm_ctx_init(&vm, args, bc_buf, bc_len);

  /* ---- 2b. 解析字节码尾部映射表 (BR 间接跳转支持) ---- */
  /* 尾部格式: [...bytecode...][map entries][map_count:u32]
   *           [func_addr:u64][func_size:u32] */
  if (bc_len >= 16) {
    u32 trail_func_size = rd32(&bc_buf[bc_len - 4]);
    u64 trail_func_addr = rd64(&bc_buf[bc_len - 12]);
    u32 trail_map_count = rd32(&bc_buf[bc_len - 16]);
    u32 map_data_size = trail_map_count * 8 + 16;
    if (trail_func_addr != 0 && trail_map_count > 0 &&
        map_data_size <= bc_len) {
      vm.func_addr = trail_func_addr;
      vm.func_size = trail_func_size;
      vm.map_count = trail_map_count;
      vm.addr_map = (addr_map_entry_t *)&bc_buf[bc_len - map_data_size];
      vm.bc_len = bc_len - map_data_size; /* 实际字节码不含映射表 */

      /* 插入排序 addr_map (按 arm64_off 升序, 为二分查找准备) */
      /* 注: 使用字段级拷贝避免编译器生成隐式 memcpy (-nostdlib) */
      for (u32 j = 1; j < vm.map_count; j++) {
        u32 t_arm = vm.addr_map[j].arm64_off;
        u32 t_vm = vm.addr_map[j].vm_off;
        int k = (int)j - 1;
        while (k >= 0 && vm.addr_map[k].arm64_off > t_arm) {
          vm.addr_map[k + 1].arm64_off = vm.addr_map[k].arm64_off;
          vm.addr_map[k + 1].vm_off = vm.addr_map[k].vm_off;
          k--;
        }
        vm.addr_map[k + 1].arm64_off = t_arm;
        vm.addr_map[k + 1].vm_off = t_vm;
      }
    }
  }

  /* ---- 3. Computed goto 分发表 (替代 switch-case, ~20-30% 加速) ---- */
  /* GCC 扩展: &&label 获取标签地址, goto *ptr 跳转 */
  /* 注: 使用循环填充默认值避免 [0...255] 范围初始化生成隐式 memcpy */
  const void *dtab[256];
  for (int _i = 0; _i < 256; _i++)
    dtab[_i] = &&L_UNKNOWN;
  /* 系统 */
  dtab[OP_NOP] = &&L_NOP;
  dtab[OP_HALT] = &&L_HALT;
  dtab[OP_RET] = &&L_RET;
  /* 数据移动 */
  dtab[OP_MOV_IMM] = &&L_MOV_IMM;
  dtab[OP_MOV_IMM32] = &&L_MOV_IMM32;
  dtab[OP_MOV_REG] = &&L_MOV_REG;
  /* 内存 */
  dtab[OP_LOAD8] = &&L_LOAD8;
  dtab[OP_LOAD32] = &&L_LOAD32;
  dtab[OP_LOAD64] = &&L_LOAD64;
  dtab[OP_STORE8] = &&L_STORE8;
  dtab[OP_STORE32] = &&L_STORE32;
  dtab[OP_STORE64] = &&L_STORE64;
  /* ALU 三寄存器 */
  dtab[OP_ADD] = &&L_ADD;
  dtab[OP_SUB] = &&L_SUB;
  dtab[OP_MUL] = &&L_MUL;
  dtab[OP_XOR] = &&L_XOR;
  dtab[OP_AND] = &&L_AND;
  dtab[OP_OR] = &&L_OR;
  dtab[OP_SHL] = &&L_SHL;
  dtab[OP_SHR] = &&L_SHR;
  dtab[OP_ASR] = &&L_ASR;
  dtab[OP_NOT] = &&L_NOT;
  dtab[OP_ROR] = &&L_ROR;
  /* ALU 立即数 */
  dtab[OP_ADD_IMM] = &&L_ADD_IMM;
  dtab[OP_SUB_IMM] = &&L_SUB_IMM;
  dtab[OP_XOR_IMM] = &&L_XOR_IMM;
  dtab[OP_AND_IMM] = &&L_AND_IMM;
  dtab[OP_OR_IMM] = &&L_OR_IMM;
  dtab[OP_MUL_IMM] = &&L_MUL_IMM;
  dtab[OP_SHL_IMM] = &&L_SHL_IMM;
  dtab[OP_SHR_IMM] = &&L_SHR_IMM;
  dtab[OP_ASR_IMM] = &&L_ASR_IMM;
  /* 比较 */
  dtab[OP_CMP] = &&L_CMP;
  dtab[OP_CMP_IMM] = &&L_CMP_IMM;
  /* 分支 */
  dtab[OP_JMP] = &&L_JMP;
  dtab[OP_JE] = &&L_JE;
  dtab[OP_JNE] = &&L_JNE;
  dtab[OP_JL] = &&L_JL;
  dtab[OP_JGE] = &&L_JGE;
  dtab[OP_JGT] = &&L_JGT;
  dtab[OP_JLE] = &&L_JLE;
  dtab[OP_JB] = &&L_JB;
  dtab[OP_JAE] = &&L_JAE;
  /* 栈操作 */
  dtab[OP_PUSH] = &&L_PUSH;
  dtab[OP_POP] = &&L_POP;
  /* 原生调用 */
  dtab[OP_CALL_NAT] = &&L_CALL_NAT;
  dtab[OP_CALL_REG] = &&L_CALL_REG;
  dtab[OP_BR_REG] = &&L_BR_REG;
  /* SIMD */
  dtab[OP_VLD16] = &&L_VLD16;
  dtab[OP_VST16] = &&L_VST16;

/* 分发宏 */
#define DISPATCH()                                                             \
  do {                                                                         \
    if (__builtin_expect(vm.pc >= vm.bc_len, 0))                               \
      goto cleanup;                                                            \
    goto *dtab[vm.bc[vm.pc]];                                                  \
  } while (0)

#define NEXT(n)                                                                \
  do {                                                                         \
    vm.pc += (n);                                                              \
    DISPATCH();                                                                \
  } while (0)
#define NEXT0() DISPATCH() /* handler 已设置 pc */

  /* ---- 开始执行 ---- */
  DISPATCH();

/* ---- 系统 ---- */
L_NOP:
  NEXT(h_nop(&vm));
L_HALT:
  ret = vm.R[0];
  goto cleanup;
L_RET: {
  u8 r = vm.bc[vm.pc + 1];
  ret = vm.R[r & 31];
  goto cleanup;
}

/* ---- 数据移动 ---- */
L_MOV_IMM:
  NEXT(h_mov_imm(&vm));
L_MOV_IMM32:
  NEXT(h_mov_imm32(&vm));
L_MOV_REG:
  NEXT(h_mov_reg(&vm));

/* ---- 内存访问 ---- */
L_LOAD8:
  NEXT(h_load8(&vm));
L_LOAD32:
  NEXT(h_load32(&vm));
L_LOAD64:
  NEXT(h_load64(&vm));
L_STORE8:
  NEXT(h_store8(&vm));
L_STORE32:
  NEXT(h_store32(&vm));
L_STORE64:
  NEXT(h_store64(&vm));

/* ---- ALU 三寄存器 ---- */
L_ADD:
  NEXT(h_add(&vm));
L_SUB:
  NEXT(h_sub(&vm));
L_MUL:
  NEXT(h_mul(&vm));
L_XOR:
  NEXT(h_xor(&vm));
L_AND:
  NEXT(h_and(&vm));
L_OR:
  NEXT(h_or(&vm));
L_SHL:
  NEXT(h_shl(&vm));
L_SHR:
  NEXT(h_shr(&vm));
L_ASR:
  NEXT(h_asr(&vm));
L_NOT:
  NEXT(h_not(&vm));
L_ROR:
  NEXT(h_ror(&vm));

/* ---- ALU 立即数 ---- */
L_ADD_IMM:
  NEXT(h_add_imm(&vm));
L_SUB_IMM:
  NEXT(h_sub_imm(&vm));
L_XOR_IMM:
  NEXT(h_xor_imm(&vm));
L_AND_IMM:
  NEXT(h_and_imm(&vm));
L_OR_IMM:
  NEXT(h_or_imm(&vm));
L_MUL_IMM:
  NEXT(h_mul_imm(&vm));
L_SHL_IMM:
  NEXT(h_shl_imm(&vm));
L_SHR_IMM:
  NEXT(h_shr_imm(&vm));
L_ASR_IMM:
  NEXT(h_asr_imm(&vm));

/* ---- 比较 ---- */
L_CMP:
  NEXT(h_cmp(&vm));
L_CMP_IMM:
  NEXT(h_cmp_imm(&vm));

/* ---- 分支 (handler 返回 0, 已设置 pc) ---- */
L_JMP:
  h_jmp(&vm);
  NEXT0();
L_JE:
  h_je(&vm);
  NEXT0();
L_JNE:
  h_jne(&vm);
  NEXT0();
L_JL:
  h_jl(&vm);
  NEXT0();
L_JGE:
  h_jge(&vm);
  NEXT0();
L_JGT:
  h_jgt(&vm);
  NEXT0();
L_JLE:
  h_jle(&vm);
  NEXT0();
L_JB:
  h_jb(&vm);
  NEXT0();
L_JAE:
  h_jae(&vm);
  NEXT0();

/* ---- 栈操作 ---- */
L_PUSH:
  NEXT(h_push(&vm));
L_POP:
  NEXT(h_pop(&vm));

/* ---- 原生调用 ---- */
L_CALL_NAT:
  NEXT(h_call_nat(&vm));
L_CALL_REG:
  NEXT(h_call_reg(&vm));
L_BR_REG: {
  u32 a = h_br_reg(&vm);
  if (a)
    NEXT(a);
  else
    NEXT0();
}

/* ---- SIMD ---- */
L_VLD16:
  NEXT(h_vld16(&vm));
L_VST16:
  NEXT(h_vst16(&vm));

/* ---- 未知指令 ---- */
L_UNKNOWN:
  ret = vm.R[0]; /* fall through to cleanup */

  /* ---- 统一退出: 释放 mmap 防止泄漏 ---- */
cleanup:
  sys_munmap(bc_buf, alloc_size);
  return ret;

#undef DISPATCH
#undef NEXT
#undef NEXT0
}
