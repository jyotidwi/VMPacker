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
 *
 * 测试 (x86/x64 本地编译):
 *   gcc -D__USE_MINGW_ANSI_STDIO=1 vm_test.c -o vm_test && ./vm_test
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
#include "vm_handlers/h_system.h" /* NOP, CALL_NAT, VLD16, VST16 */


/*
 * vm_entry — VM 解释器入口
 *
 * 参数:
 *   arg0, arg1  : 原始函数的前两个参数 (X0, X1)
 *   enc_bc      : XOR 加密的字节码
 *   bc_len      : 字节码长度
 *   xor_key     : XOR 解密密钥
 *   real_sp     : 调用者的真实 SP (未使用, 保留)
 *   caller_fp   : 调用者的 FP (X29)
 *   caller_lr   : 调用者的 LR (X30)
 *
 * 返回:
 *   R[0] 的值 (模拟 X0 返回值)
 */
u64 vm_entry(u64 arg0, u64 arg1, u8 *enc_bc, u32 bc_len, u8 xor_key,
             u64 real_sp, u64 caller_fp, u64 caller_lr) {

  (void)real_sp; /* 保留参数, 暂不使用 */

  /* ---- 1. 解密字节码 ---- */
  u8 bc_buf[VM_BYTECODE_MAX];
  if (bc_len > VM_BYTECODE_MAX)
    bc_len = VM_BYTECODE_MAX;
  for (u32 i = 0; i < bc_len; i++)
    bc_buf[i] = enc_bc[i] ^ xor_key;

  /* ---- 2. 初始化 VM 上下文 ---- */
  vm_ctx_t vm;
  vm_ctx_init(&vm, arg0, arg1, bc_buf, bc_len, caller_fp, caller_lr);

  /* ---- 3. 主循环: switch-case 分发到模块 handler ---- */
  while (vm.pc < vm.bc_len) {
    u32 adv = 0;

    switch (vm.bc[vm.pc]) {

    /* ---- 系统 ---- */
    case OP_NOP:
      adv = h_nop(&vm);
      break;
    case OP_HALT:
      return vm.R[0];
    case OP_RET: { /* RET Xn: 需要 return, 不能委托handler */
      u8 r = vm.bc[vm.pc + 1];
      return vm.R[r & 31];
    }

    /* ---- 数据移动 ---- */
    case OP_MOV_IMM:
      adv = h_mov_imm(&vm);
      break;
    case OP_MOV_IMM32:
      adv = h_mov_imm32(&vm);
      break;
    case OP_MOV_REG:
      adv = h_mov_reg(&vm);
      break;

    /* ---- 内存访问 ---- */
    case OP_LOAD8:
      adv = h_load8(&vm);
      break;
    case OP_LOAD32:
      adv = h_load32(&vm);
      break;
    case OP_LOAD64:
      adv = h_load64(&vm);
      break;
    case OP_STORE8:
      adv = h_store8(&vm);
      break;
    case OP_STORE32:
      adv = h_store32(&vm);
      break;
    case OP_STORE64:
      adv = h_store64(&vm);
      break;

    /* ---- 算术/逻辑 (三寄存器) ---- */
    case OP_ADD:
      adv = h_add(&vm);
      break;
    case OP_SUB:
      adv = h_sub(&vm);
      break;
    case OP_MUL:
      adv = h_mul(&vm);
      break;
    case OP_XOR:
      adv = h_xor(&vm);
      break;
    case OP_AND:
      adv = h_and(&vm);
      break;
    case OP_OR:
      adv = h_or(&vm);
      break;
    case OP_SHL:
      adv = h_shl(&vm);
      break;
    case OP_SHR:
      adv = h_shr(&vm);
      break;
    case OP_ASR:
      adv = h_asr(&vm);
      break;
    case OP_NOT:
      adv = h_not(&vm);
      break;
    case OP_ROR:
      adv = h_ror(&vm);
      break;

    /* ---- 算术/逻辑 (寄存器 + 立即数) ---- */
    case OP_ADD_IMM:
      adv = h_add_imm(&vm);
      break;
    case OP_SUB_IMM:
      adv = h_sub_imm(&vm);
      break;
    case OP_XOR_IMM:
      adv = h_xor_imm(&vm);
      break;
    case OP_AND_IMM:
      adv = h_and_imm(&vm);
      break;
    case OP_OR_IMM:
      adv = h_or_imm(&vm);
      break;
    case OP_MUL_IMM:
      adv = h_mul_imm(&vm);
      break;
    case OP_SHL_IMM:
      adv = h_shl_imm(&vm);
      break;
    case OP_SHR_IMM:
      adv = h_shr_imm(&vm);
      break;
    case OP_ASR_IMM:
      adv = h_asr_imm(&vm);
      break;

    /* ---- 比较 ---- */
    case OP_CMP:
      adv = h_cmp(&vm);
      break;
    case OP_CMP_IMM:
      adv = h_cmp_imm(&vm);
      break;

    /* ---- 分支 (handler 直接设置 pc, 返回 0) ---- */
    case OP_JMP:
      adv = h_jmp(&vm);
      break;
    case OP_JE:
      adv = h_je(&vm);
      break;
    case OP_JNE:
      adv = h_jne(&vm);
      break;
    case OP_JL:
      adv = h_jl(&vm);
      break;
    case OP_JGE:
      adv = h_jge(&vm);
      break;
    case OP_JGT:
      adv = h_jgt(&vm);
      break;
    case OP_JLE:
      adv = h_jle(&vm);
      break;
    case OP_JB:
      adv = h_jb(&vm);
      break;
    case OP_JAE:
      adv = h_jae(&vm);
      break;

    /* ---- 栈操作 ---- */
    case OP_PUSH:
      adv = h_push(&vm);
      break;
    case OP_POP:
      adv = h_pop(&vm);
      break;

    /* ---- 原生调用 ---- */
    case OP_CALL_NAT:
      adv = h_call_nat(&vm);
      break;

    /* ---- SIMD ---- */
    case OP_VLD16:
      adv = h_vld16(&vm);
      break;
    case OP_VST16:
      adv = h_vst16(&vm);
      break;

    /* ---- 未知指令: 跳过 ---- */
    default:
      adv = 1;
      break;
    }

    if (adv)
      vm.pc += adv;
  }

  return vm.R[0];
}
