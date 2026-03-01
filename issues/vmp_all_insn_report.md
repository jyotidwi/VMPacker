# VMP 全指令覆盖测试报告

## 概述

针对 ARM64 VMP 引擎编写了全指令覆盖测试程序 `demo/demo_all_insn.c`，覆盖所有已支持的 ARM64 指令，验证 VMP 翻译和解释器的正确性。

## 测试结果

| 版本 | 结果 | 说明 |
|------|------|------|
| 原始二进制 | 19/19 PASS ✅ | 基准对照 |
| 单函数 VMP (check_all_insn) | 19/19 PASS ✅ | 仅入口函数虚拟化 |
| 全函数 VMP (21 functions) | 19/19 PASS ✅ | 所有测试函数虚拟化 |

## 覆盖指令清单 (19 组)

| # | 测试组 | 覆盖指令 |
|---|--------|----------|
| 1 | ALU 寄存器 | ADD SUB MUL EOR AND ORR LSL LSR ASR MVN ROR UMULH |
| 2 | ALU 立即数 | ADD SUB AND ORR EOR LSL LSR ASR + CMP CMN TST |
| 3 | MOV 系列 | MOVZ MOVK MOVN |
| 4 | 加载/存储 | LDR STR LDRB STRB LDRH STRH LDRSB LDRSH LDRSW STP LDP |
| 5 | 寄存器偏移加载/存储 | LDR_REG LDRB_REG STR_REG STRB_REG |
| 6 | 分支 | B B.cond CBZ CBNZ |
| 7 | 条件选择 | CSEL CSINC CSINV CSNEG |
| 8 | 乘加/乘减 | MADD MSUB |
| 9 | 位域 | UBFM SBFM EXTR |
| 10 | 扩展寄存器加减 | ADD_EXT SUB_EXT SUBS_EXT |
| 11 | EON | EON |
| 12 | 测试位分支 | TBZ TBNZ |
| 13 | 条件比较 | CCMP CCMN (reg + imm) |
| 14 | 地址计算 | ADRP ADR (全局变量访问) |
| 15 | SIMD | LD1/ST1 16B |
| 16 | 系统调用 | SVC (write syscall) |
| 17 | 标志位寄存器 | ADDS SUBS CMP CMN TST (register) |
| 18 | EOR shifted | EOR shifted register |
| 19 | 函数调用 | BL BLR |

## VMP 保护的函数 (21 个)

`test_alu_reg` `test_alu_imm` `test_mov` `test_load_store` `test_load_store_reg` `test_branch` `test_csel` `test_madd_msub` `test_bitfield` `test_add_sub_ext` `test_eon` `test_tbz_tbnz` `test_ccmp_ccmn` `test_adrp_adr` `test_simd` `test_svc` `test_flags_reg` `test_eor_shifted` `helper_add` `test_bl_blr` `check_all_insn`


## 修复的 Bug

### 1. ROR 测试值构造错误
- 位置: `demo/demo_all_insn.c` → `test_alu_reg`
- 问题: `mov x15, #0x8000` + 多个 `movk` 导致低16位污染为 `0x8000000000008000`
- 修复: 改用 `movz x15, #0x8000, lsl #48` → 正确得到 `0x8000000000000000`

### 2. CMN 寄存器翻译错误 (本次修复)
- 位置: `pkg/arch/arm64/translator.go` → `translateOne()` ADDS_REG + Rd==XZR 分支
- 问题: CMN (ADDS XZR, Xn, Xm) 被错误翻译为 `OpCmp rn, rm`（减法比较）
- 正确行为: CMN 应计算 `Rn + Rm` 然后与 0 比较设置标志位
- 修复: 区分 ADDS_REG 和 SUBS_REG 的 XZR 情况
  - SUBS_REG + XZR = CMP → `OpCmp rn, rm` (不变)
  - ADDS_REG + XZR = CMN → `OpAdd R15, rn, rm` + `OpCmpImm R15, #0`

## 文件清单

| 文件 | 说明 |
|------|------|
| `demo/demo_all_insn.c` | 全指令覆盖测试源码 |
| `build/demo_all_insn` | 编译后原始二进制 |
| `build/demo_all_insn.vmp` | 单函数 VMP 版本 |
| `build/demo_all_insn_full.vmp` | 全函数 VMP 版本 (21 functions) |
| `test_vmp_all_insn.sh` | 自动化测试脚本 |
| `pkg/arch/arm64/translator.go` | CMN bug 修复位置 |

## 编译和测试命令

```bash
# 编译
aarch64-linux-gnu-gcc -static -O0 -march=armv8-a demo/demo_all_insn.c -o build/demo_all_insn

# VMP 保护 (全函数)
build/vmpacker.exe -func "test_alu_reg,test_alu_imm,test_mov,test_load_store,test_load_store_reg,test_branch,test_csel,test_madd_msub,test_bitfield,test_add_sub_ext,test_eon,test_tbz_tbnz,test_ccmp_ccmn,test_adrp_adr,test_simd,test_svc,test_flags_reg,test_eor_shifted,helper_add,test_bl_blr,check_all_insn" -v -o build/demo_all_insn_full.vmp build/demo_all_insn

# 推送并运行
adb push build/demo_all_insn_full.vmp /home/root/vmp/
adb shell "chmod +x /home/root/vmp/demo_all_insn_full.vmp"
adb shell "/home/root/vmp/demo_all_insn_full.vmp"

# 或使用一键脚本
bash test_vmp_all_insn.sh
```
