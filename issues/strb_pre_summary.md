# T2: STURB (Byte Store, Unscaled Offset) — 实现总结

> 日期：2026-03-01
> 类型：纯组合路径（复用现有 STRB_IMM opcode）

## 指令说明

| 字段 | 值 |
|------|-----|
| 原始 raw | `0x381FF260` |
| 实际指令 | STURB W0, [X19, #-1]（unscaled offset, bits[11:10]=00）|
| 注意 | 原 tasks.md 描述为 "STRB pre-index"，实际编码是 STURB（unscaled offset）|
| 解码模式 | `decode_ldst.go` 中已有 STURB 模式：Mask=0xFFE00C00, Value=0x38000000 |
| 翻译路径 | STRB_IMM → trStore → STORE8 |

## 实现方式

STURB 已在现有代码中完整支持：
- **解码器**：`decode_ldst.go` 的 STURB 模式匹配 unscaled offset 编码
- **翻译器**：`translator.go` 中 STRB_IMM case → `tr_loadstore.go` 的 trStore 函数
- **C 解释器**：复用现有 STORE8 handler，无需新增 opcode

无需任何代码修改，属于纯验证任务。

## Demo 测试程序

`demo/demo_insn_strb_pre.c` 覆盖 4 种 STURB 偏移场景：

| 测试 | 编码 | 操作 | 目标 |
|------|------|------|------|
| Test 1 | `0x38000020` | STURB W0, [X1, #0] | buf[16] = 0xAB |
| Test 2 | `0x381FF020` | STURB W0, [X1, #-1] | buf[15] = 0xCD |
| Test 3 | `0x38001020` | STURB W0, [X1, #1] | buf[17] = 0xEF |
| Test 4 | `0x38002020` | STURB W0, [X1, #2] | buf[18] = 0x42 |

期望结果：`0xCDABEF42`

## 测试结果

| 模式 | 结果 | 输出 |
|------|------|------|
| Native (ARM64) | ✅ PASS | `STRB_PRE PASS (result=0xCDABEF42)` |
| VMP Standard | ✅ PASS | `STRB_PRE PASS (result=0xCDABEF42)` |
| VMP Token | ✅ PASS | `STRB_PRE PASS (result=0xCDABEF42)` |

翻译统计：46/46 指令全部翻译成功，字节码 606 bytes。

## 文件变更

| 文件 | 变更 |
|------|------|
| `demo/demo_insn_strb_pre.c` | 新增 — STURB 测试程序 |
| `test_vmp_insn_strb_pre.sh` | 新增 — 自动化测试脚本 |
| `issues/strb_pre_summary.md` | 新增 — 本文档 |

无 Go/C 代码修改（纯组合路径）。
