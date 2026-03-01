# T1: EOR shifted register (LSR/ASR/ROR) — 实现总结

## 基本信息

| 项目 | 内容 |
|------|------|
| 指令名称 | EOR shifted register (LSR/ASR/ROR 移位变体) |
| 实现路径 | **纯组合**（无新增 VM Opcode） |
| 状态 | ✅ PASS |

## 编码变体

| 变体 | 示例编码 | 说明 |
|------|---------|------|
| EOR with LSL | `eor Wd, Wn, Wm, lsl #imm` | 已有支持（对照） |
| EOR with LSR | `eor Wd, Wn, Wm, lsr #imm` | 本次新增 |
| EOR with ASR | `eor Wd, Wn, Wm, asr #imm` | 本次新增 |
| EOR with ROR | `eor Wd, Wn, Wm, ror #imm` | 本次新增 |
| AND with LSR/ASR/ROR | `and Wd, Wn, Wm, {lsr/asr/ror} #imm` | 同步支持 |
| ORR with LSR/ASR/ROR | `orr Wd, Wn, Wm, {lsr/asr/ror} #imm` | 同步支持 |

## 修改文件清单

| 文件 | 修改内容 |
|------|---------|
| `pkg/arch/arm64/decode_dp_reg.go` | `postShiftedXZR3` 已支持所有 shift type（LSL/LSR/ASR/ROR） |
| `pkg/arch/arm64/tr_alu.go` | `trAluReg` 已支持 LSL/LSR/ASR/ROR 四种移位翻译 |
| `demo/demo_insn_eor_shifted.c` | 测试程序，覆盖 EOR/AND/ORR 的全部移位变体 |

## 实现方式

纯组合路径 — 使用现有 VM opcode 序列实现：

1. 将 Rm 加载到临时寄存器
2. 根据 ShiftType 发射对应移位指令（SHL/LSR/ASR/ROR）
3. 发射 EOR/AND/ORR 操作
4. SF=false 时调用 trunc32(rd) 截断高 32 位

无需修改 C 解释器侧（handler/dispatch/主循环）。

## 测试结果

| 测试项 | 结果 |
|--------|------|
| `make all` 编译 | ✅ 通过 |
| 原生运行 `EOR_SHIFTED PASS` | ✅ 通过 |
| VMP Standard 模式（20/20 指令，480 bytes） | ✅ 通过 |
| VMP Token 模式（20/20 指令） | ✅ 通过 |
