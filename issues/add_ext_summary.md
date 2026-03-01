# T4: ADD/SUB extended register — 实现总结

## 基本信息

| 项目 | 内容 |
|------|------|
| 指令名称 | ADD/SUB extended register (ADD_EXT, SUB_EXT, ADDS_EXT, SUBS_EXT) |
| 实现路径 | **纯组合**（无新增 VM Opcode） |
| 状态 | ✅ PASS |

## 编码变体

| 变体 | 示例编码 | 说明 |
|------|---------|------|
| ADD Xd, Xn, Wm, SXTW | `0x8B21C262` | 符号扩展 W 寄存器（32→64） |
| ADD Xd, Xn, Wm, UXTB | `0x8B3C0333` | 零扩展字节（8→64） |
| SUB SP, SP, Xm, UXTX | `0xCB3063FF` | 64 位零扩展（SP 操作） |
| ADD SP, SP, Xm, UXTX | `0x8B3063FF` | 64 位零扩展（SP 操作） |

支持全部扩展类型：UXTB, UXTH, UXTW, UXTX, SXTB, SXTH, SXTW, SXTX

## 修改文件清单

| 文件 | 修改内容 |
|------|---------|
| `pkg/arch/arm64/decoder.go` | ADD_EXT / SUB_EXT / ADDS_EXT / SUBS_EXT Op 枚举 + OpName |
| `pkg/arch/arm64/decode_dp_reg.go` | InstrPattern 条目 + `postExtReg` 回调 |
| `pkg/arch/arm64/translator.go` | `translateOne()` switch cases |
| `pkg/arch/arm64/tr_alu.go` | `trAddSubExt()` 翻译函数 |
| `demo/demo_insn_add_ext.c` | 验证程序 |

## 实现方式

纯组合路径 — 使用现有 VM opcode 序列实现：

1. 将 Rm 加载到临时寄存器
2. 根据扩展类型应用零扩展（AND 截断）或符号扩展（SHL + ASR）
3. 可选 LSL shift 应用于扩展后的值
4. 发射 ADD/SUB 操作
5. SF=false 时调用 trunc32(rd) 截断高 32 位

扩展类型映射：
- UXTB: AND 0xFF
- UXTH: AND 0xFFFF
- UXTW: AND 0xFFFFFFFF
- UXTX: 无操作（64 位直通）
- SXTB: SHL 56 + ASR 56
- SXTH: SHL 48 + ASR 48
- SXTW: SHL 32 + ASR 32
- SXTX: 无操作（64 位直通）

无需修改 C 解释器侧（handler/dispatch/主循环）。

## 测试结果

| 测试项 | 结果 |
|--------|------|
| `make all` 编译 | ✅ 通过 |
| 原生运行 `ADD_EXT PASS` | ✅ 通过 |
| VMP Standard 模式 | ✅ 通过 |
| VMP Token 模式 | ✅ 通过 |
