# LDR literal (PC-relative) 指令支持 — 实现总结

## 概述
- 指令：LDR literal (PC-relative load)
- 编码变体：3 个
  - `LDR Xt, [PC+imm]` (64-bit, opc=01)
  - `LDR Wt, [PC+imm]` (32-bit, opc=00)
  - `LDRSW Xt, [PC+imm]` (32→64 sign-extend, opc=10)
- 新增 VM opcode：**无** — 纯组合实现 (`MOV_IMM64 + LOAD32/64`)

## 修改文件清单

| 文件 | 改动说明 |
|------|---------|
| `pkg/arch/arm64/decoder.go` | OpName 添加 `LDR_LIT: "LDR(lit)"` |
| `pkg/arch/arm64/decode_ldst.go` | 添加 3 个 InstrPattern (LDR_LIT_64/32/LDRSW_LIT) + `postLdrLiteral` 函数 |
| `pkg/arch/arm64/translator.go` | translateOne switch 添加 `case LDR_LIT` → `trLdrLiteral` |
| `pkg/arch/arm64/tr_loadstore.go` | 新增 `trLdrLiteral` 翻译函数 |

## 翻译策略

```
ARM64:  LDR Xt, [PC + imm19*4]
  ↓ (编译时计算 absAddr = funcAddr + instOffset + imm19*4)
VM:    MOV_IMM64 R16, absAddr   (10 bytes)
       LOAD64    Rd,  R16, 0    ( 5 bytes)

ARM64:  LDRSW Xt, [PC + imm19*4]
  ↓
VM:    MOV_IMM64 R16, absAddr
       LOAD32    Rd,  R16, 0
       SHL_IMM   Rd,  Rd,  32   (符号扩展)
       ASR_IMM   Rd,  Rd,  32
```

## 测试结果
- 原生运行：✅ PASS
- VMP Standard：✅ PASS (`test_ldr_literal` + `test_struct`)
- VMP Token：待测试

## 备注
- 编译器 `-O1` 通常用 MOVZ/MOVK 序列而非 LDR literal 来加载常量
- `-O2` 优化才会生成 LDR literal（如 `test_struct` 中的 `0xDEADBEEF`）
- LDR literal 在 stub 中的 `stub_phase_A` 可能是崩溃原因之一
