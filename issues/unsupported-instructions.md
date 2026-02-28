# 不支持指令全量实现任务表

## 任务清单

### 第一批：纯组合（不需要新 VM opcode）

- [x] T1: LDRSW — LOAD32 + SHL_IMM(32) + ASR_IMM(32) 符号扩展 32→64 ✅ PASS
- [x] T2: LDRSB — LOAD8 + SHL_IMM(56) + ASR_IMM(56) 符号扩展 8→64 ✅ PASS
- [x] T3: MADD — MUL(tmp, Rn, Rm) + ADD(Rd, Ra, tmp) ✅ PASS
- [x] T4: MSUB — MUL(tmp, Rn, Rm) + SUB(Rd, Ra, tmp) ✅ PASS
- [x] T5: UBFM width>=32 — 用 MOV_IMM64 加载 mask 到 R15，再 AND ✅ PASS (附带修复: 64-bit逻辑立即数截断bug in trAluImmFlags/ANDS_IMM/ADDS_IMM)

### 第二批：需要新增 VM opcode OpLoad16 / OpStore16

- [x] T6: OpLoad16 + OpStore16 — 新增 VM opcode + C handler + Go 常量 + disasm ✅ (通过T7/T8验证)
- [x] T7: LDRH — 使用 OpLoad16 ✅ PASS
- [x] T8: STRH — 使用 OpStore16 ✅ PASS
- [x] T9: LDRSH — OpLoad16 + SHL_IMM(48) + ASR_IMM(48) 符号扩展 16→64 ✅ PASS

## 每个任务执行流程

1. 写 demo/demo_insn_xxx.c → 交叉编译 → 原生运行验证 PASS
2. 修改 translator Go 代码（tr_loadstore.go / tr_bitfield.go / translator.go）
3. make 编译 packer → VMP 加壳 demo → adb push → 运行验证 PASS
4. 通过后标记完成，进入下一个任务
