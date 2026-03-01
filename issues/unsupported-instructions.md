# 不支持的 ARM64 指令 — 实现任务表

> 来源：`vmp/stub.elf` 的 6 个函数 debug 分析
> 生成日期：2026-03-01

## 各函数翻译状态

| 函数 | 总指令 | 已翻译 | 不支持 | 状态 |
|------|--------|--------|--------|------|
| `stub_main` | 461 | 435 | 26 | ❌ |
| `check_tracer_pid` | 87 | 87 | 0 | ✅ |
| `check_proc_maps` | 84 | 82 | 2 | ❌ |
| `antidump_init` | 16 | 16 | 0 | ✅ |
| `check_stub_crc` | 47 | 46 | 1 | ❌ |
| `check_memory_crc` | 51 | 50 | 1 | ❌ |

## 实现顺序

| # | 指令 | 出现次数 | 需要新 opcode | 状态 |
|---|------|---------|--------------|------|
| 1 | EOR/EON shifted register (LSR/ASR/ROR) | 8 | ❌ 修改现有 | [x] ✅ PASS |
| 2 | STURB/LDURB (byte unscaled) | 1 | ❌ 复用现有 | ✅ DONE |
| 3 | UMULH | 2 | ✅ 新增 | [x] ✅ PASS |
| 4 | ADD/SUB(ext reg) | 8 | ❌ 新解码+翻译 | [x] ✅ PASS |
| 5 | TBZ/TBNZ | 18 | ✅ 新增 | [ ] |
| 6 | CCMP | 3 | ✅ 新增 | [ ] |
| 7 | CCMN | 1 | ✅ 新增 | [ ] |
| 8 | SVC | 2 | ✅ 新增 | [ ] |

## 每条指令的 Phase 流程

每条指令严格按以下顺序执行，PASS 后才进入下一条：

```
Phase 1: Demo 验证（编写 demo → 交叉编译 → 原生运行 PASS）
Phase 2: 壳代码修改（Go 翻译器 + C 解释器）
Phase 3: VMP 测试（make all → VMP 打包 → adb 测试 PASS）
Phase 4: 收尾交付（总结文档 + 测试脚本 + 编译 + 运行）
```

## 详细指令说明

### T1: EOR shifted register
- **问题**：`postShiftedXZR3` 在 `decode_dp_reg.go` 中将非 LSL 移位标记为 UNSUPPORTED
- **涉及 raw 值**：`0x4AC66480`(ROR#25), `0x4AC064A6`(ROR#25), `0x4AC66526`(ROR#25), `0x4A432003`(LSR#8)
- **修改范围**：解除 postShiftedXZR3 限制 + tr_alu.go 翻译器支持移位
- **不需要新 opcode**：用现有 SHL/LSR/ASR/ROR + EOR 组合实现

### T2: STRB(pre-index)
- **raw 值**：`0x381FF260` → STRB W0, [X19, #-1]!
- **修改范围**：decode_ldst.go 添加 pre-index 模式 + tr_loadstore.go 处理 writeback

### T3: UMULH
- **raw 值**：`0x9BA20D4A`, `0x9BA40D4A` → UMULH X10, X10, X2/X4
- **修改范围**：新 opcode + 全套 12 文件修改

### T4: ADD/SUB(ext reg)
- **raw 值**：`0x8B21C262`(ADD SXTW), `0x8B3C0333`(ADD LSL), `0xCB3063FF`(SUB UXTX), `0x8B3063FF`(ADD UXTX)
- **修改范围**：decode_dp_reg.go 新模式 + tr_alu.go 翻译

### T5: TBZ/TBNZ
- **已解码**：decoder 已识别名称，但 translator 未实现
- **修改范围**：新 opcode + translator case + handler

### T6: CCMP
- **raw 值**：`0x7A430AE0`, `0x7A411800`, `0x7A53A000`
- **修改范围**：新解码 + 新 opcode + handler

### T7: CCMN
- **raw 值**：`0xFA4EA000`
- **修改范围**：与 CCMP 类似

### T8: SVC
- **raw 值**：`0xD4000001` → SVC #0
- **修改范围**：新 opcode + 系统调用 handler
