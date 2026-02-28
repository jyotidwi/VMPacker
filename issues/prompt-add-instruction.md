# 🛠️ VMP 指令添加提示词模板

> **用法**：将 `{INSTRUCTION}` 替换为目标 ARM64 指令名（如 `CLZ`、`REV`、`SMULL`），整段发给 AI。
>
> **核心原则**：宁可错杀，不可放过 — 每条 ARM64 指令的所有编码变体都必须覆盖。

---

## 📋 提示词正文

````
我需要你为这个 ARM64 VMP（虚拟机保护）项目添加对 {INSTRUCTION} 指令的完整支持。

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## 📐 项目架构
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ARM64 → 自定义 VM 字节码的翻译器 + 解释器系统：

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│ ARM64 ELF   │ ──▶ │ Go 翻译器     │ ──▶ │ VM 字节码     │
│ (原生指令)   │     │ (decode+emit) │     │ (.vmp 文件)   │
└─────────────┘     └──────────────┘     └──────────────┘
                                                │
                                                ▼
                                         ┌──────────────┐
                                         │ C 解释器      │
                                         │ (运行时执行)   │
                                         └──────────────┘
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## ⚠️ 核心原则：宁可错杀，不可放过
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ARM64 每条指令都有多种编码变体。例如 LDR 有 6 种：

| # | 变体 | 特征 |
|---|------|------|
| 1 | unsigned offset (imm12) | 最常见 |
| 2 | pre-index (imm9, writeback) | `[Xn, #imm]!` |
| 3 | post-index (imm9, writeback) | `[Xn], #imm` |
| 4 | unscaled (LDUR, imm9) | 无对齐要求 |
| 5 | register offset (Rm, extend/shift) | `[Xn, Xm, LSL #n]` |
| 6 | literal (PC-relative) | `LDR Xt, label` |

**你必须：**
1. 查阅 ARM Architecture Reference Manual，列出 {INSTRUCTION} 的 **所有** 编码变体
2. 为每个变体都添加解码模式（即使你认为不常见）
3. 不确定是否存在？实现它
4. 暂时无法翻译的变体 → 返回明确错误，**不可静默跳过**

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## 🔄 执行流程（严格按顺序，每步验证）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

```
 Phase 1                Phase 2                Phase 3
┌──────────┐          ┌──────────┐          ┌──────────┐
│ Demo 验证 │ ──PASS─▶ │ 壳代码修改 │ ──PASS─▶ │ VMP 测试  │
│          │          │          │          │          │
│ ① 写 demo│          │ ④ Go 翻译 │          │ ⑦ make   │
│ ② 编译   │          │ ⑤ C handler│         │ ⑧ VMP 打包│
│ ③ 原生运行│          │ ⑥ 注册分发 │          │ ⑨ adb 测试│
└──────────┘          └──────────┘          └──────────┘
     │                      │                      │
     ▼                      ▼                      ▼
  FAIL→修复              FAIL→修复              FAIL→修复
```

> **铁律**：每个 Phase 必须 PASS 才能进入下一个。失败则修复后重新验证。

---

### Phase 1：Demo 验证（先证明指令行为正确）

**① 编写 demo 文件** → `demo/demo_insn_{INSTRUCTION}.c`

```c
// demo/demo_insn_{INSTRUCTION}.c
// 测试 {INSTRUCTION} 指令的所有变体
#include <stdio.h>

// 用 inline asm 或 C 代码触发 {INSTRUCTION} 的各种编码
// 确保函数足够大（>72B）以支持 standard mode
int __attribute__((noinline)) test_{INSTRUCTION}(/* 参数 */) {
    // ... 测试逻辑 ...
    return result;
}

int main() {
    int ret = test_{INSTRUCTION}(/* 测试数据 */);
    if (ret == expected) {
        printf("{INSTRUCTION} PASS\n");
        return 0;
    }
    printf("{INSTRUCTION} FAIL: got %d, want %d\n", ret, expected);
    return 1;
}
```

**② 交叉编译**
```powershell
aarch64-linux-gnu-gcc -O1 -static -o build/demo_insn_{INSTRUCTION} demo/demo_insn_{INSTRUCTION}.c
```

> 注意：使用 `-O1` 让编译器生成目标指令。`-O0` 可能不会生成某些优化指令，`-O2` 可能优化掉。

**③ 原生运行验证**
```powershell
adb push build/demo_insn_{INSTRUCTION} /home/root/vmp/
adb shell "chmod +x /home/root/vmp/demo_insn_{INSTRUCTION}; /home/root/vmp/demo_insn_{INSTRUCTION}"
```

**预期输出**：`{INSTRUCTION} PASS`
**如果 FAIL** → 修复 demo 代码，重新编译运行，直到 PASS。

---

### Phase 2：壳代码修改（按文件顺序逐一修改）

> 如果 {INSTRUCTION} 可以完全用现有 VM opcode 组合实现，跳过标记 `[NEW_OP]` 的步骤。

#### 📁 文件修改清单

| # | 文件 | 说明 | 条件 |
|---|------|------|------|
| 1 | `pkg/vm/opcodes.go` | VM opcode 常量（Go） | `[NEW_OP]` |
| 2 | `stub/vm_opcodes.h` | VM opcode 常量（C） | `[NEW_OP]` |
| 3 | `pkg/arch/arm64/decoder.go` | Op 枚举 + OpName | 必改 |
| 4 | `pkg/arch/arm64/decode_*.go` | 解码模式表 | 必改 |
| 5 | `pkg/arch/arm64/translator.go` | 翻译器主分发 | 必改 |
| 6 | `pkg/arch/arm64/tr_*.go` | 翻译器实现 | 必改 |
| 7 | `stub/vm_handlers/h_*.h` | C handler | `[NEW_OP]` |
| 8 | `stub/vm_dispatch.h` | Dispatch 跳转表 | `[NEW_OP]` |
| 9 | `stub/vm_interp_clean.c` | 解释器主循环 | `[NEW_OP]` |
| 10 | `stub/vm_decode.h` | 指令大小表 | `[NEW_OP]` |
| 11 | `pkg/vm/disasm.go` | 反汇编器 | `[NEW_OP]` |
| 12 | `pkg/vm/types.go` | 指令大小（通过 disasm） | `[NEW_OP]` |

---

#### 📝 各文件修改详情

**文件 1: `pkg/vm/opcodes.go`** `[NEW_OP]`
- opcode 值范围 `0x00-0xFF`，不可与现有值冲突
- 注释格式：`OpXxx byte = 0xNN // 描述 大小B: [编码格式]`

**文件 2: `stub/vm_opcodes.h`** `[NEW_OP]`
- 必须与 `opcodes.go` 值 **完全一致**
- 格式：`#define OP_XXX 0xNN /* 描述 大小B */`

**文件 3: `pkg/arch/arm64/decoder.go`**
- `Op` 枚举添加新常量
- `OpName()` 的 names map 添加名称字符串

**文件 4: `pkg/arch/arm64/decode_*.go`**
- 按指令类别选择文件：

| 类别 | 文件 | 指令举例 |
|------|------|---------|
| 数据处理（立即数） | `decode_dp_imm.go` | ADD/SUB/AND/ORR(imm), MOVZ/K/N, UBFM/SBFM |
| 数据处理（寄存器） | `decode_dp_reg.go` | ADD/SUB/AND/ORR(reg), CSEL, MUL, DIV |
| 加载/存储 | `decode_ldst.go` | LDR/STR/LDP/STP 全系列 |
| 分支 | `decode_branch.go` | B/BL/BR/BLR/RET, B.cond, CBZ/CBNZ |

- 使用表驱动：`InstrPattern{Name, Mask, Value, Op, Fields, Post}`
- **每个编码变体 = 独立的 InstrPattern 条目**
- Mask/Value 计算：固定位 Mask=1 Value=期望值，可变位 Mask=0
- 常用 FieldDef：`fSF`(bit31), `fRd`(0:4), `fRn`(5:9), `fRm16`(16:20)

**文件 5: `pkg/arch/arm64/translator.go`**
- `translateOne()` switch 添加 case → 调用 tr_*.go 中的翻译函数

**文件 6: `pkg/arch/arm64/tr_*.go`**
- 按类别选择：`tr_alu.go` / `tr_bitfield.go` / `tr_loadstore.go` / `tr_branch.go` / `tr_special.go`
- 函数签名：`func (t *Translator) trXxx(inst vm.Instruction) error`
- 关键 API：
  - `t.mapReg(inst.Rd)` → VM 寄存器编号
  - `t.emit(opcode, operands...)` → 发射字节码
  - `t.emitU32()` / `t.emitU64()` → 发射立即数
  - `t.trunc32(rd)` → W 寄存器操作后截断高 32 位
  - `inst.Rd == vm.REG_XZR` → 结果写入 R16（丢弃寄存器）

**文件 7: `stub/vm_handlers/h_*.h`** `[NEW_OP]`
- 选择：`h_alu.h` / `h_mem.h` / `h_cmp.h` / `h_mov.h` / `h_stack.h` / `h_system.h` / `h_branch.h`
- handler 签名：`static inline u32 h_xxx(vm_ctx_t *vm)`
- 返回值 = 指令字节数（PC 推进量）
- 字节码读取：`vm->bc[vm->pc + N]`，`rd16/rd32/rd64` 读立即数
- 寄存器：`vm->R[reg & 31]`
- SP 栈访问：`VM_STK_CHECK(vm, addr, width)`

**文件 8: `stub/vm_dispatch.h`** `[NEW_OP]`
- wrapper：`__attribute__((noinline)) VM_SECTION_XXX static u32 hw_xxx(vm_ctx_t *vm) { return h_xxx(vm); }`
- 注册：`tbl[OP_XXX] = hw_xxx;`
- Section：ALU→`VM_SECTION_ALU`, MEM→`VM_SECTION_MEM`, BRANCH→`VM_SECTION_BRANCH`, 其他→`VM_SECTION_SYSTEM`

**文件 9: `stub/vm_interp_clean.c`** `[NEW_OP]`
- dispatch 表：`dtab[OP_XXX] = &&L_XXX;`
- 标签：
  ```c
  L_XXX:
    NEXT(h_xxx(vm));        // 普通指令
  // 或
  L_XXX:
    h_xxx(vm); NEXT0();     // 分支指令（handler 已设置 pc）
  ```

**文件 10: `stub/vm_decode.h`** `[NEW_OP]`
- `vm_insn_size()` switch 添加：`case OP_XXX: return N;`

**文件 11: `pkg/vm/disasm.go`** `[NEW_OP]`
- `opTable` 添加：`OpXxx: {"XXX", N},`
- `DisasmOne()` switch 添加格式化输出

**文件 12: `pkg/vm/types.go`** `[NEW_OP]`
- 确认 `InstructionSize()` 通过 `disasm.go` 的 `opTable` 正确返回大小

---

### Phase 3：VMP 打包测试

**⑦ 编译全部**
```powershell
make all
```

**⑧ VMP 打包**
```powershell
# Standard mode
.\build\vmpacker.exe -func test_{INSTRUCTION} -debug -v -o build/demo_insn_{INSTRUCTION}_std.vmp build/demo_insn_{INSTRUCTION}

# Token mode
.\build\vmpacker.exe -token -func test_{INSTRUCTION} -debug -v -o build/demo_insn_{INSTRUCTION}_token.vmp build/demo_insn_{INSTRUCTION}
```

**⑨ 推送 + 运行测试**
```powershell
# Standard mode
adb push build/demo_insn_{INSTRUCTION}_std.vmp /home/root/vmp/
adb shell "chmod +x /home/root/vmp/demo_insn_{INSTRUCTION}_std.vmp; /home/root/vmp/demo_insn_{INSTRUCTION}_std.vmp"

# Token mode
adb push build/demo_insn_{INSTRUCTION}_token.vmp /home/root/vmp/
adb shell "chmod +x /home/root/vmp/demo_insn_{INSTRUCTION}_token.vmp; /home/root/vmp/demo_insn_{INSTRUCTION}_token.vmp"
```

**预期输出**：`{INSTRUCTION} PASS`（两种模式都必须通过）

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## ✅ 验证清单
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

完成所有修改后，逐项检查：

```
[ ] opcode 值一致性 — opcodes.go 和 vm_opcodes.h 值完全相同
[ ] opcode 值唯一性 — 新值不与任何现有值冲突
[ ] 指令大小一致性 — vm_decode.h / disasm.go opTable / handler 返回值三者一致
[ ] 所有编码变体   — ARM64 手册中该指令的每个变体都有 InstrPattern
[ ] XZR 处理      — reg=31 位置正确处理了 XZR（xzrReplace）
[ ] 32-bit 模式   — W 寄存器操作后调用了 trunc32(rd)
[ ] Writeback     — pre/post-index 的 base register 更新正确
[ ] 符号扩展      — LDRSB/LDRSH/LDRSW/SBFM 使用 SHL+ASR 组合
[ ] dispatch 注册 — vm_dispatch.h 和 vm_interp_clean.c 都已注册
[ ] Demo PASS     — 原生运行通过
[ ] VMP Std PASS  — Standard mode 打包运行通过
[ ] VMP Token PASS— Token mode 打包运行通过
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## 📖 完整示例：LDRH（16-bit 无符号加载）
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

### Phase 1: Demo

```c
// demo/demo_insn_ldrh.c
#include <stdio.h>
static unsigned short arr[] = {0x1234, 0x5678, 0xABCD};

int __attribute__((noinline)) test_ldrh(unsigned short *p, int idx) {
    return p[idx];  // 编译器生成 LDRH
}

int main() {
    int v = test_ldrh(arr, 1);
    if (v == 0x5678) { printf("LDRH PASS\n"); return 0; }
    printf("LDRH FAIL: got 0x%x\n", v);
    return 1;
}
```

### Phase 2: 壳代码修改

**需要新 opcode**：现有只有 LOAD8/LOAD32/LOAD64，缺少 16-bit → 新增 `OpLoad16 = 0xE7`

| # | 文件 | 改动 |
|---|------|------|
| 1 | `opcodes.go` | `OpLoad16 byte = 0xE7 // 5B: [op][dst][base][imm16]` |
| 2 | `vm_opcodes.h` | `#define OP_LOAD16 0xE7` |
| 3 | `decoder.go` | 枚举 `LDRH_IMM`，OpName `"LDRH(imm)"` |
| 4 | `decode_ldst.go` | 3 个变体：unsigned offset / pre-index / post-index |
| 5 | `translator.go` | `case LDRH_IMM: return 0, t.trLoad(inst)` |
| 6 | `tr_loadstore.go` | trLoad 中 `case LDRH_IMM: vmOp = vm.OpLoad16` |
| 7 | `h_mem.h` | `h_load16()` — 读 2 字节，零扩展 |
| 8 | `vm_dispatch.h` | `hw_load16` wrapper + `tbl[OP_LOAD16]` |
| 9 | `vm_interp_clean.c` | `dtab[OP_LOAD16] = &&L_LOAD16;` + label |
| 10 | `vm_decode.h` | `case OP_LOAD16: return 5;` |
| 11 | `disasm.go` | `OpLoad16: {"LOAD16", 5}` |

### Phase 3: VMP 测试

```powershell
make all
.\build\vmpacker.exe -func test_ldrh -debug -v -o build/demo_insn_ldrh_std.vmp build/demo_insn_ldrh
.\build\vmpacker.exe -token -func test_ldrh -debug -v -o build/demo_insn_ldrh_token.vmp build/demo_insn_ldrh
adb push build/demo_insn_ldrh_std.vmp /home/root/vmp/
adb shell "chmod +x /home/root/vmp/demo_insn_ldrh_std.vmp; /home/root/vmp/demo_insn_ldrh_std.vmp"
# → LDRH PASS ✅
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## 🔄 批量添加
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

```
请按照 issues/prompt-add-instruction.md 的流程，依次添加以下指令：
1. CLZ（前导零计数）
2. REV（字节序反转）
3. SMULL（有符号 32×32→64 乘法）

每条指令严格走完 Phase 1→2→3，全部 PASS 后才进入下一条。
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## 📊 ARM64 编码变体速查表
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

| 指令类别 | 变体 | 编码特征 |
|---------|------|---------|
| **LDR/STR** | unsigned offset | `size:111:V:01:opc:imm12:Rn:Rt` |
| | pre-index | `size:111:V:00:opc:0:imm9:11:Rn:Rt` |
| | post-index | `size:111:V:00:opc:0:imm9:01:Rn:Rt` |
| | unscaled (LDUR/STUR) | `size:111:V:00:opc:0:imm9:00:Rn:Rt` |
| | register offset | `size:111:V:00:opc:1:Rm:opt:S:10:Rn:Rt` |
| | literal (PC-rel) | `opc:011:V:00:imm19:Rt` |
| **ADD/SUB** | immediate | `sf:op:S:10001:sh:imm12:Rn:Rd` |
| | shifted register | `sf:op:S:01011:sh:0:Rm:imm6:Rn:Rd` |
| | extended register | `sf:op:S:01011:00:1:Rm:opt:imm3:Rn:Rd` |
| **AND/ORR/EOR** | immediate (bitmask) | `sf:opc:100100:N:immr:imms:Rn:Rd` |
| | shifted register | `sf:opc:01010:sh:N:Rm:imm6:Rn:Rd` |
| **MOV wide** | MOVZ/MOVK/MOVN | `sf:opc:100101:hw:imm16:Rd` |
| **Bitfield** | UBFM/SBFM | `sf:opc:100110:N:immr:imms:Rn:Rd` |
| **Branch** | B/BL | `op:00101:imm26` |
| | B.cond | `0101010:0:imm19:0:cond` |
| | CBZ/CBNZ | `sf:011010:op:imm19:Rt` |
| | TBZ/TBNZ | `b5:011011:op:b40:imm14:Rt` |
| **Cond select** | CSEL/CSINC/CSINV/CSNEG | `sf:op:S:11010:00:Rm:cond:o2:Rn:Rd` |
| **Multiply** | MUL/MADD/MSUB | `sf:00:11011:000:Rm:o0:Ra:Rn:Rd` |
| **Divide** | UDIV/SDIV | `sf:0:S:11010110:Rm:opcode:Rn:Rd` |

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## 🏗️ 构建命令速查
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

```powershell
# 交叉编译 demo
aarch64-linux-gnu-gcc -O1 -static -o build/demo_insn_xxx demo/demo_insn_xxx.c

# 编译 stub + packer
make all

# VMP 打包（standard / token）
.\build\vmpacker.exe -func test_xxx -debug -v -o build/demo_insn_xxx_std.vmp build/demo_insn_xxx
.\build\vmpacker.exe -token -func test_xxx -debug -v -o build/demo_insn_xxx_token.vmp build/demo_insn_xxx

# 推送 + 运行
adb push build/demo_insn_xxx_std.vmp /home/root/vmp/
adb shell "chmod +x /home/root/vmp/demo_insn_xxx_std.vmp; /home/root/vmp/demo_insn_xxx_std.vmp"
adb push build/demo_insn_xxx_token.vmp /home/root/vmp/
adb shell "chmod +x /home/root/vmp/demo_insn_xxx_token.vmp; /home/root/vmp/demo_insn_xxx_token.vmp"
```

## 现在请添加 {INSTRUCTION}

先列出所有 ARM64 编码变体，然后严格按 Phase 1 → 2 → 3 执行。
每个 Phase 必须 PASS 才能进入下一个。
````

---

## 📌 使用说明

1. 复制 ```````` 之间的提示词正文
2. 全局替换 `{INSTRUCTION}` 为目标指令名
3. 发给 AI（确保 AI 能访问项目源码）
4. AI 会按 Phase 1→2→3 逐步执行，每步验证通过才继续
