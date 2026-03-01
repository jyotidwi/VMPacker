# T3: UMULH (unsigned high 64-bit multiply) — 实现总结

## 基本信息

| 项目 | 内容 |
|------|------|
| 指令名称 | UMULH Xd, Xn, Xm |
| 实现路径 | **新增 opcode**（OpUmulh = 0xF2） |
| 状态 | ✅ PASS |

## 编码格式

| 字段 | 位域 | 值 |
|------|------|-----|
| sf | [31] | 1 (64-bit only) |
| op54 | [30:29] | 00 |
| op31 | [23:21] | 110 |
| o0 | [15] | 0 |
| Ra | [14:10] | 11111 (unused) |
| Mask | — | 0xFFE0FC00 |
| Value | — | 0x9BC07C00 |

## VM Bytecode 格式

```
[OpUmulh][d][n][m]   — 4 bytes
```

## 修改文件清单（11 文件）

| 文件 | 修改内容 |
|------|---------|
| `pkg/vm/opcodes.go` | 新增 `OpUmulh byte = 0xF2` |
| `stub/vm_opcodes.h` | 新增 `#define OP_UMULH 0xF2` |
| `pkg/vm/disasm.go` | opTable + DisasmOne 3-reg case |
| `stub/vm_decode.h` | `vm_insn_size()` 4-byte case |
| `pkg/arch/arm64/decoder.go` | UMULH Op enum + OpName |
| `pkg/arch/arm64/decode_dp_reg.go` | InstrPattern (mask/value/postFunc) |
| `pkg/arch/arm64/translator.go` | `case UMULH: return 0, t.trUmulh(inst)` |
| `pkg/arch/arm64/tr_alu.go` | `trUmulh()` — emit [OpUmulh][d][n][m] |
| `stub/vm_handlers/h_alu.h` | `h_umulh()` — `__uint128_t` 128-bit multiply |
| `stub/vm_dispatch.h` | `hw_umulh` wrapper + `tbl[OP_UMULH]` |
| `stub/vm_interp_clean.c` | `dtab[OP_UMULH]` + `L_UMULH` label |

## 实现方式

新增 opcode 路径 — C handler 使用 `__uint128_t` 进行 128 位无符号乘法，提取高 64 位：

```c
__uint128_t r = (__uint128_t)Rn * (__uint128_t)Rm;
Rd = (u64)(r >> 64);
```

Go translator 直接 emit 4 字节 `[OpUmulh][d][n][m]`，无需移位处理（UMULH 始终 64-bit）。

## 测试结果

| 测试项 | 结果 |
|--------|------|
| `make all` 编译 | ✅ 通过 (stub 6496 bytes) |
| 原生运行 `UMULH PASS` | ✅ `0x200558FF6030C85D` |
| VMP Standard 模式 (27/27 指令) | ✅ `0x200558FF6030C85D` |
| VMP Token 模式 (27/27 指令) | ✅ `0x200558FF6030C85D` |
