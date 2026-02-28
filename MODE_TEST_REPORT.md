# VMP 普通模式 vs Token 模式测试报告

## 测试日期：2026-03-01

## 测试结果总览

| 测试项 | 模式 | 语言 | 结果 | 备注 |
|--------|------|------|------|------|
| demo_license (valid key) | 普通模式 | C | ✅ `[+] License valid!` | |
| demo_license (invalid key) | 普通模式 | C | ✅ `[-] License invalid.` | |
| demo_license (valid key) | Token 模式 | C | ✅ `[+] License valid!` | |
| demo_license (invalid key) | Token 模式 | C | ✅ `[-] License invalid.` | |
| demo_go_test | Token 模式 | Go | ✅ `checkKey(10) = 143` | |
| demo_insn_add | 普通模式 | C | ❌ 函数太小 (68B < 72B trampoline) | 设计限制 |
| demo_go_test | 普通模式 | Go | ❌ 函数太小 (64B < 72B trampoline) | 设计限制 |

## 普通模式 vs Token 模式对比

| 特性 | 普通模式 (Standard) | Token 模式 |
|------|-------------------|-----------|
| Trampoline 大小 | 72 字节 (18 条指令) | 12 字节 (3 条指令) |
| 最小函数要求 | ≥72 字节 | ≥12 字节 |
| PIE 支持 | ❌ (绝对地址 MOVZ/MOVK) | ✅ (PC-relative ADR) |
| 多函数保护 | 每函数独立 trampoline | 共享 Token 入口 |
| 参数传递 | 直接传 bcVA/bcLen/xorKey | 通过 X16 传 token |

## 已知限制

1. **普通模式函数大小限制**：被保护函数必须 ≥72 字节，否则 trampoline 放不下
2. **普通模式不支持 PIE**：`BuildTrampoline` 使用绝对地址 `MOVZ/MOVK` 编码 `bcVA`，ASLR 下会失效
3. **CALL_NAT 绝对地址**：两种模式下 `BL` 外部调用都编码为绝对地址，PIE 下会失效

## 建议

- 小函数优先使用 Token 模式
- PIE 二进制必须使用 Token 模式
- 普通模式仅适用于 ET_EXEC 且函数 ≥72 字节的场景
