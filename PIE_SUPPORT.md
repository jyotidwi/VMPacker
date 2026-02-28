# PIE (ET_DYN) 支持

## 概述

VMP packer 现已支持 PIE (Position-Independent Executable, ET_DYN) 二进制文件的 Token 模式保护。

## 问题

PIE 二进制在运行时由 ASLR 随机化基地址。原先 packer 在 `_token_table_va` 和 `token_desc_t.bc_va` 中写入绝对虚拟地址，ASLR 后这些地址全部失效。

## 解决方案：PC-relative 偏移

采用统一的 PC-relative 偏移方案，ET_EXEC 和 ET_DYN 均使用相同代码路径：

### Stub 端 (`stub/vm_interp_clean.c`)

```c
u64 self_va;
__asm__ volatile("adr %0, _token_table_va" : "=r"(self_va));
u64 tbl_off = *(volatile u64 *)&_token_table_va;
token_desc_t *table = (token_desc_t *)(self_va + tbl_off);
u8 *enc_bc = (u8 *)(self_va + table[func_id].bc_off);
```

- `ADR` 指令获取 `_token_table_va` 的运行时地址 (PC-relative, ±1MB)
- `_token_table_va` 存储 token 描述符表相对于自身地址的偏移
- `bc_off` 存储加密字节码相对于 `_token_table_va` 地址的偏移

### Packer 端 (`pkg/binary/elf/packer.go`)

```go
selfVA := payloadVA + tokenTableVAOff
// _token_table_va = tokenTableVA - selfVA (相对偏移)
// bc_off = bcVA - selfVA (相对偏移)
```

### 数据结构 (`stub/vm_token.h`)

```c
typedef struct {
    u64 bc_off;     // 相对于 _token_table_va 的偏移 (原 bc_va)
    u32 bc_len;
    u32 reserved;
} token_desc_t;
```

## 已知限制

- **仅 Token 模式支持 PIE**：标准模式 trampoline 仍使用绝对地址加载 `bcVA`
- **CALL_NAT 限制**：如果被保护函数包含对外部函数的调用 (`BL`)，translator 编码的绝对目标地址在 PIE 下会失效。纯算术/逻辑函数不受影响
- **ADR 范围**：±1MB，payload 在同一 LOAD 段内，实际不会超限

## 测试结果

| 测试 | ELF 类型 | 结果 |
|------|----------|------|
| C `demo_insn_add` | ET_EXEC | ✅ PASS:ADD:42 |
| Go `demo_go_test` | ET_EXEC | ✅ checkKey(10)=143 |
| Rust `demo_rust_test` | ET_EXEC | ✅ checkKey(10)=143 |
| Rust `demo_rust_test_pie` | ET_DYN (PIE) | ✅ checkKey(10)=143 |
