# VMP 混淆技术实现总结

## 概述

在现有 VMP 解释器基础上，实现了三项混淆技术，增强 VM 保护的抗逆向能力。

## 已实现技术

### 1. 间接 Dispatch 跳转表

**文件**: `stub/vm_dispatch.h`  
**宏**: `VM_INDIRECT_DISPATCH`

将 switch-case 分发替换为函数指针跳转表。编译后 handler 地址不再以连续 case 标签出现，增加静态分析难度。

```c
// 启用前: switch(opcode) { case OP_ADD: ... }
// 启用后: dispatch_table[opcode](vm)
```

### 2. 多函数分裂

**文件**: `stub/vm_sections.h`, `stub/vm_interp.lds`  
**宏**: `VM_FUNC_SPLIT`

使用 `__attribute__((section(...)))` 将 handler 函数分散到不同 ELF section，打破代码局部性。链接脚本将所有 section 合并到单一 `.text` 输出段。

### 3. Token 化入口

**文件**: `stub/vm_token.h`, `stub/vm_interp_clean.c`, `pkg/binary/elf/trampoline.go`, `pkg/binary/elf/packer.go`  
**宏**: `VM_TOKEN_ENTRY`  
**CLI**: `-token`

将 72 字节标准跳板缩减为 12 字节 Token 跳板。参数通过描述符表间接查找，不在跳板中暴露。

**Token 32-bit 编码**:
```
bits[31:24] = XOR key
bits[23:12] = bytecode offset (reserved)
bits[11:0]  = function ID (0-4095)
```

## 两种保护模式对比

| 特性 | Standard 模式 | Token 模式 (`-token`) |
|------|--------------|----------------------|
| 跳板大小 | 72 字节 | 12 字节 |
| 最小函数要求 | ≥72B | ≥12B |
| 参数暴露 | bcVA/bcLen/xorKey 明文 | 仅 32-bit token |
| 入口点 | 每函数独立 BL | 统一 B vm_entry_token |
| Blob 头部 | 8B | 24B |

## 编译

```powershell
# 编译 VM 解释器 blob (启用全部三项混淆)
make stub

# 编译 Go packer
make packer

# 或一步完成
make all
```

## 使用

```powershell
# Standard 模式
./build/vmpacker.exe -func check_license -v -o protected.vmp input.elf

# Token 模式
./build/vmpacker.exe -func rsa_pss_verify -token -v -o protected.vmp input.elf

# 多函数保护
./build/vmpacker.exe -func "func1,func2" -token -o protected.vmp input.elf

# 按地址保护
./build/vmpacker.exe -addr "0x401530-0x401560:my_func" -o protected.vmp input.elf

# 查看 ELF 信息
./build/vmpacker.exe -info input.elf
```

## 编译选项

`Makefile` 中 `STUB_CFLAGS` 已启用全部三项:
```makefile
STUB_CFLAGS = ... -DVM_INDIRECT_DISPATCH -DVM_FUNC_SPLIT -DVM_TOKEN_ENTRY
```

## 安全改进

- **Unsupported Instruction Abort**: 翻译阶段遇到不支持的指令时立即中止，不再生成损坏的 .vmp 文件
- **随机垃圾填充**: 跳板后的原始代码用随机字节覆盖
- **OpcodeCryptor**: 逐指令 opcode 加密 (位置相关 XOR)
- **PC 反向遍历**: 字节码指令顺序反转，增加静态分析难度
- **CRC 完整性校验**: 运行时校验字节码完整性

## 文件清单

| 文件 | 说明 |
|------|------|
| `stub/vm_dispatch.h` | 间接 Dispatch 跳转表 |
| `stub/vm_sections.h` | 多函数分裂 section 宏 |
| `stub/vm_token.h` | Token 编解码 + 描述符表 |
| `stub/vm_interp_clean.c` | VM 解释器主体 |
| `stub/vm_interp.lds` | 链接脚本 |
| `pkg/binary/elf/trampoline.go` | 跳板代码生成 (Standard + Token) |
| `pkg/binary/elf/packer.go` | ELF 打包器 |
| `cmd/vmpacker/main.go` | CLI 入口 |
| `demo/demo_indirect_dispatch.c` | 间接 Dispatch demo |
| `demo/demo_func_split.c` | 多函数分裂 demo |
| `demo/demo_token_entry.c` | Token 化入口 demo |
