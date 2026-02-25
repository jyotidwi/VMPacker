<div align="center">

# 🛡️ VMP — ARM64 ELF Virtual Machine Protection

**轻量级 ARM64 ELF 虚拟化保护工具**

将目标函数的 ARM64 机器码翻译为自定义 VM 字节码，运行时由嵌入的 VM 解释器执行。
有效抵抗 IDA Pro / Ghidra 等静态分析工具的反编译。

[![Go](https://img.shields.io/badge/Go-1.23+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![ARM64](https://img.shields.io/badge/Arch-ARM64%20|%20AArch64-red)](https://developer.arm.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

</div>

---

## 🎯 功能特性

- **ARM64 指令虚拟化** — 支持 100+ 条 ARM64 指令（含 NEON SIMD、STP/LDP、CSEL 等复杂指令）
- **按函数名保护** — 指定符号名自动定位并保护
- **按地址保护** — 适用于 stripped 二进制，直接指定 IDA Pro 中看到的地址
- **自动函数边界检测** — 仅指定起始地址即可自动扫描到 RET 确定函数大小
- **PT_NOTE → PT_LOAD 注入** — 不破坏原始段布局，零副作用
- **XOR 字节码加密** — 运行时解密，增加静态分析难度
- **符号表清除** — 自动 strip，防止逆向工具恢复函数名
- **批量保护** — 一次保护多个函数

## 📐 架构概览

```
原始 ELF                              保护后 ELF
┌──────────────────┐                  ┌──────────────────┐
│  ELF Header      │                  │  ELF Header      │
├──────────────────┤                  ├──────────────────┤
│  .text           │                  │  .text           │
│  ┌────────────┐  │                  │  ┌────────────┐  │
│  │ func_A:    │  │   ARM64→VM       │  │ func_A:    │  │
│  │ 原始指令    │──┼──翻译加密──→     │  │ BL interp  │  │ ← 跳板
│  └────────────┘  │                  │  └────────────┘  │
├──────────────────┤                  ├──────────────────┤
│  PT_NOTE (无用)  │──劫持──→         │  PT_LOAD (RX)    │ ← 新段
│                  │                  │  ┌────────────┐  │
│                  │                  │  │ VM Interp   │  │ 解释器 blob
│                  │                  │  │ Bytecode    │  │ 加密字节码
│                  │                  │  └────────────┘  │
└──────────────────┘                  └──────────────────┘
```

**保护流程**: 解码 ARM64 → 翻译为 VM 字节码 → XOR 加密 → 注入 PT_LOAD → 原函数替换为跳板 → Strip 符号表

## 📁 项目结构

```
vmp/
├── cmd/vmpacker/              # CLI 入口
│   ├── main.go                # 命令行解析 + //go:embed
│   └── vm_interp.bin          # VM 解释器 blob (编译产物，自动嵌入)
├── pkg/
│   ├── vm/                    # VM 核心抽象
│   │   ├── types.go           # 接口: Decoder, Translator, Packer
│   │   └── opcodes.go         # VM 操作码定义
│   ├── arch/arm64/            # ARM64 架构支持
│   │   ├── decoder.go         # ARM64 指令解码器
│   │   ├── decoder_test.go    # 解码器单元测试
│   │   ├── translator.go      # ARM64 → VM 字节码翻译
│   │   └── translator_test.go # 翻译器单元测试
│   └── binary/elf/            # ELF 二进制操作
│       ├── packer.go          # ELF 注入 (PT_NOTE hijack)
│       └── trampoline.go      # ARM64 跳板代码生成
├── stub/                      # VM 解释器 (C 源码)
│   ├── vm_interp_clean.c      # 解释器核心实现
│   ├── vm_interp.lds          # 链接脚本 (.rodata → .text)
│   ├── vm_opcodes.h           # 操作码定义 (与 Go 侧同步)
│   ├── vm_types.h             # VM 数据类型定义
│   └── vm_decode.h            # 字节码解码宏
├── demo/                      # 示例程序
│   ├── demo_license.c         # License 验证示例
│   └── demo_simple.c          # 简单测试示例
├── Makefile                   # 构建系统
└── go.mod
```

## 🔧 编译环境

### 依赖

| 工具 | 版本 | 用途 |
|------|------|------|
| **Go** | ≥ 1.21 | 编译 vmpacker |
| **aarch64-linux-gnu-gcc** | 任意 | 交叉编译 VM 解释器 |
| **aarch64-linux-gnu-ld** | 任意 | 链接 VM 解释器 |
| **aarch64-linux-gnu-objcopy** | 任意 | 提取纯二进制 blob |
| **GNU Make** | 任意 | 构建系统 |

> **Windows 用户**: 可通过 [MSYS2](https://www.msys2.org/) 或 [WSL](https://learn.microsoft.com/en-us/windows/wsl/) 安装交叉编译工具链：
> ```bash
> # MSYS2
> pacman -S mingw-w64-x86_64-aarch64-none-elf-gcc
> # Ubuntu / WSL
> sudo apt install gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu
> ```

### 编译

```bash
# 一键编译（推荐）
make all

# 输出到 build/ 目录:
#   build/vmpacker.exe    — Go packer 工具
#   build/vm_interp.bin   — VM 解释器 blob
#   build/stub/           — 编译中间产物
```

其他 Make 目标：

```bash
make stub      # 仅编译 VM 解释器 blob
make packer    # 仅编译 Go packer（需要先 make stub）
make demo      # 交叉编译 demo 程序
make test      # 运行单元测试
make clean     # 清理所有产物
make help      # 查看所有目标
```

## 🚀 使用方法

### 按函数名保护

```bash
# 单个函数
./vmpacker -func check_license -o protected.elf original.elf

# 多个函数
./vmpacker -func "check_license,verify_token" -o protected.elf original.elf

# 详细输出（显示反汇编 + VM 字节码）
./vmpacker -func check_license -v -o protected.elf original.elf
```

### 按地址保护（适用于 stripped 二进制）

```bash
# 指定地址范围（IDA Pro 中直接看到的 start-end）
./vmpacker -addr "0x4006AC-0x400790" -o protected.elf stripped.elf

# 仅指定起始地址（自动扫描到 RET 确定大小）
./vmpacker -addr "0x4006AC" -o protected.elf stripped.elf

# 指定地址 + 自定义名称
./vmpacker -addr "0x4006AC-0x400790:main" -o protected.elf stripped.elf

# 混合使用：按名称 + 按地址
./vmpacker -func verify -addr "0x4006AC-0x400790:main" -o protected.elf app.elf
```

### 查看 ELF 信息

```bash
./vmpacker -info original.elf
```

### 完整参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-func` | — | 要保护的函数名（逗号分隔） |
| `-addr` | — | 按地址保护（格式: `0xADDR`, `0xSTART-0xEND`, 可选 `:name` 后缀） |
| `-o` | `<input>.vmp` | 输出文件路径 |
| `-v` | `false` | 详细输出（显示反汇编和字节码） |
| `-strip` | `true` | 清除符号表 |
| `-info` | `false` | 仅显示 ELF 信息 |

## 🔒 反编译对抗

VM 解释器采用多层混淆防护：

| 层级 | 技术 | IDA Pro 效果 |
|------|------|--------------|
| L1 | **Computed Goto** + XOR 加密跳转表 | 无法识别 switch 结构，handler 变成孤立代码块 |
| L2 | **MBA 混淆** (Mixed Boolean Arithmetic) | `a+b` → `(a^b)+2*(a&b)`，反编译满屏位运算 |
| L3 | **Opaque Predicates** | 虚假控制流分支，IDA 认为多路径可达 |
| L4 | **符号表清除** | `.symtab`/`.strtab`/`.comment` 用随机数据覆盖 |

## ⚠️ 注意事项

### 架构与格式限制

- **仅支持 ARM64 (AArch64)** — 不支持 x86/MIPS/RISC-V 等其他架构
- **仅支持 ELF 格式** — 不支持 PE (Windows) / Mach-O (macOS)
- **仅支持静态链接的函数体** — 不能保护 PLT 桩或动态链接器代码

### 函数约束

- 目标函数必须位于 `.text` section
- 按地址保护时，地址必须 **4 字节对齐**（ARM64 指令长度）
- 自动大小检测依赖 RET (`0xD65F03C0`) 指令，对于以 `B` 结尾的函数（尾调用优化）需要手动指定结束地址
- 函数内的 **PC-relative 寻址**（如 `ADRP`+`ADD` 访问全局变量）在 VM 中通过直接地址计算处理，但需确保目标地址在运行时可达

### 编译注意

- VM 解释器 **必须** 使用 `-mcmodel=tiny` 编译，**禁止** `-fPIC`
  - `-fPIC` 生成 `ADRP` 指令（4KB 页对齐寻址），blob 嵌入非对齐偏移时会崩溃
  - `-mcmodel=tiny` 生成 `ADR` 指令（纯 PC-relative），无对齐要求
- 链接脚本 `vm_interp.lds` 将 `.rodata` 合并到 `.text`，确保常量表可通过 PC-relative 访问

### 使用建议

- ⚡ **先在测试环境验证**，确认保护后的程序功能正常再部署生产
- ⚡ **保留原始二进制备份**，保护操作不可逆
- ⚡ 建议在 **真实 ARM64 硬件** 上测试，QEMU 用户模式可能存在兼容性问题
- ⚡ `-v` 标志会输出全部反汇编和字节码，仅在调试时使用

### 安全声明

> **本工具仅用于保护自有软件知识产权**，请勿用于恶意软件加壳、规避安全检测等违法用途。使用者应遵守所在地区法律法规，开发者不承担任何因滥用导致的法律责任。

## 📜 License

[MIT License](LICENSE) — 自由使用、修改、分发，需保留版权声明。
