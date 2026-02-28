# VMP Go 兼容性修复：PHDR 重排

## 问题描述

VMP 加壳后的 Go 编译 ARM64 ELF 二进制在运行时发生 Segmentation Fault，崩溃点在 `runtime.save_g`（Go 运行时启动阶段），而非 VM 执行阶段。

## 根因分析

### 崩溃现场

```
Program received signal SIGSEGV, Segmentation fault.
0x000000000007e2c4 in runtime.save_g ()

0x7e2c0: adrp  x27, 0x1a0000
0x7e2c4: ldrsb x0, [x27, #2236]   ← 访问 0x1A08BC (.noptrbss)
```

### 内存映射对比

| 区域 | 原始二进制 | VMP 二进制 |
|------|-----------|-----------|
| 0x17B000-0x1A5000 | ✅ [heap] (BSS 零页) | ❌ 完全未映射 |

### 根本原因

VMP packer 劫持 PT_NOTE（PHDR[1]）转换为 PT_LOAD 用于承载 payload。新 PT_LOAD 的 vaddr（0x1B0000）高于原始 .data/.bss 段（0x170000），但在 PHDR 表中位于其前面。

Linux 内核 ELF loader 按 PHDR 表顺序处理 PT_LOAD 段。乱序的 PT_LOAD 导致内核无法正确建立 BSS 区域的零页映射。

```
原始 PHDR 顺序:
  [0] PT_PHDR
  [1] PT_NOTE        ← Go build ID
  [2] PT_LOAD (RX)   .text      vaddr=0x10000
  [3] PT_LOAD (R)    .rodata    vaddr=0xB0000
  [4] PT_LOAD (RW)   .data/.bss vaddr=0x170000
  [5] PT_GNU_STACK

VMP 后（修复前）:
  [0] PT_PHDR
  [1] PT_LOAD (RX)   payload    vaddr=0x1B0000  ← 问题：高 vaddr 排在前面
  [2] PT_LOAD (RX)   .text      vaddr=0x10000
  [3] PT_LOAD (R)    .rodata    vaddr=0xB0000
  [4] PT_LOAD (RW)   .data/.bss vaddr=0x170000
  [5] PT_GNU_STACK
```

## 修复方案

在 `pkg/binary/elf/packer.go` 的 `injectVMPBatch()` 函数中，PT_NOTE → PT_LOAD 劫持完成后，新增 PHDR 重排步骤：

1. 收集所有 PT_LOAD 类型的 PHDR 条目
2. 按 Vaddr 升序排序
3. 如果当前顺序不符合升序，将排序后的内容写回原始 PHDR 槽位

```
VMP 后（修复后）:
  [0] PT_PHDR
  [1] PT_LOAD (RX)   .text      vaddr=0x10000   ← 重排后正确顺序
  [2] PT_LOAD (R)    .rodata    vaddr=0xB0000
  [3] PT_LOAD (RW)   .data/.bss vaddr=0x170000
  [4] PT_LOAD (RX)   payload    vaddr=0x1B0000  ← 最高 vaddr 排最后
  [5] PT_GNU_STACK
```

### 关键代码（packer.go, injectVMPBatch 函数）

```go
// 4b. 按 Vaddr 升序重排所有 PT_LOAD 段，防止内核映射 BSS 失败
var loads []phdrSlot
for i := 0; i < int(ehdr.Phnum); i++ {
    ph := readPhdr64(p.data, off)
    if ph.Type == uint32(elf.PT_LOAD) {
        loads = append(loads, phdrSlot{idx: i, phdr: ph})
    }
}
sort.Slice(loads, func(a, b int) bool {
    return loads[a].phdr.Vaddr < loads[b].phdr.Vaddr
})
// 将排序后的 PHDR 写回原始槽位...
```

## 同期修复

### 1. payloadVA 冲突（已修复）

原始代码硬编码 `payloadVA = 0x800000`，与 Go 二进制的 .rodata 段冲突。改为动态计算：取所有 PT_LOAD 段的最高 (Vaddr + Memsz)，向上对齐到 0x10000。

### 2. vm_ctx_t 栈溢出（已修复）

`vm_ctx_t` 结构体约 260KB，在栈上分配导致 Go 程序的小栈溢出。改为 `mmap` 堆分配。

## 测试结果

| 测试用例 | 语言 | 模式 | 结果 |
|---------|------|------|------|
| `main.checkKey` | Go | Token | ✅ `checkKey(10) = 143, [+] OK` |
| `check_add` | C | Token | ✅ `PASS:ADD:42` |

## 影响范围

此修复对所有 ELF 二进制生效，不限于 Go。任何 PT_NOTE 位于 PT_LOAD 之前的 ELF（Go、Rust、某些 C 编译器配置）都会受益。修复是无害的——如果 PT_LOAD 已经有序，则不做任何操作。


## Rust 测试

Rust 默认编译为 `ET_DYN`（PIE 二进制），VMP packer 当前不支持 PIE（trampoline 使用绝对地址跳转）。通过编译参数强制生成 `ET_EXEC` 后测试通过：

```powershell
$env:CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER='aarch64-linux-gnu-gcc'
$env:RUSTFLAGS='-C relocation-model=static -C target-feature=+crt-static'
cargo build --target aarch64-unknown-linux-gnu --release
```

## 最终测试结果（3/3 通过）

| 测试用例 | 语言 | ELF 类型 | 模式 | 结果 |
|---------|------|---------|------|------|
| `main.checkKey` | Go | ET_EXEC | Token | ✅ OK |
| `check_add` | C | ET_EXEC | Token | ✅ PASS |
| `check_key` | Rust | ET_EXEC | Token | ✅ OK |

## 语言无关性分析

VMP packer 工作在 ELF 二进制层面，与源语言无关。只要满足以下条件，任何 ARM64 程序都可以被保护：

### 必要条件

1. **ELF 格式**：必须是 ELF64 ARM64 (EM_AARCH64)
2. **ET_EXEC 类型**：必须是静态地址可执行文件（非 PIE/ET_DYN）
3. **符号表可用**：目标函数必须在 `.symtab` 中有符号（未 strip）
4. **PT_NOTE 段存在**：packer 需要劫持一个 PT_NOTE 段
5. **函数指令集兼容**：目标函数中的所有 ARM64 指令必须被 VM 翻译器支持

### 各语言编译参数

| 语言 | 编译命令 | 关键参数 |
|------|---------|---------|
| C | `aarch64-linux-gnu-gcc -static -O0` | `-static` 确保 ET_EXEC |
| Go | `GOOS=linux GOARCH=arm64 go build -gcflags="-N -l"` | Go 默认 ET_EXEC |
| Rust | `cargo build --target aarch64-unknown-linux-gnu` | 需要 `-C relocation-model=static` |
| C++ | `aarch64-linux-gnu-g++ -static -O0` | 同 C |

### 已知限制

1. **不支持 PIE (ET_DYN)**：trampoline 使用绝对地址，PIE 运行时基址随机化会导致跳转失效
2. **不支持共享库 (.so)**：同 PIE 原因
3. **指令集覆盖**：部分 ARM64 指令尚未实现（见 `issues/unsupported-instructions.md`）
