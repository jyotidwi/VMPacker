# T5: TBZ/TBNZ VMP Reverse Mode Bug Fix

## 问题描述

TBZ/TBNZ 指令在原生模式下通过测试（4/4 PASS），但在 VMP 打包后的 reverse 模式下失败（3/4，TBZ/TBNZ result=1 FAIL）。

## Root Cause

`pkg/binary/elf/packer.go` 中的 `remapBranchTargets` 函数存在两个 bug：

1. **`isBranchOpcode()` 遗漏 TBZ/TBNZ**：该函数未包含 `OpTbz` 和 `OpTbnz`，导致 reverse 模式下 TBZ/TBNZ 的分支目标从未被重映射。

2. **target32 偏移硬编码为 `pc+1`**：标准分支指令是 5 字节格式 `[op][target32]`，target32 在 `pc+1`。但 TBZ/TBNZ 是 7 字节格式 `[op][reg][bit][target32]`，target32 在 `pc+3`。

## 修复方案

将 `isBranchOpcode(op byte) bool` 替换为 `branchTargetOffset(op byte) int`：

- 标准分支（OpJmp, OpJe, ...）→ 返回 1
- TBZ/TBNZ → 返回 3
- 非分支 → 返回 0

`remapBranchTargets` 使用返回的偏移值读写 target32，而非硬编码 `pc+1`。

## 修改文件

- `pkg/binary/elf/packer.go`（~行 934-1030）

## 验证状态

- [x] `make all` 编译通过
- [ ] ARM64 设备 VMP Standard 模式测试
- [ ] ARM64 设备 VMP Token 模式测试

## 测试脚本

`test_vmp_insn_tbz.sh`
