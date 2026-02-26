# VM 解释器安全审计报告 v2

## 审计范围

对 VM 解释器全部 C stub 代码进行安全审计，覆盖：
- 栈溢出 / 缓冲区越界
- 内存泄漏
- 未定义行为 (UB)
- 未验证的指针解引用
- VM 状态篡改风险

## 审计发现与修复

| # | 严重度 | 问题 | 文件 | 状态 |
|---|--------|------|------|------|
| 1 | 🔴 HIGH | 非 SP 寄存器内存访问无保护，可篡改 vm_ctx_t | `h_mem.h` | ✅ 已修复 |
| 2 | 🟡 MEDIUM | ROR 移位量为 0 时 `v << 64` 是 C 标准 UB | `h_alu.h` | ✅ 已修复 |
| 3 | 🟢 OK | 操作栈 PUSH/POP 边界保护 | `h_stack.h` | ✅ 已有保护 |
| 4 | 🟢 OK | SP 内存栈边界保护 | `h_mem.h` | ✅ 已有保护 |
| 5 | 🟢 OK | 分支目标验证 | `h_branch.h` | ✅ 已有保护 |
| 6 | 🟢 OK | PC 越界保护 (DISPATCH 宏) | `vm_interp_clean.c` | ✅ 已有保护 |
| 7 | 🟢 OK | 内存泄漏 (mmap/munmap 配对) | `vm_interp_clean.c` | ✅ 无泄漏 |
| 8 | ⚠️ 设计决策 | CALL_NAT/CALL_REG/BR_REG 无地址验证 | `h_system.h` | 信任边界内 |
| 9 | ⚠️ 设计决策 | VLD16/VST16 指针无验证 | `h_system.h` | 信任边界内 |


## 修复详情

### Fix 1: ROR 零移位 UB (`h_alu.h`)

**问题**：`(v >> n) | (v << (64 - n))` 当 `n=0` 时，`v << 64` 是 C 标准未定义行为（移位量 ≥ 类型宽度）。

**修复**：添加 `n == 0` 短路判断：
```c
if (n == 0) {
    vm->R[d & 31] = v;
} else {
    vm->R[d & 31] = (v >> n) | (v << (64 - n));
}
```

### Fix 2: 非 SP 内存访问 vm_ctx_t 黑名单保护 (`h_mem.h`)

**问题**：LOAD/STORE 仅在 `base == R[31]` (SP) 时做边界检查，通过其他寄存器可以读写任意内存，包括 vm_ctx_t 结构体本身（pc、flags、字节码指针等），恶意字节码可篡改 VM 状态。

**修复**：新增双层保护宏：
```c
/* vm_ctx_t 黑名单: 禁止读写 VM 上下文结构体 */
#define VM_CTX_OVERLAP(vm, addr, width) \
  ((addr) < VM_CTX_HI(vm) && ((addr) + (width)) > VM_CTX_LO(vm))

/* 通用检查: NULL + vm_ctx_t 黑名单 */
#define VM_MEM_SAFE(vm, addr, width) \
  ((addr) != 0 && !VM_CTX_OVERLAP(vm, addr, width))
```

所有 6 个 LOAD/STORE handler 均已更新：
- SP 路径：保持原有 `VM_STK_CHECK` 白名单
- 非 SP 路径：新增 `VM_MEM_SAFE` 黑名单（NULL 检查 + vm_ctx_t 重叠检测）

### 设计决策说明

以下项目属于 VM 信任边界内的设计决策，未做修改：

- **CALL_NAT / CALL_REG / BR_REG**：字节码中的地址直接作为函数指针调用。字节码由 packer 生成，属于可信输入。
- **VLD16 / VST16**：SIMD 操作的源/目标指针来自寄存器，vtmp 缓冲区有 `VM_SIMD_BUF` 限制不会溢出。

## 编译验证

```
$ make clean; make stub
aarch64-linux-gnu-gcc ... stub/vm_interp_clean.c → 0 warnings, 0 errors
[+] vm_interp.bin: 13658 bytes
```

## 影响评估

| 修复项 | 性能影响 | 兼容性影响 |
|--------|---------|-----------|
| ROR UB | 无（仅增加一个分支判断） | 无 |
| vm_ctx_t 黑名单 | 极低（每次非 SP 内存访问增加 2 次比较） | 无（正常字节码不会访问 vm_ctx_t） |
