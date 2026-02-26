# Task 3: PC 反向遍历 (Reverse PC Traversal)

## 概述

实现字节码指令级反转 + 尾部 size 标记方案，使 VM 解释器从字节码末尾向前执行，增加静态分析难度。

## 设计

### 核心思路

1. Packer 在打包时将指令顺序反转，每条指令后追加 1 字节 size 标记
2. Stub 解释器在 reverse 模式下从 `bc_len` 开始，DISPATCH 宏自动递减 PC 定位指令
3. 所有分支目标通过 `offsetMap` 重映射到反转后的新偏移

### Trailer 布局 (21B 固定)

```
[bytecode][BR map entries][reverse(1B)][oc_key(4B)][map_count:u32][func_addr:u64][func_size:u32]
```

### Stub 端 DISPATCH 宏 (reverse 模式)

```c
// pc 指向上一条指令的 size 标记之后
// 步骤: pc--; size = bc[pc]; pc -= size;
if (vm.reverse) {
    if (vm.pc <= 0) goto cleanup;
    vm.pc--;
    u8 _sz = vm.bc[vm.pc];
    vm.pc -= _sz;
}
```

### NEXT 宏 (编译器屏障)

```c
#define NEXT(n) do {                    \
    u32 _adv = (n);                     \
    __asm__ volatile("" ::: "memory");  \
    if (!vm.reverse) vm.pc += _adv;     \
    DISPATCH();                         \
} while(0)
```

关键: `__asm__ volatile("" ::: "memory")` 防止 GCC `-Os` 在 reverse 模式下消除 handler 调用。

### Packer 端处理流程

1. `reverseInstructions()`: 反转指令顺序，追加 size 标记，构建 `offsetMap`
2. `remapBranchTargets()`: 重映射所有分支指令的 target32
3. 重映射 `addr_map` 中的 `vm_off` (BR_REG 间接跳转)
4. `encryptOpcodes()`: 在反转后的字节码上执行 OpcodeCryptor 加密
5. 写入 `reverse=1` 标志到 trailer

### 分支 fall-through 处理

```c
// h_branch.h — reverse 模式下分支不命中时不手动设置 pc
#define BRANCH_FALLTHROUGH(vm, inst_size) \
    do { if (!(vm)->reverse) (vm)->pc += (inst_size); } while(0)
```

## 修改文件

| 文件 | 修改内容 |
|------|---------|
| `stub/vm_types.h` | `vm_ctx_t` 添加 `reverse` 字段 |
| `stub/vm_interp_clean.c` | DISPATCH/NEXT 宏支持 reverse，PC 初始化 |
| `stub/vm_handlers/h_branch.h` | BRANCH_FALLTHROUGH 宏 |
| `pkg/binary/elf/packer.go` | `reverseInstructions()`, `remapBranchTargets()`, trailer 写入 |
| `pkg/vm/disasm.go` | `InstructionSize()` 导出 |

## 关键 Bug 修复

GCC `-Os` 优化会消除 reverse 模式下 handler 的副作用调用。根因: NEXT 宏中 `(n)` 的返回值在 reverse 分支未使用，编译器判定整个 handler 调用可消除。

修复: 添加 compiler barrier `__asm__ volatile("" ::: "memory")` 强制求值。

## 验证

```
$ ./build/vmpacker.exe -func check_oc -v -o build/demo_oc_test.vmp build/demo_oc_test
$ adb -s 192.168.1.1:5555 shell "/home/root/vmp/demo_oc_test.vmp 10 20"
PASS: check_oc(10, 20) = 171056
```
