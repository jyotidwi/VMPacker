# SIGILL 修复心得

> 日期: 2026-02-26 | 项目: VMP ARM64 虚拟化保护

---

## 一、问题现象

`rsa_verify_demo.vmp` 运行时输出 Device Serial 和 Activation Code 后崩溃：

```
Illegal instruction (SIGILL)
```

`original_arm64.vmp`（无 `BR Xn` 指令）运行正常。

---

## 二、定位过程

| 步骤 | 操作 | 结果 |
|------|------|------|
| 1 | 启用全量 trace（每条 VM 指令打印 `pc=/op=`） | 获取 crash 前最后执行的 opcode |
| 2 | `default` case 改为打印 UNKNOWN_OP 并停机 | 排除 pc 飘移导致执行垃圾字节码的假设 |
| 3 | 日志末尾：`pc=0x0459, op=0xCD` | **确认 crash 在 `OP_BR_REG (0xCD)` handler 内部** |
| 4 | 反汇编 `main+0x2F0` | 发现 `br x0` 用于 switch-case 跳转表（computed goto） |
| 5 | 审查 `h_br_reg` 代码 | 确认错误：一律将 BR 当外部函数指针调用 |

---

## 三、Root Cause

```
ARM64 编译器用 BR X0 实现 switch-case 跳转表：
  adr  X1, .Ljump_table
  ldr  X0, [X1, X0, lsl #3]
  br   X0                    ← 跳到 main 函数内部某 case 代码块

但 h_br_reg 把 R[0] 当作函数指针:
  native_fn_t fn = (native_fn_t)addr;
  fn(R[0], R[1], ...);      ← 目标是函数中间地址, 没有 prologue → SIGILL
```

VMP 保护后原始函数体被 trampoline + garbage 覆盖，BR 跳到的原始代码地址已不存在。

---

## 四、修复方案

**核心思想**：翻译器在编译期生成「ARM64 偏移 → VM 字节码偏移」映射表嵌入字节码尾部，VM 运行时查表做内部跳转。

### 4.1 字节码 Trailer 格式

```
[...VM bytecode...][map entries][map_count:u32][func_addr:u64][func_size:u32]
                    └─ 每条 entry: [arm64_off:u32][vm_off:u32] = 8B
```

### 4.2 修改的文件

| 文件 | 修改内容 |
|------|---------|
| `vm_types.h` | `vm_ctx_t` 新增 `func_addr/func_size/addr_map/map_count` |
| `vm_interp_clean.c` | `vm_entry` 解析字节码尾部 trailer |
| `h_system.h` | `h_br_reg` 区分内部跳转 vs 外部尾调用 |
| `translator.go` | `Translate()` 末尾序列化 `labels` 映射表 |

### 4.3 h_br_reg 核心逻辑

```c
if (目标在 [func_addr, func_addr+func_size) 内) {
    arm64_off = addr - func_addr;
    二分查找 addr_map → 设置 vm.pc = vm_off;
    return 0;   // 不 advance
} else {
    native_fn_t fn = (native_fn_t)addr;
    fn(...);    // 真正的尾调用
    return 2;
}
```

---

## 五、后续优化 (同期完成)

### 5.1 安全修复

| 修复 | 效果 |
|------|------|
| `bc_buf[65536]` → `sys_mmap()` 动态分配 | 栈帧 70KB → 7KB，防栈溢出 |
| `goto cleanup` + `sys_munmap()` 统一出口 | 所有 return 路径均释放内存，防泄漏 |
| 纯 syscall 实现（`__NR_mmap=222`, `__NR_munmap=215`） | 无 libc 依赖 |

### 5.2 性能优化

| 优化 | 原理 | 预期收益 |
|------|------|---------|
| Computed goto 分发表 | 每个 handler 末尾独立 indirect jump，消除 CPU 分支预测集中点 | ~20-30% |
| XOR 解密 8 字节加宽 | `u64` 批量异或替代逐字节 | ~8x 解密速度 |
| addr_map 二分查找 | 初始化时插入排序 + O(log n) 查找 | switch 密集场景显著提升 |

### 5.3 -nostdlib 兼容要点

编译 `-nostdlib -fno-builtin` 下 GCC 会将以下操作优化为隐式 `memcpy` 调用：
- 结构体赋值 `a = b` → **需改为字段级拷贝**
- 数组范围初始化 `[0...255] = val` → **需改为循环填充**

---

## 六、调试技巧备忘

1. **全量 trace** 是定位 VM crash 的最可靠手段
2. **default case 改为停机** 可快速排除 pc 飘移类 bug
3. debug 代码保留在源码中（注释状态），取消注释即可重新启用
4. 使用 `dbg_hex` 通过 `__NR_write` syscall 直接输出到 stderr，不依赖 libc
