# VMP 内存泄漏审计报告

## 审计结论：无内存泄漏 ✅

## 审计范围

| 文件 | 组件 | 状态 |
|------|------|------|
| `stub/vm_interp_clean.c` | `vm_entry()` 主函数 | ✅ 无泄漏 |
| `stub/vm_interp_clean.c` | `vm_entry_token_inner()` | ✅ 无分配 |
| `stub/vm_handlers/h_system.h` | CALL_NAT / BR_REG / VLD16 / VST16 | ✅ 无分配 |
| `stub/vm_handlers/h_branch.h` | 所有分支 handler | ✅ 无分配 |
| `stub/vm_handlers/h_alu.h` | 所有 ALU handler | ✅ 无分配 |
| `stub/vm_handlers/h_mem.h` | LOAD/STORE handler | ✅ 无分配 |
| `stub/vm_handlers/h_mov.h` | MOV handler | ✅ 无分配 |
| `stub/vm_handlers/h_stack.h` | PUSH/POP handler | ✅ 无分配 |
| `stub/vm_handlers/h_cmp.h` | CMP handler | ✅ 无分配 |

## vm_entry() 分配/释放配对

```
分配1: bc_buf = sys_mmap(alloc_size)     → cleanup: sys_munmap(bc_buf, alloc_size)  ✅
分配2: vm    = sys_mmap(ctx_alloc)       → cleanup: sys_munmap(vm, ctx_alloc)       ✅
```

## 错误路径分析

| 错误路径 | 处理方式 | 状态 |
|----------|---------|------|
| `bc_buf` mmap 失败 | `return 0`（mmap 返回错误码，无需释放） | ✅ |
| `vm` mmap 失败 | `sys_munmap(bc_buf, alloc_size); return 0` | ✅ |
| `OP_HALT` | `goto cleanup` | ✅ |
| `OP_RET` | `goto cleanup` | ✅ |
| `L_UNKNOWN` | `ret = vm->R[0]` → fall through to `cleanup` | ✅ |
| 间接 dispatch `VM_STEP_HALT` | `goto cleanup` | ✅ |
| 主循环 `break`（PC 越界等） | fall through to `cleanup` | ✅ |

## 栈上分配（自动释放）

- `vm_jump_table[256]`（间接 dispatch 模式）— 函数返回自动释放
- `dtab[256]`（computed goto 模式）— 函数返回自动释放
- `vm_ctx_t.addr_map` — 指向 `bc_buf` 内部偏移，随 `bc_buf` 一起释放

## 审计日期

2026-03-01
