# Task 3: VM 解释器栈溢出 & 内存泄漏审计报告

## 审计范围

对 VM 解释器全部 C stub 代码进行安全审计，重点检查：
- 栈溢出 / 缓冲区越界
- 内存泄漏
- 未验证的指针解引用

## 审计发现

| # | 严重度 | 问题 | 文件 |
|---|--------|------|------|
| 1 | 🔴 CRITICAL | VM 内存栈无边界检查，SP 可下溢越界 | `vm_types.h`, `h_mem.h` |
| 2 | 🟡 MEDIUM | 字节码操作数越界读取，handler 不检查 pc+size | `vm_decode.h`, `vm_interp_clean.c` |
| 3 | 🟡 MEDIUM | 分支目标未验证，可跳转到任意偏移 | `h_branch.h` |
| 4 | 🟢 LOW | PUSH/POP 溢出静默忽略，无错误指示 | `h_stack.h` |
| 5 | ✅ OK | 无内存泄漏 — mmap/munmap 正确配对 | `vm_interp_clean.c` |

## 修复详情

### Fix 1: 内存栈边界保护 (CRITICAL)
