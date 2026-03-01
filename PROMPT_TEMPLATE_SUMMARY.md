# VMP 指令添加模板 — 工作总结

## 概述

创建了一个可复用的 AI 提示词模板，用于标准化地为 VMP 项目添加新 ARM64 指令支持。

## 文件

| 文件 | 说明 |
|------|------|
| `issues/prompt-add-instruction.md` | 指令添加提示词模板 |

## 模板特性

- **3 Phase 工作流**：Demo 验证 → 壳代码修改 → VMP 打包测试
- **12 文件修改清单**：9 个必改 + 3 个条件修改（`[NEW_OP]` 标记）
- **LDRH 完整示例**：展示从 demo 到 VMP 测试的全流程
- **ARM64 编码变体速查表**：覆盖 LDR/STR、ADD/SUB、AND/ORR/EOR、MOV、Bitfield、Branch 等
- **12 项验证清单**：包含 opcode 一致性、编码变体覆盖、Demo/VMP 双模式测试
- **构建命令速查**：交叉编译、make、VMP 打包、adb 推送一站式参考

## 使用方法

```
1. 复制模板正文
2. 全局替换 {INSTRUCTION} 为目标指令名（如 CLZ、REV、SMULL）
3. 发给 AI，按 Phase 1→2→3 逐步执行
```

## Git

- Commit: `1a05899` — `docs: beautify instruction-adding prompt template with 3-phase workflow`
- Push: `master → origin/master` ✅
