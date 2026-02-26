# 调试信息清除 & OpcodeCryptor/PC反向遍历 Bug 审查

## 修改内容

### 清除调试信息 (`stub/vm_interp_clean.c`)

1. **删除 `dbg_write()` 函数** — syscall 写 stderr 的底层函数
2. **删除 `dbg_hex()` 函数** — 十六进制格式化输出函数
3. **删除 DISPATCH 宏中的调试调用**:
   ```c
   // 已删除:
   dbg_hex("PC=", vm.pc);
   dbg_hex("OP=", _dec_op);
   ```
   这两行在每条 VM 指令分发时都会触发 `svc #0` 系统调用写 stderr，造成：
   - 严重性能损耗（每条指令 2 次 syscall）
   - 信息泄露（暴露 PC 值和解密后的 opcode）

## 审查结论

| 模块 | 状态 | 说明 |
|------|------|------|
| OpcodeCryptor 加密 (Go) | ✅ 正确 | `encryptOpcodes` 公式、类型、reversed 跳步均正确 |
| OpcodeCryptor 解密 (C) | ✅ 正确 | `OC_DECRYPT` 宏与 Go 侧完全一致 |
| PC 反向遍历 DISPATCH | ✅ 正确 | `pc--; sz=bc[pc]; pc-=sz` 逻辑与 offsetMap 配合正确 |
| 分支目标重映射 | ✅ 正确 | `remapBranchTargets` + `BRANCH_FALLTHROUGH` 均正确 |
| addr_map 重映射 | ✅ 正确 | Process() 中对 vm_off 做了 offsetMap 转换 |
| Trailer 解析 | ✅ 正确 | C 侧读取顺序与 Go 侧写入顺序一致 |
| Handler 操作数读取 | ✅ 正确 | reverse 模式下 pc 已指向指令起始 |
| 调试信息 | 🔧 已修复 | 清除 dbg_write/dbg_hex 及 DISPATCH 中的调用 |
