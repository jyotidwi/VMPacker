# VMP Stub 保护问题分析报告

## 问题概述

VMP保护后的stub在设备上运行时发生SIGSEGV崩溃，原始未保护的stub运行正常。

## 测试结果

| 测试场景 | 文件 | Stub大小 | 运行结果 |
|---------|------|---------|---------|
| 原始程序 | hello | - | ✅ 正常输出 "Hello from ARM64!" |
| 原始stub加壳 | hello_plain.packed | 5570字节 | ✅ 正常输出 "Hello from ARM64!" |
| VMP stub加壳 | hello_vmp_stub.packed | 76936字节 | ❌ SIGSEGV崩溃 |

## 根本原因

### 1. VMP保护后的ELF结构变化

**原始 stub.elf:**
```
Program Headers:
  LOAD  0x10001000  size=0x15C2  (RWE)  [.text段]
  NOTE  0x100025C4  size=0x10    (R)    [.note.vmp]
```

**VMP后 stub.elf.vmp:**
```
Program Headers:
  LOAD  0x10001000  size=0x15C2  (RWE)  [.text段 - 包含VM跳板]
  LOAD  0x10010000  size=0x3C88  (R E)  [VM解释器 + 字节码段]
```

### 2. objcopy提取问题

**当前Makefile命令:**
```makefile
$(OBJCOPY) -O binary $(BUILD)/stub.elf.vmp $@
```

**问题分析:**
- VMP在ELF中添加了第二个LOAD段（VMA=0x10010000），存放VM解释器和字节码
- 这个LOAD段**没有对应的section header**（无名段）
- `objcopy -O binary` 默认只提取有section header的内容
- 结果：只提取了.text段（5588字节），VM解释器段丢失

**当前stub.vmp.bin的76936字节构成:**
```
0x10001000: .text段 (0x15C2字节)
0x100025C2 - 0x10010000: 空洞/填充 (0xDA3E = 55870字节)
0x10010000: VM解释器+字节码 (0x3C88 = 15496字节)
总计: 0x12C88 = 76936字节
```

这说明之前某次构建用了不同的提取方式（可能手动dd或其他工具），包含了中间的gap。

### 3. 运行时崩溃机制

1. stub_main被VMP替换成VM跳板（3条指令）
2. 跳板跳转到0x10010000处的VM解释器
3. 但objcopy只提取了.text段，VM解释器代码不在binary中
4. 运行时跳转到无效地址 → SIGSEGV

## 内存布局对比

### 原始stub (5570字节)
```
0x10001000: _start
0x10001074: data_start (压缩数据开始)
0x100013C0: stub_main (原生ARM64代码)
```

### VMP stub (应该是 0x15C2 + 0x3C88 = 21930字节，不含gap)
```
0x10001000: _start
0x10001074: data_start
0x100013C0: stub_main跳板 (跳转到0x10010000)
...
0x10010000: VM解释器入口
0x10010xxx: VM字节码 (stub_main的7151字节字节码)
```

## VMP保护细节

### stub_main函数特征
- 大小: 1844字节 (0x734)
- 翻译后VM字节码: 7151字节
- 包含大量系统调用（mmap、mprotect、read等）
- 包含内联汇编 `svc #0`
- 调用外部函数: get1, ss11, fail, load_interp, sync_cache_range等

### VMP翻译统计
- SVC指令: 仅2个被翻译（实际应该有更多系统调用）
- CALL指令: 27个（调用外部原生函数）
- 问题: 编译器将syscall内联函数的部分逻辑提取成了独立函数（get1, ss11），导致VMP需要频繁跳出VM执行原生代码

## 解决方案

### 方案1: 修复objcopy提取（推荐）

修改Makefile，使用自定义脚本提取所有LOAD段：

```makefile
$(BUILD)/stub.vmp.bin: $(BUILD)/stub.elf.vmp
	python3 extract_load_segments.py $(BUILD)/stub.elf.vmp $@
```

**extract_load_segments.py伪代码:**
```python
1. 解析ELF header，读取所有LOAD段的offset和size
2. 计算最小VMA和最大VMA+size
3. 从文件中提取 [min_offset, max_offset] 的连续数据
4. 写入输出文件
```

### 方案2: 使用dd命令直接提取

```makefile
$(BUILD)/stub.vmp.bin: $(BUILD)/stub.elf.vmp
	# 提取从offset 0x1000开始的所有LOAD段数据
	dd if=$(BUILD)/stub.elf.vmp of=$@ bs=1 skip=4096 count=76936
```

### 方案3: 修改vmpacker，将VM段放入.text section

让vmpacker在添加VM段时创建对应的section header，这样objcopy就能识别。

### 方案4: 不保护stub_main（临时方案）

stub_main包含大量系统调用和复杂逻辑，VMP保护可能引入性能问题和兼容性问题。可以考虑：
- 只保护go-packer主程序的关键函数
- 或者保护stub中更小的辅助函数（如integrity检查函数）

## 验证步骤

1. 实现方案1或2，重新生成stub.vmp.bin
2. 确认文件大小约21KB（不含gap）或77KB（含gap）
3. 重新编译go-packer: `cd go-packer; go build -o bin/packer.exe ./cmd/packer/`
4. 加壳测试: `packer.exe -i test/hello -o test/hello_fixed.packed -encrypt`
5. 推送设备测试: `adb push test/hello_fixed.packed /home/root/vmp/`
6. 运行验证: `adb shell "/home/root/vmp/hello_fixed.packed"`

## 技术细节

### ELF LOAD段提取算法

```python
def extract_load_segments(elf_path, output_path):
    with open(elf_path, 'rb') as f:
        # 读取ELF header
        f.seek(32)  # e_phoff offset
        e_phoff = struct.unpack('<Q', f.read(8))[0]
        f.seek(56)  # e_phnum offset
        e_phnum = struct.unpack('<H', f.read(2))[0]
        
        # 读取所有LOAD段
        load_segments = []
        for i in range(e_phnum):
            f.seek(e_phoff + i * 56)
            p_type = struct.unpack('<I', f.read(4))[0]
            if p_type == 1:  # PT_LOAD
                f.seek(e_phoff + i * 56 + 8)
                p_offset = struct.unpack('<Q', f.read(8))[0]
                p_vaddr = struct.unpack('<Q', f.read(8))[0]
                f.read(8)  # skip p_paddr
                p_filesz = struct.unpack('<Q', f.read(8))[0]
                load_segments.append((p_vaddr, p_offset, p_filesz))
        
        # 计算连续范围
        min_vaddr = min(seg[0] for seg in load_segments)
        max_vaddr = max(seg[0] + seg[2] for seg in load_segments)
        min_offset = min(seg[1] for seg in load_segments)
        
        # 提取数据
        f.seek(min_offset)
        data = f.read(max_vaddr - min_vaddr)
        
        with open(output_path, 'wb') as out:
            out.write(data)
```

## 后续优化建议

1. **性能测试**: VMP保护后stub_main的解压性能可能下降，需要测试实际影响
2. **选择性保护**: 考虑只保护关键的完整性检查函数，而不是整个stub_main
3. **编译优化**: 使用 `-O3 -finline-functions` 强制内联syscall函数，减少CALL指令
4. **VM优化**: 优化VM解释器对SVC指令的处理，确保系统调用正确执行

## 相关文件

- `go-packer/stub/Makefile` - 需要修改objcopy命令
- `go-packer/stub/build/stub.elf.vmp` - VMP保护后的ELF
- `go-packer/stub/build/stub.vmp.bin` - 当前错误的binary（缺少VM段）
- `go-packer/stub/embed.go` - Go embed引用
- `cmd/vmpacker/main.go` - VMP保护工具

## 时间线

- 2025-03-01: 发现VMP stub加壳后SIGSEGV崩溃
- 2025-03-01: 确认原始stub加壳正常运行
- 2025-03-01: 分析ELF结构，发现VM段丢失问题
- 待定: 实施修复方案并验证
