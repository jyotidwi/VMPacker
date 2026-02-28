# VMP 解释器隐藏技术实现指南

> 基于 `rsa_verify_demo_vmp` (ARM64 ELF) 逆向分析提取的3项核心混淆技术

---

## 技术4：间接Dispatch (Indirect Dispatch via Jump Table)

### 原理

传统VM dispatch使用 `switch-case`，编译器生成直接跳转表，IDA可以完整恢复所有case。
间接dispatch通过**相对偏移 + 基址计算**实现handler跳转，静态分析工具无法追踪目标。

### 原始样本中的实现

```asm
; rsa_verify_demo_vmp @ 0x566BB8
LDRSW X8, [X2, X9, LSL#2]   ; X2=跳转表基址, X9=opcode, 加载32位有符号偏移
ADD   X8, X8, X2             ; handler绝对地址 = 偏移 + 基址
BR    X8                      ; 间接跳转
```

**关键设计点**：
- 跳转表存储的是**相对偏移**而非绝对地址，重定位后仍然有效
- `LDRSW` 加载32位有符号值并符号扩展到64位，支持前后方向跳转
- `BR X8` 是寄存器间接跳转，IDA无法静态确定所有目标

### 对抗效果

| 分析工具 | 效果 |
|----------|------|
| IDA Pro | 无法追踪BR X8的所有目标，交叉引用断裂 |
| Ghidra | 同上，switch recovery失败 |
| Binary Ninja | 需要手动指定跳转表范围 |
| 符号执行 | 需要具体化X2和X9才能求解 |

### C语言实现要点

```c
// 跳转表存储相对偏移
static const int32_t handler_offsets[256] = {
    [OPCODE_ADD] = (int32_t)((char*)handler_add - (char*)handler_offsets),
    [OPCODE_SUB] = (int32_t)((char*)handler_sub - (char*)handler_offsets),
    // ...
};

// dispatch: 基址 + 偏移 → 间接调用
void *base = (void*)handler_offsets;
int32_t offset = handler_offsets[opcode];
void (*handler)(vm_ctx*) = (void(*)(vm_ctx*))((char*)base + offset);
handler(ctx);
```

---

## 技术5：多函数分裂 (Function Splitting / JUMPOUT)

### 原理

将VM解释器的逻辑**分散到多个不连续的函数中**，通过无条件跳转(B/JMP)而非函数调用(BL/CALL)连接。
IDA的函数识别算法基于prologue/epilogue匹配，跨函数的B跳转会被识别为JUMPOUT，导致函数边界错误。

### 原始样本中的实现

```
VM逻辑分布:
├── sub_575C9C (1313基本块) ─── 主解释器
│   ├── 0x577108: VM入口点(start跳转目标)
│   └── 内部handler群
├── sub_5671B0 (71基本块) ─── dispatcher + 部分handler
│   ├── 0x56F8D8: opcode fetch核心
│   └── 0x566BB8: 跳转表dispatch
└── sub_61DDAC ─── 栈检查/扩展

JUMPOUT连接:
  JUMPOUT__3 (0x5689F4) ──→ 0x56F8D8 (跨函数跳到dispatcher)
  JUMPOUT__1 (0x60BFA8) ──→ 0x56F8D8
  JUMPOUT__0 (0x616214) ──→ 0x56F8D8
  JUMPOUT__4 (0x6161F8) ──→ 0x577108 (跨函数跳到解释器内部)
```

**关键设计点**：
- 使用 `B`(无条件跳转) 而非 `BL`(函数调用)，不保存返回地址
- handler分散在 0x56xxxx ~ 0x61xxxx 范围内（跨度753KB）
- IDA将每个片段识别为独立函数，无法还原完整控制流

### 对抗效果

| 分析工具 | 效果 |
|----------|------|
| IDA Pro | 函数识别错误，生成JUMPOUT伪函数 |
| Ghidra | 函数边界错误，反编译不完整 |
| 人工分析 | 需要在753KB范围内反复跳转，极其痛苦 |
| 自动化脚本 | 需要手动合并函数才能分析 |

### C语言实现要点

```c
// 使用 __attribute__((section)) 将handler放到不同section
__attribute__((section(".text.vm_part1")))
void handler_add(vm_ctx *ctx) {
    // ... 执行ADD
    goto *ctx->dispatch_addr;  // 跳回dispatcher，不用return
}

__attribute__((section(".text.vm_part3")))
void handler_sub(vm_ctx *ctx) {
    // ... 执行SUB
    goto *ctx->dispatch_addr;
}

// 或者使用内联汇编强制跳转
#define JUMPOUT(addr) asm volatile("b " #addr)
```

---

## 技术6：Token化入口 (Tokenized Entry Point)

### 原理

被VMP保护的函数不直接调用VM解释器，而是通过一个**trampoline stub**：
1. 将唯一token加载到寄存器
2. 无条件跳转到VM入口
3. VM根据token查找对应的字节码和上下文

### 原始样本中的实现

```asm
; start @ 0x60FD74 (被保护的入口函数)
MOV   W0, #0x44F4              ; token低16位
MOVK  W0, #0x44D8, LSL#16     ; token = 0x44D844F4
B     0x577108                  ; 跳转到VM解释器入口
```

**关键设计点**：
- 每个被保护函数只有3条指令（MOV + MOVK + B），极小的stub
- Token编码信息：函数ID、字节码偏移、解密密钥等
- 所有被保护函数共享同一个VM入口，统一dispatch

### Token设计建议

```
Token 32位布局:
┌─────────────┬──────────────┬────────────┐
│ bits[31:24] │ bits[23:12]  │ bits[11:0] │
│  XOR密钥    │  字节码偏移   │  函数ID    │
│  (8 bits)   │  (12 bits)   │  (12 bits) │
└─────────────┴──────────────┴────────────┘

解码: func_id   = token & 0xFFF
      bc_offset = (token >> 12) & 0xFFF
      xor_key   = (token >> 24) & 0xFF
```

### 对抗效果

| 分析工具 | 效果 |
|----------|------|
| IDA Pro | 入口函数只有3条指令，看不到任何业务逻辑 |
| 字符串分析 | 无法通过字符串定位功能函数 |
| 交叉引用 | 所有被保护函数都指向同一个VM入口 |
| 动态分析 | 需要理解token编码才能追踪具体函数 |

---

## 三技术组合架构图

```
被保护函数A                    被保护函数B
┌──────────┐                  ┌──────────┐
│ MOV token_A                 │ MOV token_B
│ B vm_entry │                │ B vm_entry │
└─────┬──────┘                └─────┬──────┘
      │                             │
      └──────────┬──────────────────┘
                 ▼
         ┌───────────────┐
         │  VM Entry      │  ← Token化入口(技术6)
         │  解码token     │
         │  查找字节码    │
         └───────┬───────┘
                 ▼
         ┌───────────────┐
         │  Dispatcher    │  ← 间接Dispatch(技术4)
         │  fetch opcode  │
         │  table[op]+base│
         │  BR X8         │
         └───┬───┬───┬───┘
             │   │   │
    ┌────────┘   │   └────────┐
    ▼            ▼            ▼
┌────────┐ ┌────────┐ ┌────────┐
│handler1│ │handler2│ │handler3│  ← 多函数分裂(技术5)
│.part_a │ │.part_c │ │.part_f │    分散在不同section
│ B disp │ │ B disp │ │ B disp │
└────────┘ └────────┘ └────────┘
```

---

## 编译与测试

```bash
# ARM64交叉编译
aarch64-linux-gnu-gcc -O1 -o vmp_demo vmp_demo.c -static

# x86_64本地编译（demo用computed goto，两个平台都支持）
gcc -O1 -o vmp_demo vmp_demo.c
```
