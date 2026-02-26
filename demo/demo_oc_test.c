/*
 * demo_oc_test.c — OpcodeCryptor 验证 demo
 *
 * 纯计算函数，无外部调用，用于验证 opcode 加密后 VM 执行正确性。
 * check_oc(a, b) = ((a ^ 0xDEAD) + b) * 3 - 1
 *
 * 编译: aarch64-linux-gnu-gcc -static -O1 -o demo_oc_test demo_oc_test.c
 * 保护: vmpacker -func check_oc -v -o demo_oc_test.vmp demo_oc_test
 * 测试: ./demo_oc_test.vmp
 *        期望输出: PASS (exit 0)
 *
 * 验证逻辑:
 *   check_oc(10, 20) == ((10 ^ 0xDEAD) + 20) * 3 - 1
 *                     == (0xDEA7 + 20) * 3 - 1
 *                     == 0xDEBB * 3 - 1
 *                     == 0x29C31 - 1
 *                     == 0x29C30
 *                     == 171056
 */
#include <stdio.h>

int check_oc(long a, long b) {
    long x = a ^ 0xDEAD;
    long y = x + b;
    long z = y * 3;
    long w = z - 1;
    /* 填充: 确保函数 >= 72 字节 (18 条 ARM64 指令) 以容纳跳板 */
    __asm__ volatile("nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop; nop");
    return (int)w;
}

int main(void) {
    int result = check_oc(10, 20);
    int expected = 171056;

    if (result == expected) {
        printf("PASS: check_oc(10, 20) = %d\n", result);
        return 0;
    } else {
        printf("FAIL: check_oc(10, 20) = %d, expected %d\n", result, expected);
        return 1;
    }
}
