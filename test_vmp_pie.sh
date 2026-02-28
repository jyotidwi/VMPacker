#!/bin/bash
# test_vmp_pie.sh — PIE (ET_DYN) VMP 回归测试脚本
# 在 Windows 上通过 adb 推送到 ARM64 设备执行
#
# 用法: bash test_vmp_pie.sh
# 前提: make all 已完成, adb 已连接

set -e
DEVICE_DIR="/home/root/vmp"
BUILD="build"
PASS=0
FAIL=0

run_test() {
    local name="$1" file="$2" expected="$3"
    echo -n "  [$name] "
    adb push "$BUILD/$file" "$DEVICE_DIR/" > /dev/null 2>&1
    adb shell "chmod +x $DEVICE_DIR/$file" > /dev/null 2>&1
    output=$(adb shell "$DEVICE_DIR/$file" 2>&1)
    if echo "$output" | grep -q "$expected"; then
        echo "PASS ($expected)"
        PASS=$((PASS+1))
    else
        echo "FAIL (expected: $expected, got: $output)"
        FAIL=$((FAIL+1))
    fi
}

echo "=== VMP PIE 回归测试 ==="
echo ""

# 1. C ET_EXEC
echo "[C ET_EXEC]"
run_test "demo_insn_add" "demo_insn_add.vmp" "PASS:ADD:42"

# 2. Go ET_EXEC
echo "[Go ET_EXEC]"
run_test "demo_go_test" "demo_go_test_token.vmp" "checkKey(10) = 143"

# 3. Rust ET_EXEC
echo "[Rust ET_EXEC]"
run_test "demo_rust_test" "demo_rust_test_token.vmp" "checkKey(10) = 143"

# 4. Rust ET_DYN (PIE) — 关键测试
echo "[Rust ET_DYN (PIE)]"
run_test "demo_rust_test_pie" "demo_rust_test_pie.vmp" "checkKey(10) = 143"

echo ""
echo "=== 结果: $PASS passed, $FAIL failed ==="
[ $FAIL -eq 0 ] && echo "[+] ALL PASS" || echo "[-] SOME FAILED"
