#!/bin/bash
# VMP 自动化测试脚本 - 在 ARM64 设备上运行
# 用法: adb push test_vmp_all.sh /home/root/vmp/; adb shell "chmod +x /home/root/vmp/test_vmp_all.sh; /home/root/vmp/test_vmp_all.sh"

PASS=0
FAIL=0
TOTAL=0
DIR="/home/root/vmp"

run_test() {
    local name="$1"
    local binary="$2"
    local expect="$3"
    TOTAL=$((TOTAL + 1))
    
    output=$("$DIR/$binary" 2>&1)
    exitcode=$?
    
    # 用 printf 避免换行问题，用 grep -F 固定字符串匹配
    if printf '%s' "$output" | grep -qF "$expect"; then
        echo "[PASS] $name (exit=$exitcode)"
        PASS=$((PASS + 1))
    else
        echo "[FAIL] $name: expected '$expect', got: $output (exit=$exitcode)"
        FAIL=$((FAIL + 1))
    fi
}

echo "========================================="
echo "  VMP 自动化回归测试"
echo "========================================="
echo ""

# Go 测试
if [ -f "$DIR/demo_go_test_token.vmp" ]; then
    run_test "Go-checkKey-Token" "demo_go_test_token.vmp" "[+] OK"
fi

# C 测试
if [ -f "$DIR/demo_insn_add.vmp" ]; then
    run_test "C-ADD-Token" "demo_insn_add.vmp" "PASS:ADD"
fi

# Rust 测试
if [ -f "$DIR/demo_rust_test_token.vmp" ]; then
    run_test "Rust-checkKey-Token" "demo_rust_test_token.vmp" "[+] OK"
fi

echo ""
echo "========================================="
echo "  结果: $PASS/$TOTAL 通过, $FAIL 失败"
echo "========================================="

[ $FAIL -eq 0 ] && exit 0 || exit 1
