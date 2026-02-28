#!/bin/bash
# test_vmp_modes.sh — VMP 普通模式 + Token 模式 端到端测试
# 在 ARM64 Linux 设备上运行
# 前置: 将 build/ 下的 .vmp 文件推送到 /home/root/vmp/

set -e
PASS=0
FAIL=0
TOTAL=0

check() {
    local desc="$1" cmd="$2" expected="$3"
    TOTAL=$((TOTAL+1))
    result=$(eval "$cmd" 2>&1) || true
    if echo "$result" | grep -qF "$expected"; then
        echo "[PASS] $desc"
        PASS=$((PASS+1))
    else
        echo "[FAIL] $desc"
        echo "  expected: $expected"
        echo "  got:      $result"
        FAIL=$((FAIL+1))
    fi
}

echo "=== VMP Mode Test ==="
echo ""

# --- 普通模式 (Standard) ---
echo "--- Standard Mode ---"
check "C license valid (std)" \
    "/home/root/vmp/demo_license_std.vmp 12345678" \
    "[+] License valid!"

check "C license invalid (std)" \
    "/home/root/vmp/demo_license_std.vmp 00000000" \
    "[-] License invalid."

# --- Token 模式 ---
echo ""
echo "--- Token Mode ---"
check "C license valid (token)" \
    "/home/root/vmp/demo_license_token.vmp 12345678" \
    "[+] License valid!"

check "C license invalid (token)" \
    "/home/root/vmp/demo_license_token.vmp 00000000" \
    "[-] License invalid."

check "Go checkKey (token)" \
    "/home/root/vmp/demo_go_test_token.vmp" \
    "checkKey(10) = 143"

echo ""
echo "=== Result: $PASS/$TOTAL passed, $FAIL failed ==="
[ $FAIL -eq 0 ] && exit 0 || exit 1
