#!/bin/bash
# ============================================================
# VMP 混淆技术端到端测试脚本
# ============================================================

set +e

ADB="adb -s 192.168.1.1:5555"
PACKER="./build/vmpacker.exe"
DEVICE_DIR="/home/root/vmp"
TMPOUT="/tmp/vmp_test_out.txt"
PASS=0
FAIL=0

green() { echo -e "\033[32m[PASS]\033[0m $1"; PASS=$((PASS+1)); }
red()   { echo -e "\033[31m[FAIL]\033[0m $1"; FAIL=$((FAIL+1)); }
info()  { echo -e "\033[36m[INFO]\033[0m $1"; }

# 推送并运行，输出写入 TMPOUT
push_and_run() {
    local vmp="$1"; shift
    local remote="$DEVICE_DIR/$(basename $vmp)"
    $ADB push "$vmp" "$remote" > /dev/null 2>&1
    $ADB shell "chmod +x $remote; $remote $*" > "$TMPOUT" 2>&1
}

# 推送并运行，获取退出码写入 TMPOUT
push_and_run_rc() {
    local vmp="$1"; shift
    local remote="$DEVICE_DIR/$(basename $vmp)"
    $ADB push "$vmp" "$remote" > /dev/null 2>&1
    $ADB shell "chmod +x $remote; $remote $*; echo EXITRC=\$?" > "$TMPOUT" 2>&1
}

# ============================================================
info "=== 测试 1: Token 模式 — demo_simple ==="
$PACKER -func check_simple -token -o build/demo_simple_tok.vmp build/demo_simple > /dev/null 2>&1
push_and_run_rc build/demo_simple_tok.vmp
RC=$(cat "$TMPOUT" | tr -d '\r' | grep 'EXITRC=' | sed 's/EXITRC=//' | tr -d ' \n')
if [ "$RC" = "37" ]; then
    green "demo_simple Token 退出码=37"
else
    red "demo_simple Token 退出码 (expected 37, got '$RC')"
fi

# ============================================================
info "=== 测试 2: Standard 模式 — demo_license ==="
$PACKER -func check_license -o build/demo_license_std.vmp build/demo_license > /dev/null 2>&1

push_and_run build/demo_license_std.vmp 12345678
OUT=$(cat "$TMPOUT" | tr -d '\r')
if echo "$OUT" | grep -q 'License valid'; then
    green "demo_license Standard valid key"
else
    red "demo_license Standard valid key (got: '$OUT')"
fi

push_and_run build/demo_license_std.vmp 00000000
OUT=$(cat "$TMPOUT" | tr -d '\r')
if echo "$OUT" | grep -q 'License invalid'; then
    green "demo_license Standard invalid key"
else
    red "demo_license Standard invalid key (got: '$OUT')"
fi

# ============================================================
info "=== 测试 3: Token 模式 — demo_license ==="
$PACKER -func check_license -token -o build/demo_license_tok.vmp build/demo_license > /dev/null 2>&1

push_and_run build/demo_license_tok.vmp 12345678
OUT=$(cat "$TMPOUT" | tr -d '\r')
if echo "$OUT" | grep -q 'License valid'; then
    green "demo_license Token valid key"
else
    red "demo_license Token valid key (got: '$OUT')"
fi

push_and_run build/demo_license_tok.vmp 00000000
OUT=$(cat "$TMPOUT" | tr -d '\r')
if echo "$OUT" | grep -q 'License invalid'; then
    green "demo_license Token invalid key"
else
    red "demo_license Token invalid key (got: '$OUT')"
fi

# ============================================================
info "=== 测试 4: Unsupported Instruction Abort ==="
$PACKER -func _start -o build/demo_simple_start.vmp build/demo_simple > "$TMPOUT" 2>&1
if grep -q "unsupported instruction" "$TMPOUT"; then
    green "Unsupported instruction 正确中止"
else
    red "Unsupported instruction 未中止"
fi

# ============================================================
info "=== 测试 5: rsa_verify_demo Token 模式 ==="
if [ -f "vmp2.0/rsa_verify_demo" ]; then
    $PACKER -func rsa_pss_verify -token -o build/rsa_verify_demo.vmp vmp2.0/rsa_verify_demo > /dev/null 2>&1
    REMOTE="$DEVICE_DIR/rsa_verify_demo.vmp"
    $ADB push build/rsa_verify_demo.vmp "$REMOTE" > /dev/null 2>&1
    $ADB shell "chmod +x $REMOTE; echo test_key_123 | $REMOTE" > "$TMPOUT" 2>&1
    OUT=$(cat "$TMPOUT" | tr -d '\r')
    if echo "$OUT" | grep -q 'VERIFY_FAILED'; then
        green "rsa_verify_demo Token"
    else
        red "rsa_verify_demo Token (got: '$OUT')"
    fi
else
    info "跳过: vmp2.0/rsa_verify_demo 不存在"
fi

# ============================================================
rm -f "$TMPOUT"
echo ""
echo "========================================"
echo "  测试结果: $PASS 通过, $FAIL 失败"
echo "========================================"
[ $FAIL -gt 0 ] && exit 1 || exit 0
