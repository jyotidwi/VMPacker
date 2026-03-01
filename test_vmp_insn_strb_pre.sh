#!/usr/bin/env bash
# test_vmp_insn_strb_pre.sh — T2: STURB (byte store, unscaled offset) 自动化测试
# 覆盖: Native / VMP Standard / VMP Token 三种模式
set -euo pipefail

DEMO=demo/demo_insn_strb_pre.c
BIN=build/demo_insn_strb_pre
FUNC=test_strb_pre
REMOTE=/home/root/vmp
EXPECTED="STRB_PRE PASS"
PASS=0; FAIL=0

ok()   { echo "[PASS] $1"; ((PASS++)); }
fail() { echo "[FAIL] $1"; ((FAIL++)); }

echo "=== T2: STURB test ==="

# Step 1: 交叉编译
echo "[1/6] Cross-compile..."
aarch64-linux-gnu-gcc -O1 -static -o "$BIN" "$DEMO" || { fail "compile"; exit 1; }
ok "compile"

# Step 2: Native 测试
echo "[2/6] Native test..."
adb push "$BIN" "$REMOTE/demo_insn_strb_pre" >/dev/null
OUT=$(adb shell "chmod +x $REMOTE/demo_insn_strb_pre && $REMOTE/demo_insn_strb_pre" 2>&1)
echo "  $OUT"
[[ "$OUT" == *"$EXPECTED"* ]] && ok "native" || fail "native"

# Step 3: make all
echo "[3/6] make all..."
make all >/dev/null 2>&1 || { fail "make"; exit 1; }
ok "make"

# Step 4: VMP Standard 打包 + 测试
echo "[4/6] VMP Standard..."
./build/vmpacker -func "$FUNC" -debug -v "$BIN" >/dev/null 2>&1
adb push "${BIN}.vmp" "$REMOTE/demo_insn_strb_pre_std.vmp" >/dev/null
OUT=$(adb shell "chmod +x $REMOTE/demo_insn_strb_pre_std.vmp && $REMOTE/demo_insn_strb_pre_std.vmp" 2>&1)
echo "  $OUT"
[[ "$OUT" == *"$EXPECTED"* ]] && ok "standard" || fail "standard"

# Step 5: 重新编译 + VMP Token 打包 + 测试
echo "[5/6] VMP Token..."
aarch64-linux-gnu-gcc -O1 -static -o "$BIN" "$DEMO"
./build/vmpacker -token -func "$FUNC" -debug -v "$BIN" >/dev/null 2>&1
adb push "${BIN}.vmp" "$REMOTE/demo_insn_strb_pre_tok.vmp" >/dev/null
OUT=$(adb shell "chmod +x $REMOTE/demo_insn_strb_pre_tok.vmp && $REMOTE/demo_insn_strb_pre_tok.vmp" 2>&1)
echo "  $OUT"
[[ "$OUT" == *"$EXPECTED"* ]] && ok "token" || fail "token"

# Step 6: 汇总
echo ""
echo "[6/6] Results: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] && echo "=== T2 STURB: ALL PASS ===" || echo "=== T2 STURB: SOME FAILED ==="
exit "$FAIL"
