#!/bin/bash
# TBZ/TBNZ 指令 VMP 打包测试脚本
# 使用 demo_insn_remaining.c 中的 TBZ/TBNZ 测试用例
set -e

VMPACKER=./build/vmpacker
DEMO_SRC=demo/demo_insn_remaining.c
DEMO_BIN=build/demo_insn_remaining
FUNC=test_remaining

echo "=== TBZ/TBNZ VMP Test ==="

# 1. 编译原生 demo
echo "[1] Compiling native demo..."
aarch64-linux-gnu-gcc -O0 -static -o $DEMO_BIN $DEMO_SRC
echo "    Native build OK"

# 2. 原生运行
echo "[2] Running native..."
NATIVE_OUT=$(adb push $DEMO_BIN /data/local/tmp/ && adb shell /data/local/tmp/demo_insn_remaining)
echo "    $NATIVE_OUT"

# 3. Standard 模式打包
echo "[3] VMP Standard mode..."
$VMPACKER -in $DEMO_BIN -out build/demo_insn_remaining.vmp -func $FUNC -debug -v
adb push build/demo_insn_remaining.vmp /data/local/tmp/demo_insn_remaining_vmp
adb shell chmod +x /data/local/tmp/demo_insn_remaining_vmp
STD_OUT=$(adb shell /data/local/tmp/demo_insn_remaining_vmp)
echo "    Standard: $STD_OUT"

# 4. Token 模式打包
echo "[4] VMP Token mode..."
$VMPACKER -in $DEMO_BIN -out build/demo_insn_remaining.vmp.tok -func $FUNC -token -debug -v
adb push build/demo_insn_remaining.vmp.tok /data/local/tmp/demo_insn_remaining_tok
adb shell chmod +x /data/local/tmp/demo_insn_remaining_tok
TOK_OUT=$(adb shell /data/local/tmp/demo_insn_remaining_tok)
echo "    Token: $TOK_OUT"

echo ""
echo "=== Done ==="
