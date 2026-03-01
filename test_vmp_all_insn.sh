#!/bin/bash
# test_vmp_all_insn.sh — VMP 全指令覆盖测试脚本
# 用法: bash test_vmp_all_insn.sh
set -e

REMOTE=/home/root/vmp
SRC=demo/demo_all_insn.c
BIN=build/demo_all_insn
VMP_SINGLE=${BIN}.vmp
VMP_FULL=${BIN}_full.vmp

FUNCS="test_alu_reg,test_alu_imm,test_mov,test_load_store,test_load_store_reg,test_branch,test_csel,test_madd_msub,test_bitfield,test_add_sub_ext,test_eon,test_tbz_tbnz,test_ccmp_ccmn,test_adrp_adr,test_simd,test_svc,test_flags_reg,test_eor_shifted,helper_add,test_bl_blr,check_all_insn"

echo "=== [1/5] 编译 ==="
aarch64-linux-gnu-gcc -static -O0 -march=armv8-a $SRC -o $BIN
echo "[+] 编译完成: $BIN"

echo ""
echo "=== [2/5] VMP 保护 (单函数: check_all_insn) ==="
build/vmpacker.exe -func check_all_insn -v -o $VMP_SINGLE $BIN
echo "[+] VMP 完成: $VMP_SINGLE"

echo ""
echo "=== [3/5] VMP 保护 (全函数: 21个) ==="
build/vmpacker.exe -func "$FUNCS" -v -o $VMP_FULL $BIN
echo "[+] VMP 完成: $VMP_FULL"

echo ""
echo "=== [4/5] 推送到设备 ==="
adb shell "mkdir -p $REMOTE" 2>/dev/null || true
adb push $BIN $REMOTE/demo_all_insn
adb push $VMP_SINGLE $REMOTE/demo_all_insn.vmp
adb push $VMP_FULL $REMOTE/demo_all_insn_full.vmp
adb shell "chmod +x $REMOTE/demo_all_insn $REMOTE/demo_all_insn.vmp $REMOTE/demo_all_insn_full.vmp"

echo ""
echo "=== [5/5] 运行测试 ==="
echo "--- [A] 原始版本 ---"
adb shell "$REMOTE/demo_all_insn"
echo ""
echo "--- [B] 单函数 VMP (check_all_insn) ---"
adb shell "$REMOTE/demo_all_insn.vmp"
echo ""
echo "--- [C] 全函数 VMP (21 functions) ---"
adb shell "$REMOTE/demo_all_insn_full.vmp"
