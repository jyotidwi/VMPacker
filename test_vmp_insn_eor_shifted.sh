#!/bin/bash
# test_vmp_insn_eor_shifted.sh
# T1: EOR shifted register (LSR/ASR/ROR) 自动化测试脚本
# 用法: bash test_vmp_insn_eor_shifted.sh
set -e

DEMO=demo_insn_eor_shifted
FUNC=test_eor_shifted
BUILD=build
DEVICE_DIR=/home/root/vmp

echo "=== T1: EOR shifted register 自动化测试 ==="

# Step 1: 交叉编译
echo "[1/6] 交叉编译 ${DEMO}.c ..."
aarch64-linux-gnu-gcc -O1 -static -o ${BUILD}/${DEMO} demo/${DEMO}.c
echo "      编译成功: ${BUILD}/${DEMO}"

# Step 2: 推送到设备并原生运行
echo "[2/6] 原生运行测试 ..."
adb push ${BUILD}/${DEMO} ${DEVICE_DIR}/${DEMO} > /dev/null
adb shell "chmod +x ${DEVICE_DIR}/${DEMO} && ${DEVICE_DIR}/${DEMO}"
echo "      原生运行 PASS"

# Step 3: VMP Standard 模式打包
echo "[3/6] VMP Standard 模式打包 ..."
./vmpacker -func ${FUNC} -debug -v ${BUILD}/${DEMO}
echo "      Standard 打包成功"

# Step 4: Standard 模式设备测试
echo "[4/6] Standard 模式设备测试 ..."
adb push ${BUILD}/${DEMO} ${DEVICE_DIR}/${DEMO} > /dev/null
adb shell "chmod +x ${DEVICE_DIR}/${DEMO} && ${DEVICE_DIR}/${DEMO}"
echo "      Standard 模式 PASS"

# Step 5: VMP Token 模式打包
echo "[5/6] VMP Token 模式打包 ..."
# 先恢复原始二进制
aarch64-linux-gnu-gcc -O1 -static -o ${BUILD}/${DEMO} demo/${DEMO}.c
./vmpacker -token -func ${FUNC} -debug -v ${BUILD}/${DEMO}
echo "      Token 打包成功"

# Step 6: Token 模式设备测试
echo "[6/6] Token 模式设备测试 ..."
adb push ${BUILD}/${DEMO} ${DEVICE_DIR}/${DEMO} > /dev/null
adb shell "chmod +x ${DEVICE_DIR}/${DEMO} && ${DEVICE_DIR}/${DEMO}"
echo "      Token 模式 PASS"

echo ""
echo "=== T1: EOR shifted register 全部测试通过 ✅ ==="
