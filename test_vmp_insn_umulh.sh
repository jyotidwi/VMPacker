#!/bin/bash
# test_vmp_insn_umulh.sh
# T3: UMULH (unsigned high 64-bit multiply) 自动化测试脚本
# 用法: bash test_vmp_insn_umulh.sh
set -e

DEMO=demo_insn_umulh
FUNC=test_umulh
BUILD=build
DEVICE_DIR=/home/root/vmp

echo "=== T3: UMULH 自动化测试 ==="

# Step 1: 交叉编译
echo "[1/7] 交叉编译 ${DEMO}.c ..."
aarch64-linux-gnu-gcc -O2 -static -o ${BUILD}/${DEMO} demo/${DEMO}.c
echo "      编译成功: ${BUILD}/${DEMO}"

# Step 2: 推送到设备并原生运行
echo "[2/7] 原生运行测试 ..."
adb push ${BUILD}/${DEMO} ${DEVICE_DIR}/${DEMO} > /dev/null
adb shell "chmod +x ${DEVICE_DIR}/${DEMO} && ${DEVICE_DIR}/${DEMO}"
echo "      原生运行 PASS"

# Step 3: make all
echo "[3/7] make all (rebuild stub + packer) ..."
make all
echo "      make all 成功"

# Step 4: VMP Standard 模式打包
echo "[4/7] VMP Standard 模式打包 ..."
./${BUILD}/vmpacker -func ${FUNC} -debug -v -o ${BUILD}/${DEMO}.vmp ${BUILD}/${DEMO}
echo "      Standard 打包成功"

# Step 5: Standard 模式设备测试
echo "[5/7] Standard 模式设备测试 ..."
adb push ${BUILD}/${DEMO}.vmp ${DEVICE_DIR}/${DEMO}.vmp > /dev/null
adb shell "chmod +x ${DEVICE_DIR}/${DEMO}.vmp && ${DEVICE_DIR}/${DEMO}.vmp"
echo "      Standard 模式 PASS"

# Step 6: VMP Token 模式打包
echo "[6/7] VMP Token 模式打包 ..."
aarch64-linux-gnu-gcc -O2 -static -o ${BUILD}/${DEMO} demo/${DEMO}.c
./${BUILD}/vmpacker -token -func ${FUNC} -debug -v -o ${BUILD}/${DEMO}_token.vmp ${BUILD}/${DEMO}
echo "      Token 打包成功"

# Step 7: Token 模式设备测试
echo "[7/7] Token 模式设备测试 ..."
adb push ${BUILD}/${DEMO}_token.vmp ${DEVICE_DIR}/${DEMO}_token.vmp > /dev/null
adb shell "chmod +x ${DEVICE_DIR}/${DEMO}_token.vmp && ${DEVICE_DIR}/${DEMO}_token.vmp"
echo "      Token 模式 PASS"

echo ""
echo "=== T3: UMULH 全部测试通过 ✅ ==="
