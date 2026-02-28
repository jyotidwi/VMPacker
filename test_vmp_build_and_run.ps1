# VMP 一键构建+测试脚本 (Windows PowerShell)
# 用法: .\test_vmp_build_and_run.ps1

$ErrorActionPreference = "Stop"
$DEVICE_DIR = "/home/root/vmp"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "  VMP 构建 + 设备测试" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 1. 编译 stub + packer
Write-Host "`n[1/8] 编译 stub + packer..." -ForegroundColor Yellow
make all
if ($LASTEXITCODE -ne 0) { Write-Host "FAIL: make all" -ForegroundColor Red; exit 1 }

# 2. 交叉编译 Go 测试程序
Write-Host "`n[2/8] 交叉编译 Go 测试程序..." -ForegroundColor Yellow
$env:CGO_ENABLED='0'; $env:GOOS='linux'; $env:GOARCH='arm64'
go build -gcflags="-N -l" -o build/demo_go_test ./demo/demo_go_test/
if ($LASTEXITCODE -ne 0) { Write-Host "FAIL: go build" -ForegroundColor Red; exit 1 }
Remove-Item Env:GOOS; Remove-Item Env:GOARCH

# 3. 交叉编译 C 测试程序
Write-Host "`n[3/8] 交叉编译 C 测试程序..." -ForegroundColor Yellow
aarch64-linux-gnu-gcc -static -O0 -march=armv8-a demo/demo_insn_add.c -o build/demo_insn_add
if ($LASTEXITCODE -ne 0) { Write-Host "FAIL: gcc" -ForegroundColor Red; exit 1 }

# 4. 交叉编译 Rust 测试程序
Write-Host "`n[4/8] 交叉编译 Rust 测试程序..." -ForegroundColor Yellow
$env:CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER='aarch64-linux-gnu-gcc'
$env:RUSTFLAGS='-C relocation-model=static -C target-feature=+crt-static'
cargo build --manifest-path demo/demo_rust_test/Cargo.toml --target aarch64-unknown-linux-gnu --release
if ($LASTEXITCODE -ne 0) { Write-Host "FAIL: cargo build" -ForegroundColor Red; exit 1 }
Copy-Item demo/demo_rust_test/target/aarch64-unknown-linux-gnu/release/demo_rust_test build/demo_rust_test -Force

# 5. VMP 加壳
Write-Host "`n[5/8] VMP 加壳..." -ForegroundColor Yellow
.\build\vmpacker.exe -token -func "main.checkKey" -debug -v -o build/demo_go_test_token.vmp build/demo_go_test
if ($LASTEXITCODE -ne 0) { Write-Host "FAIL: vmpacker go" -ForegroundColor Red; exit 1 }

.\build\vmpacker.exe -token -func check_add -debug -v -o build/demo_insn_add.vmp build/demo_insn_add
if ($LASTEXITCODE -ne 0) { Write-Host "FAIL: vmpacker c" -ForegroundColor Red; exit 1 }

.\build\vmpacker.exe -token -func check_key -debug -v -o build/demo_rust_test_token.vmp build/demo_rust_test
if ($LASTEXITCODE -ne 0) { Write-Host "FAIL: vmpacker rust" -ForegroundColor Red; exit 1 }

# 6. 推送到设备
Write-Host "`n[6/8] 推送到设备..." -ForegroundColor Yellow
adb push build/demo_go_test_token.vmp "$DEVICE_DIR/demo_go_test_token.vmp"
adb push build/demo_insn_add.vmp "$DEVICE_DIR/demo_insn_add.vmp"
adb push build/demo_rust_test_token.vmp "$DEVICE_DIR/demo_rust_test_token.vmp"
adb push test_vmp_all.sh "$DEVICE_DIR/test_vmp_all.sh"

# 7. 运行测试
Write-Host "`n[7/8] 运行设备测试..." -ForegroundColor Yellow
adb shell "chmod +x $DEVICE_DIR/test_vmp_all.sh; $DEVICE_DIR/test_vmp_all.sh"

# 8. 完成
Write-Host "`n[8/8] 完成!" -ForegroundColor Green
