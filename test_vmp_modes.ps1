# test_vmp_modes.ps1 — VMP 普通模式 + Token 模式 编译/打包/推送/测试 一体化脚本
# 用法: .\test_vmp_modes.ps1

$ErrorActionPreference = "Continue"
$pass = 0; $fail = 0; $total = 0

function Test-VMP($desc, $cmd, $expected) {
    $script:total++
    $result = Invoke-Expression $cmd 2>&1 | Out-String
    if ($result -match [regex]::Escape($expected)) {
        Write-Host "[PASS] $desc" -ForegroundColor Green
        $script:pass++
    } else {
        Write-Host "[FAIL] $desc" -ForegroundColor Red
        Write-Host "  expected: $expected"
        Write-Host "  got:      $($result.Trim())"
        $script:fail++
    }
}

Write-Host "=== VMP Mode Test ===" -ForegroundColor Cyan
Write-Host ""

# --- 编译 ---
Write-Host "--- Build ---" -ForegroundColor Yellow
make all
aarch64-linux-gnu-gcc -O1 -static -o build/demo_license demo/demo_license.c
$env:CGO_ENABLED='0'; $env:GOOS='linux'; $env:GOARCH='arm64'
go build -gcflags="-N -l" -o build/demo_go_test ./demo/demo_go_test/

# --- 打包 ---
Write-Host ""
Write-Host "--- Pack ---" -ForegroundColor Yellow

# 普通模式 (check_license 168B > 72B trampoline)
.\build\vmpacker.exe -func check_license -debug -v -o build/demo_license_std.vmp build/demo_license

# Token 模式
.\build\vmpacker.exe -token -func check_license -debug -v -o build/demo_license_token.vmp build/demo_license
.\build\vmpacker.exe -token -func "main.checkKey" -debug -v -o build/demo_go_test_token.vmp build/demo_go_test

# --- 推送 ---
Write-Host ""
Write-Host "--- Push ---" -ForegroundColor Yellow
adb push build/demo_license_std.vmp /home/root/vmp/
adb push build/demo_license_token.vmp /home/root/vmp/
adb push build/demo_go_test_token.vmp /home/root/vmp/
adb shell "chmod +x /home/root/vmp/demo_license_std.vmp /home/root/vmp/demo_license_token.vmp /home/root/vmp/demo_go_test_token.vmp"

# --- 测试 ---
Write-Host ""
Write-Host "--- Standard Mode ---" -ForegroundColor Yellow
Test-VMP "C license valid (std)" `
    'adb shell "/home/root/vmp/demo_license_std.vmp 12345678"' `
    "[+] License valid!"
Test-VMP "C license invalid (std)" `
    'adb shell "/home/root/vmp/demo_license_std.vmp 00000000"' `
    "[-] License invalid."

Write-Host ""
Write-Host "--- Token Mode ---" -ForegroundColor Yellow
Test-VMP "C license valid (token)" `
    'adb shell "/home/root/vmp/demo_license_token.vmp 12345678"' `
    "[+] License valid!"
Test-VMP "C license invalid (token)" `
    'adb shell "/home/root/vmp/demo_license_token.vmp 00000000"' `
    "[-] License invalid."
Test-VMP "Go checkKey (token)" `
    'adb shell "/home/root/vmp/demo_go_test_token.vmp"' `
    "checkKey(10) = 143"

Write-Host ""
Write-Host "=== Result: $pass/$total passed, $fail failed ===" -ForegroundColor $(if($fail -eq 0){"Green"}else{"Red"})
exit $fail
