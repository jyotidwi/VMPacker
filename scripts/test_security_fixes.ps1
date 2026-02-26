#!/usr/bin/env pwsh
<#
.SYNOPSIS
    VM 解释器安全修复验证测试
.DESCRIPTION
    验证 ROR UB 修复和 vm_ctx_t 黑名单保护的编译正确性。
    测试流程:
      1. clean + 重新编译 stub
      2. 编译 packer
      3. 编译 demo 程序
      4. 用 packer 打包 demo
      5. 用 QEMU 运行打包后的 demo 验证功能正常
.NOTES
    需要: aarch64-linux-gnu-gcc, Go, qemu-aarch64 (可选)
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $ProjectRoot) { $ProjectRoot = Get-Location }
Set-Location $ProjectRoot

Write-Host "=== VM 安全修复验证测试 ===" -ForegroundColor Cyan
Write-Host ""

# ---- Step 1: 编译 stub ----
Write-Host "[1/4] 编译 VM stub..." -ForegroundColor Yellow
make clean 2>&1 | Out-Null
$stubOut = make stub 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  FAIL: stub 编译失败" -ForegroundColor Red
    Write-Host $stubOut
    exit 1
}
# 检查无 warning
$warnings = $stubOut | Select-String -Pattern "warning:"
if ($warnings) {
    Write-Host "  WARN: 编译产生警告:" -ForegroundColor Yellow
    $warnings | ForEach-Object { Write-Host "    $_" }
} else {
    Write-Host "  PASS: stub 编译成功，零警告" -ForegroundColor Green
}
