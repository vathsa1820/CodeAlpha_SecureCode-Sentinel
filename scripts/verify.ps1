# SecureCode Sentinel - Developer Verification Script (PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "🚀 Running SecureCode Sentinel Full System Verification..." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

# 1. Run Python Security Checks
python scripts/verify.py
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Verification script failed!" -ForegroundColor Red
    exit 1
}

Write-Host "🎉 Verification Complete!" -ForegroundColor Green
