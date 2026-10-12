# HomeWifiVPN 遗留系统改动清理脚本（需管理员）
$ErrorActionPreference = 'Continue'
Write-Host "=== 清理 HomeWifiVPN 遗留的系统改动 ===" -ForegroundColor Cyan

# 1. 关闭所有网卡的 IP 转发
Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
  try {
    Set-NetIPInterface -InterfaceIndex $_.InterfaceIndex -Forwarding Disabled -ErrorAction Stop
    Write-Host ("  [OK] 关闭转发: " + $_.InterfaceAlias)
  } catch {
    Write-Host ("  [跳过] " + $_.InterfaceAlias + ": " + $_.Exception.Message) -ForegroundColor DarkYellow
  }
}

# 2. 关闭注册表 IPEnableRouter
try {
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'IPEnableRouter' -Value 0 -Type DWord -ErrorAction Stop
  Write-Host "  [OK] IPEnableRouter = 0"
} catch {
  Write-Host ("  [失败] IPEnableRouter: " + $_.Exception.Message) -ForegroundColor Red
}

# 3. 移除 HomeWifiVPN 防火墙规则
$rules = Get-NetFirewallRule -DisplayName 'HomeWifiVPN*' -ErrorAction SilentlyContinue
if ($rules) {
  $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
  Write-Host ("  [OK] 已移除 " + ($rules | Measure-Object).Count + " 条 HomeWifiVPN 防火墙规则")
} else {
  Write-Host "  [OK] 无 HomeWifiVPN 防火墙规则"
}

Write-Host ""
Write-Host "=== 清理完成，请重启 Clash Verge 的虚拟网卡模式 ===" -ForegroundColor Green
Write-Host "验证：" -ForegroundColor Yellow
Write-Host "  Get-NetIPInterface -AddressFamily IPv4 | Select InterfaceAlias,Forwarding"
Write-Host "  所有网卡的 Forwarding 应显示为 Disabled"
