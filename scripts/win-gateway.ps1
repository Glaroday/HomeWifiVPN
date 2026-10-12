# ============================================================
#  HomeWifiVPN - Windows 旁路网关一键配置脚本
#  作用：把本机变成局域网透明网关（其他设备只需把网关/DNS 指向本机）
#  需要：以【管理员身份】运行 PowerShell 执行本脚本
#  用法：
#    powershell -ExecutionPolicy Bypass -File scripts\win-gateway.ps1 -Action on
#    powershell -ExecutionPolicy Bypass -File scripts\win-gateway.ps1 -Action off
#    powershell -ExecutionPolicy Bypass -File scripts\win-gateway.ps1 -Action status
# ============================================================
param(
  [ValidateSet('on','off','status')]
  [string]$Action = 'status',
  [string]$LanPrefix = '',
  [int]$PanelPort = 8090,
  [int]$ProxyPort = 7890,
  [int]$DnsPort = 53
)

$ErrorActionPreference = 'Continue'

function Test-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p = New-Object Security.Principal.WindowsPrincipal($id)
  return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-LanInfo {
  $ip = $null
  $ifIndex = $null
  $prefix = $null
  try {
    $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
         Sort-Object RouteMetric | Select-Object -First 1
    if ($r) { $ifIndex = $r.ifIndex }
    if ($ifIndex) {
      $addr = Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
              Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
      if ($addr) {
        $ip = $addr.IPAddress
        $prefix = $addr.PrefixLength
      }
    }
  } catch { }
  return @{ IP = $ip; IfIndex = $ifIndex; Prefix = $prefix }
}

$admin = Test-Admin
$lan = Get-LanInfo

if ($LanPrefix) {
  $cidr = $LanPrefix
} elseif ($lan.IP -and $lan.Prefix) {
  $octets = $lan.IP.Split('.')
  $cidr = $octets[0] + '.' + $octets[1] + '.' + $octets[2] + '.0/' + $lan.Prefix
} else {
  $cidr = '192.168.0.0/16'
}

$suggestIp = '192.168.5.100'
if ($lan.IP) {
  $o = $lan.IP.Split('.')
  $suggestIp = $o[0] + '.' + $o[1] + '.' + $o[2] + '.100'
}

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " HomeWifiVPN Windows 旁路网关配置" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host (" 本机局域网 IP : " + $lan.IP)
Write-Host (" 局域网网段    : " + $cidr)
Write-Host (" 网卡索引      : " + $lan.IfIndex)
Write-Host (" 管理员权限    : " + $admin)
Write-Host "-----------------------------------------------"

if ($Action -eq 'status') {
  Write-Host ""
  Write-Host "[网卡 IP 转发状态]" -ForegroundColor Yellow
  Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Select-Object InterfaceAlias, InterfaceIndex, Forwarding | Format-Table -AutoSize

  Write-Host "[防火墙规则]" -ForegroundColor Yellow
  Get-NetFirewallRule -DisplayName 'HomeWifiVPN*' -ErrorAction SilentlyContinue |
    Select-Object DisplayName, Enabled, Direction, Action | Format-Table -AutoSize

  Write-Host "[监听端口]" -ForegroundColor Yellow
  netstat -ano | Select-String (":" + $ProxyPort + "\s") | Select-Object -First 3
  netstat -ano | Select-String (":" + $DnsPort + "\s") | Select-Object -First 3
  netstat -ano | Select-String (":" + $PanelPort + "\s") | Select-Object -First 3

  Write-Host ""
  Write-Host "提示：Forwarding 必须为 Enabled 才能作为网关为其他设备转发流量。" -ForegroundColor Green
  exit 0
}

if (-not $admin) {
  Write-Host "错误：需要管理员权限！请右键以管理员身份运行 PowerShell 后重试。" -ForegroundColor Red
  Write-Host "或执行下面命令（会自动弹出 UAC）：" -ForegroundColor Yellow
  Write-Host ('Start-Process powershell -Verb RunAs -ArgumentList ''-ExecutionPolicy Bypass -File "' + $PSCommandPath + '" -Action ' + $Action + '''')
  exit 1
}

if ($Action -eq 'on') {
  Write-Host "==> 1/5 开启本机 IP 转发（所有网卡）" -ForegroundColor Green
  Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
    $idx = $_.InterfaceIndex
    $alias = $_.InterfaceAlias
    try {
      Set-NetIPInterface -InterfaceIndex $idx -Forwarding Enabled -ErrorAction Stop
    } catch {
      Write-Host ("    跳过 " + $alias + ": " + $_.Exception.Message) -ForegroundColor DarkYellow
    }
  }
  try {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'IPEnableRouter' -Value 1 -Type DWord -ErrorAction SilentlyContinue
  } catch { }

  Write-Host "==> 2/5 放行防火墙（局域网 -> 网关）" -ForegroundColor Green
  $rules = @(
    @{ Name = 'HomeWifiVPN Panel TCP'; Port = $PanelPort; Proto = 'TCP' },
    @{ Name = 'HomeWifiVPN Proxy TCP'; Port = $ProxyPort; Proto = 'TCP' },
    @{ Name = 'HomeWifiVPN DNS UDP';   Port = $DnsPort;   Proto = 'UDP' },
    @{ Name = 'HomeWifiVPN DNS TCP';   Port = $DnsPort;   Proto = 'TCP' }
  )
  foreach ($rule in $rules) {
    Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow -Protocol $rule.Proto -LocalPort $rule.Port -RemoteAddress $cidr -Profile Any | Out-Null
    Write-Host ("    OK " + $rule.Name + " (" + $rule.Proto + "/" + $rule.Port + ") 允许来自 " + $cidr)
  }

  $mihomoExe = Join-Path $PSScriptRoot '..\data\mihomo.exe'
  if (Test-Path $mihomoExe) {
    Get-NetFirewallRule -DisplayName 'HomeWifiVPN mihomo' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
    New-NetFirewallRule -DisplayName 'HomeWifiVPN mihomo' -Direction Inbound -Action Allow -Program (Resolve-Path $mihomoExe).Path -Profile Any | Out-Null
    Write-Host "    OK 已放行 mihomo.exe"
  }

  Write-Host "==> 3/5 检查 mihomo 核心与配置" -ForegroundColor Green
  $dataDir = Join-Path $PSScriptRoot '..\data'
  $exe = Join-Path $dataDir 'mihomo.exe'
  if (Test-Path $exe) {
    Write-Host "    OK 核心已就绪"
  } else {
    Write-Host "    警告：未找到 data\mihomo.exe，请先在面板「核心检测」卡片点击一键安装" -ForegroundColor Yellow
  }

  Write-Host "==> 4/5 重启 mihomo（启用 TUN 透明接管）" -ForegroundColor Green
  if (Test-Path $exe) {
    Get-Process mihomo -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 600
    $resolvedData = (Resolve-Path $dataDir).Path
    Start-Process -FilePath $exe -ArgumentList @('-d', $resolvedData) -WindowStyle Hidden
    Start-Sleep -Seconds 2
    $verOk = $false
    try {
      $ver = Invoke-RestMethod -Uri 'http://127.0.0.1:9090/version' -TimeoutSec 3
      $verOk = $true
      Write-Host ("    OK mihomo 已启动： " + $ver.version) -ForegroundColor Green
    } catch {
      Write-Host "    警告：mihomo 已拉起但 9090 未响应，请查看面板日志" -ForegroundColor Yellow
    }
    if (-not $verOk) { Write-Host "    （提示：若端口被 Clash Verge 占用，请先退出 Clash Verge）" -ForegroundColor DarkYellow }
  }

  Write-Host "==> 5/5 完成" -ForegroundColor Green
  Write-Host ""
  Write-Host "=================== 配置完成 ===================" -ForegroundColor Cyan
  Write-Host " 现在在【其他设备】上这样设置："
  Write-Host ("   IP 地址   : 同网段空闲地址（如 " + $suggestIp + "）")
  Write-Host "   子网掩码  : 255.255.255.0"
  Write-Host ("   网关      : " + $lan.IP)
  Write-Host ("   DNS       : " + $lan.IP + "   <- 切勿填 8.8.8.8")
  Write-Host ""
  Write-Host " 若设备不支持改网关（如智能电视、部分手机），改用【代理直通】方式："
  Write-Host ("   代理服务器: " + $lan.IP + "   端口: " + $ProxyPort + "   (HTTP/SOCKS5)")
  Write-Host "================================================" -ForegroundColor Cyan
  Write-Host " 注意：Windows 需保持开机且不休眠，本机才能持续为局域网转发。" -ForegroundColor DarkYellow
  exit 0
}

if ($Action -eq 'off') {
  Write-Host "==> 关闭旁路网关" -ForegroundColor Yellow
  Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object {
    try {
      Set-NetIPInterface -InterfaceIndex $_.InterfaceIndex -Forwarding Disabled -ErrorAction Stop
    } catch { }
  }
  Get-NetFirewallRule -DisplayName 'HomeWifiVPN*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
  Write-Host "    OK 已关闭 IP 转发并移除防火墙规则"
  Write-Host "    OK 其他设备改回「自动(DHCP)」即可恢复直连" -ForegroundColor Green
  exit 0
}
