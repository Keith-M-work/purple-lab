<#
  wazuh-deploy.ps1  (sanitized, TCP+UDP aware)
  ------------------------------------------------------------
  Helpers:
   - Test-WazuhFirewall     : verify Dashboard/Indexer/Enroll + Events (TCP & UDP)
   - Install-WazuhAgent-Pi  : remote install + configure agent
   - Enroll-WazuhAgent-Pi   : run agent-auth via SSH on the Pi
   - Get-WazuhAgentStatus   : quick health across Pis
   - Show-WazuhPorts        : show port maps for Wazuh containers
   - Resolve-WazuhContainers: locate manager/dashboard/indexer by name
   - Audit-AgentProtocol    : check each Pis ossec.conf <protocol> (tcp/udp)

  Requirements:
   - OpenSSH client on Windows
   - Key-based SSH access to each Pi (user "pi")
   - $Global:Pi hashtable defined elsewhere (name -> IP)
   - pfSense allows from each VLAN to WAZUH_MGR_IP:
       TCP/UDP 1514 (events), TCP 1515 (enroll), TCP 443 (UI), TCP 9220 (indexer)
#>

# ======================
# Configuration (edit)
# ======================
$Global:WazuhConfig = @{
  ManagerLANIP     = "WAZUH_MGR_IP"  # e.g., 192.168.10.50
  DashboardPort    = 443             # host -> dashboard (container 5601)
  IndexerHostPort  = 9220            # host -> indexer (container 9200)
  AgentEnrollPort  = 1515            # TCP enrollment (agent-auth)
  AgentEventPort   = 1514            # Events port; pfSense allows TCP and UDP
  APIPort          = 55000           # optional API
  AgentVersion     = "4.6.0-1"       # adjust if needed
  AgentArch        = "arm64"         # Pi OS 64-bit; use armhf if 32-bit
  AgentPkgUrl      = "https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_{0}_{1}.deb"
  DefaultEventProto= "tcp"           # agent-side default; pfSense allows both
}

# ======================
# Container discovery
# ======================
function Resolve-WazuhContainers {
  $names = docker ps --format "{{.Names}}"
  $script:WazuhManager   = ($names | Select-String -SimpleMatch "wazuh.manager").ToString()
  $script:WazuhDashboard = ($names | Select-String -SimpleMatch "wazuh.dashboard").ToString()
  $script:WazuhIndexer   = ($names | Select-String -SimpleMatch "wazuh.indexer").ToString()

  [pscustomobject]@{
    Manager   = $script:WazuhManager
    Dashboard = $script:WazuhDashboard
    Indexer   = $script:WazuhIndexer
  }
}

function Show-WazuhPorts {
  $c = Resolve-WazuhContainers
  if ($c.Dashboard) { Write-Host "`n[Dashboard ports]" -ForegroundColor Cyan; docker inspect $($c.Dashboard) | jq '.[0].NetworkSettings.Ports' }
  if ($c.Indexer)   { Write-Host "`n[Indexer ports]"   -ForegroundColor Cyan; docker inspect $($c.Indexer)   | jq '.[0].NetworkSettings.Ports' }
  if ($c.Manager)   { Write-Host "`n[Manager ports]"   -ForegroundColor Cyan; docker inspect $($c.Manager)   | jq '.[0].NetworkSettings.Ports' }
}

# ======================
# Firewall preflight
# ======================
function Test-WazuhFirewall {
  $p = $Global:WazuhConfig
  Write-Host "`n[Preflight] Testing Wazuh ports on $($p.ManagerLANIP) ..." -ForegroundColor Cyan

  foreach ($row in @(
    @{Name="Dashboard";  Port=$p.DashboardPort},
    @{Name="Indexer";    Port=$p.IndexerHostPort},
    @{Name="Enroll";     Port=$p.AgentEnrollPort},
    @{Name="Events TCP"; Port=$p.AgentEventPort}
  )) {
    $ok = Test-NetConnection -ComputerName $p.ManagerLANIP -Port $row.Port -InformationLevel Quiet
    Write-Host ("{0,-12} {1,5}/TCP -> {2}" -f $row.Name,$row.Port,($(if($ok){"OPEN"}else{"BLOCKED"}))) `
      -ForegroundColor ($(if($ok){"Green"}else{"Red"}))
  }

  # UDP probe for 1514  success criteria is "no immediate ICMP error"
  try {
    $u = New-Object System.Net.Sockets.UdpClient
    $u.Client.ReceiveTimeout = 1000
    $u.Connect($p.ManagerLANIP, $p.AgentEventPort)
    [void]$u.Send([byte[]](0,1,2,3),4)
    Write-Host ("{0,-12} {1,5}/UDP -> SENT (no ICMP error)" -f "Events UDP", $p.AgentEventPort) -ForegroundColor Yellow
  } catch {
    Write-Host "Events $($p.AgentEventPort)/UDP -> ERROR $($_.Exception.Message)" -ForegroundColor Red
  } finally { if ($u) { $u.Close() } }
}

# ======================
# Agent install + enroll
# ======================
function Install-WazuhAgent-Pi {
  param(
    [Parameter(Mandatory=$true)][string]$Name,
    [ValidateSet("tcp","udp")][string]$EventProtocol = $Global:WazuhConfig.DefaultEventProto
  )
  if (-not $Global:Pi.ContainsKey($Name)) { throw "Global:Pi does not contain '$Name'." }

  $p = $Global:WazuhConfig
  $pkgUrl = [string]::Format($p.AgentPkgUrl, $p.AgentVersion, $p.AgentArch)
  $agentName = $Name

  $remote = @"
set -e
echo '[+] Installing Wazuh Agent on $agentName'

# Package
curl -sfL -o /tmp/wazuh-agent.deb '$pkgUrl'
sudo dpkg -i /tmp/wazuh-agent.deb

# Point to manager + port
sudo sed -i "s#<address>.*</address>#<address>$($p.ManagerLANIP)</address>#" /var/ossec/etc/ossec.conf
sudo sed -i "s#<port>.*</port>#<port>$($p.AgentEventPort)</port>#" /var/ossec/etc/ossec.conf

# Enforce protocol per parameter (tcp/udp)
if grep -q '<protocol>' /var/ossec/etc/ossec.conf; then
  sudo sed -i "s#<protocol>.*</protocol>#<protocol>$EventProtocol</protocol>#" /var/ossec/etc/ossec.conf
else
  sudo sed -i "s#</server>#  <protocol>$EventProtocol</protocol>\n  </server>#" /var/ossec/etc/ossec.conf
fi

# Agent display name (helps in UI)
if grep -q '<agent_name>' /var/ossec/etc/ossec.conf; then
  sudo sed -i "s#<agent_name>.*</agent_name>#<agent_name>$agentName</agent_name>#" /var/ossec/etc/ossec.conf
else
  sudo sed -i "s#</client>#  <agent_name>$agentName</agent_name>\n</client>#" /var/ossec/etc/ossec.conf
fi

sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl restart wazuh-agent

echo '[+] Agent installed & restarted.'
"@

  ssh "pi@$($Global:Pi[$Name])" $remote
}

function Enroll-WazuhAgent-Pi {
  param([Parameter(Mandatory=$true)][string]$Name)
  if (-not $Global:Pi.ContainsKey($Name)) { throw "Global:Pi does not contain '$Name'." }
  $p = $Global:WazuhConfig

  $cmd = @"
sudo /var/ossec/bin/agent-auth -m $($p.ManagerLANIP) -p $($p.AgentEnrollPort) -A $Name || true
sudo systemctl restart wazuh-agent
sleep 2
echo '--- tail ossec.log ---'
sudo tail -n 60 /var/ossec/logs/ossec.log
"@
  ssh "pi@$($Global:Pi[$Name])" $cmd
}

# ======================
# Status + audit helpers
# ======================
function Get-WazuhAgentStatus {
  if (-not $Global:Pi) { Write-Warning "Global:Pi not defined."; return }
  Write-Host "`n=== Wazuh Agent Status on Pis ===" -ForegroundColor Cyan
  foreach ($k in $Global:Pi.Keys) {
    Write-Host "`n$k ($($Global:Pi[$k])):" -ForegroundColor Green
    $svc = ssh "pi@$($Global:Pi[$k])" "systemctl is-active wazuh-agent 2>/dev/null || echo not-installed"
    $pkg = ssh "pi@$($Global:Pi[$k])" "dpkg -l | grep -q wazuh-agent && echo INSTALLED || echo NOT-INSTALLED"
    Write-Host ("Service: {0}  |  Package: {1}" -f $svc,$pkg)
  }
  try {
    $c = Resolve-WazuhContainers
    if ($c.Manager) {
      Write-Host "`n=== Manager view (agent_control -lc) ===" -ForegroundColor Cyan
      docker exec -it $($c.Manager) /var/ossec/bin/agent_control -lc
    }
  } catch { Write-Warning "Manager query failed: $($_.Exception.Message)" }
}

function Audit-AgentProtocol {
  if (-not $Global:Pi) { Write-Warning "Global:Pi not defined."; return }
  Write-Host "`n=== Agent Protocol Audit (per Pi) ===" -ForegroundColor Cyan
  foreach ($k in $Global:Pi.Keys) {
    $proto = ssh "pi@$($Global:Pi[$k])" "grep -oP '(?<=<protocol>).*?(?=</protocol>)' /var/ossec/etc/ossec.conf 2>/dev/null || echo unknown"
    Write-Host ("{0,-8} {1,-15} protocol={2}" -f $k,$Global:Pi[$k],$proto)
  }
}

Write-Host "[Wazuh] Deploy helpers loaded (1514 TCP+UDP allowed; agent default=$($Global:WazuhConfig.DefaultEventProto))." -ForegroundColor Green
