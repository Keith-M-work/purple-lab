# =============================================================
# YOURLAB.LOCAL - Realistic Active Directory Population Script
# 75 users, 6 departments, service accounts, attack paths
# Run on DC01 as YOURLAB\Administrator
# =============================================================

# =============================================================
# PASSWORD CONFIGURATION - Set these before running!
# =============================================================
# Default password for all standard user accounts
$DefaultUserPassword = "<CHANGE_ME_USER_PASSWORD>"

# Default password for service accounts (set SPNs for Kerberoasting)
$DefaultSvcPassword = "<CHANGE_ME_SVC_PASSWORD>"

# Weak password for the intentional Kerberoast target (svc_automate)
# Use a crackable password here on purpose for the exercise
$WeakSvcPassword = "<CHANGE_ME_WEAK_PASSWORD>"

# Validate passwords are set
if ($DefaultUserPassword -like "*CHANGE_ME*" -or $DefaultSvcPassword -like "*CHANGE_ME*" -or $WeakSvcPassword -like "*CHANGE_ME*") {
    Write-Host "[!] ERROR: Update the password variables at the top of this script before running." -ForegroundColor Red
    Write-Host "[!] Look for <CHANGE_ME_...> placeholders and replace with your own passwords." -ForegroundColor Red
    exit 1
}

# --- Organizational Units ---
$OUs = @(
    "OU=Executive,DC=yourlab,DC=local",
    "OU=IT,DC=yourlab,DC=local",
    "OU=Finance,DC=yourlab,DC=local",
    "OU=HR,DC=yourlab,DC=local",
    "OU=Sales,DC=yourlab,DC=local",
    "OU=Engineering,DC=yourlab,DC=local",
    "OU=Service Accounts,DC=yourlab,DC=local",
    "OU=Contractors,DC=yourlab,DC=local"
)

foreach ($ou in $OUs) {
    try {
        $name = ($ou -split ",")[0] -replace "OU=",""
        New-ADOrganizationalUnit -Name $name -Path ($ou -replace "^OU=[^,]+,","") -ErrorAction Stop
        Write-Host "[+] Created OU: $name" -ForegroundColor Green
    } catch {
        Write-Host "[*] OU already exists: $name" -ForegroundColor Yellow
    }
}

# --- Security Groups ---
$Groups = @(
    @{Name="IT-Admins"; Path="OU=IT,DC=yourlab,DC=local"; Desc="IT Department Administrators"},
    @{Name="IT-HelpDesk"; Path="OU=IT,DC=yourlab,DC=local"; Desc="Help Desk Technicians"},
    @{Name="IT-Security"; Path="OU=IT,DC=yourlab,DC=local"; Desc="Security Operations Team"},
    @{Name="IT-DevOps"; Path="OU=IT,DC=yourlab,DC=local"; Desc="DevOps Engineers"},
    @{Name="Finance-Team"; Path="OU=Finance,DC=yourlab,DC=local"; Desc="Finance Department"},
    @{Name="Finance-Managers"; Path="OU=Finance,DC=yourlab,DC=local"; Desc="Finance Management"},
    @{Name="HR-Team"; Path="OU=HR,DC=yourlab,DC=local"; Desc="Human Resources"},
    @{Name="HR-Managers"; Path="OU=HR,DC=yourlab,DC=local"; Desc="HR Management"},
    @{Name="Sales-Team"; Path="OU=Sales,DC=yourlab,DC=local"; Desc="Sales Representatives"},
    @{Name="Sales-Managers"; Path="OU=Sales,DC=yourlab,DC=local"; Desc="Sales Management"},
    @{Name="Engineering-Team"; Path="OU=Engineering,DC=yourlab,DC=local"; Desc="Software Engineers"},
    @{Name="Engineering-Leads"; Path="OU=Engineering,DC=yourlab,DC=local"; Desc="Engineering Team Leads"},
    @{Name="VPN-Users"; Path="DC=yourlab,DC=local"; Desc="VPN Access Group"},
    @{Name="RDP-Servers"; Path="DC=yourlab,DC=local"; Desc="RDP Access to Servers"},
    @{Name="Backup-Operators"; Path="DC=yourlab,DC=local"; Desc="Backup Operations Access"},
    @{Name="PAW-Users"; Path="DC=yourlab,DC=local"; Desc="Privileged Access Workstation Users"}
)

foreach ($g in $Groups) {
    try {
        New-ADGroup -Name $g.Name -GroupScope Global -GroupCategory Security -Path $g.Path -Description $g.Desc -ErrorAction Stop
        Write-Host "[+] Created Group: $($g.Name)" -ForegroundColor Green
    } catch {
        Write-Host "[*] Group already exists: $($g.Name)" -ForegroundColor Yellow
    }
}

# --- Helper function ---
function Create-LabUser {
    param(
        [string]$First,
        [string]$Last,
        [string]$Title,
        [string]$Dept,
        [string]$OU,
        [string]$Password = "",
        [string]$Manager = "",
        [string[]]$Groups = @()
    )
    $sam = "$($First.Substring(0,1).ToLower()).$($Last.ToLower())"
    if ($Password -eq "") { $Password = $DefaultUserPassword }
    $upn = "$sam@yourlab.local"
    $name = "$First $Last"
    
    try {
        $params = @{
            Name = $name
            GivenName = $First
            Surname = $Last
            SamAccountName = $sam
            UserPrincipalName = $upn
            DisplayName = $name
            Title = $Title
            Department = $Dept
            Company = "YourLab Corp"
            AccountPassword = (ConvertTo-SecureString $Password -AsPlainText -Force)
            Enabled = $true
            Path = $OU
            ChangePasswordAtLogon = $false
        }
        New-ADUser @params -ErrorAction Stop
        
        if ($Manager -ne "") {
            Set-ADUser -Identity $sam -Manager $Manager
        }
        
        foreach ($g in $Groups) {
            Add-ADGroupMember -Identity $g -Members $sam -ErrorAction SilentlyContinue
        }
        
        Write-Host "[+] Created: $sam ($Title, $Dept)" -ForegroundColor Green
    } catch {
        Write-Host "[*] User exists or error: $sam - $_" -ForegroundColor Yellow
    }
}

# =============================================================
# EXECUTIVE LEADERSHIP (5)
# =============================================================
Create-LabUser -First "Robert" -Last "Chen" -Title "CEO" -Dept "Executive" -OU "OU=Executive,DC=yourlab,DC=local" -Password $DefaultUserPassword -Groups @("VPN-Users")
Create-LabUser -First "Sarah" -Last "Mitchell" -Title "CFO" -Dept "Executive" -OU "OU=Executive,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "r.chen" -Groups @("VPN-Users","Finance-Managers")
Create-LabUser -First "David" -Last "Torres" -Title "CTO" -Dept "Executive" -OU "OU=Executive,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "r.chen" -Groups @("VPN-Users","IT-Admins","PAW-Users")
Create-LabUser -First "Lisa" -Last "Park" -Title "CISO" -Dept "Executive" -OU "OU=Executive,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "d.torres" -Groups @("VPN-Users","IT-Security","PAW-Users")
Create-LabUser -First "Michael" -Last "Ross" -Title "COO" -Dept "Executive" -OU "OU=Executive,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "r.chen" -Groups @("VPN-Users")

# =============================================================
# IT DEPARTMENT (15)
# =============================================================
# IT Management
Create-LabUser -First "James" -Last "Wilson" -Title "IT Director" -Dept "IT" -OU "OU=IT,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "d.torres" -Groups @("IT-Admins","VPN-Users","RDP-Servers","PAW-Users")
Create-LabUser -First "Karen" -Last "Liu" -Title "Security Manager" -Dept "IT" -OU "OU=IT,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "l.park" -Groups @("IT-Security","VPN-Users","PAW-Users")

# System Administrators (high-value targets)
Create-LabUser -First "Thomas" -Last "Baker" -Title "Senior Sysadmin" -Dept "IT" -OU "OU=IT,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "j.wilson" -Groups @("IT-Admins","RDP-Servers","Backup-Operators","VPN-Users","PAW-Users")
Create-LabUser -First "Maria" -Last "Garcia" -Title "Systems Administrator" -Dept "IT" -OU "OU=IT,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "j.wilson" -Groups @("IT-Admins","RDP-Servers","VPN-Users")
Create-LabUser -First "Kevin" -Last "Nguyen" -Title "Junior Sysadmin" -Dept "IT" -OU "OU=IT,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "t.baker" -Groups @("IT-HelpDesk","RDP-Servers","VPN-Users")

# Security Team
Create-LabUser -First "Angela" -Last "Davis" -Title "SOC Analyst" -Dept "IT" -OU "OU=IT,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "k.liu" -Groups @("IT-Security","VPN-Users")
Create-LabUser -First "Ryan" -Last "Cooper" -Title "Threat Hunter" -Dept "IT" -OU "OU=IT,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "k.liu" -Groups @("IT-Security","VPN-Users","RDP-Servers")
Create-LabUser -First "Jessica" -Last "Kim" -Title "Security Engineer" -Dept "IT" -OU "OU=IT,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "k.liu" -Groups @("IT-Security","IT-DevOps","VPN-Users","PAW-Users")

# Help Desk
Create-LabUser -First "Brandon" -Last "White" -Title "Help Desk Lead" -Dept "IT" -OU "OU=IT,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "j.wilson" -Groups @("IT-HelpDesk","VPN-Users")
Create-LabUser -First "Samantha" -Last "Brown" -Title "Help Desk Tech" -Dept "IT" -OU "OU=IT,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "b.white" -Groups @("IT-HelpDesk","VPN-Users")
Create-LabUser -First "Derek" -Last "Thompson" -Title "Help Desk Tech" -Dept "IT" -OU "OU=IT,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "b.white" -Groups @("IT-HelpDesk","VPN-Users")

# DevOps
Create-LabUser -First "Alex" -Last "Patel" -Title "DevOps Engineer" -Dept "IT" -OU "OU=IT,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "j.wilson" -Groups @("IT-DevOps","VPN-Users","RDP-Servers")
Create-LabUser -First "Nina" -Last "Volkov" -Title "DevOps Engineer" -Dept "IT" -OU "OU=IT,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "a.patel" -Groups @("IT-DevOps","VPN-Users","RDP-Servers")
Create-LabUser -First "Chris" -Last "Morgan" -Title "Cloud Engineer" -Dept "IT" -OU "OU=IT,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "a.patel" -Groups @("IT-DevOps","VPN-Users")

# =============================================================
# FINANCE (10)
# =============================================================
Create-LabUser -First "Patricia" -Last "Anderson" -Title "Finance Director" -Dept "Finance" -OU "OU=Finance,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "s.mitchell" -Groups @("Finance-Managers","VPN-Users")
Create-LabUser -First "George" -Last "Wright" -Title "Controller" -Dept "Finance" -OU "OU=Finance,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "p.anderson" -Groups @("Finance-Managers","VPN-Users")
Create-LabUser -First "Helen" -Last "Zhao" -Title "Senior Accountant" -Dept "Finance" -OU "OU=Finance,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "g.wright" -Groups @("Finance-Team","VPN-Users")
Create-LabUser -First "Mark" -Last "Sullivan" -Title "Accountant" -Dept "Finance" -OU "OU=Finance,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "g.wright" -Groups @("Finance-Team","VPN-Users")
Create-LabUser -First "Diana" -Last "Reed" -Title "Accounts Payable" -Dept "Finance" -OU "OU=Finance,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "g.wright" -Groups @("Finance-Team","VPN-Users")
Create-LabUser -First "Frank" -Last "Ellis" -Title "Accounts Receivable" -Dept "Finance" -OU "OU=Finance,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "g.wright" -Groups @("Finance-Team","VPN-Users")
Create-LabUser -First "Amy" -Last "Stewart" -Title "Financial Analyst" -Dept "Finance" -OU "OU=Finance,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "p.anderson" -Groups @("Finance-Team","VPN-Users")
Create-LabUser -First "Victor" -Last "Petrov" -Title "Payroll Specialist" -Dept "Finance" -OU "OU=Finance,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "g.wright" -Groups @("Finance-Team","VPN-Users")
Create-LabUser -First "Laura" -Last "Bennett" -Title "Budget Analyst" -Dept "Finance" -OU "OU=Finance,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "p.anderson" -Groups @("Finance-Team","VPN-Users")
Create-LabUser -First "Steven" -Last "Cole" -Title "Tax Specialist" -Dept "Finance" -OU "OU=Finance,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "p.anderson" -Groups @("Finance-Team","VPN-Users")

# =============================================================
# HUMAN RESOURCES (8)
# =============================================================
Create-LabUser -First "Rebecca" -Last "Taylor" -Title "HR Director" -Dept "HR" -OU "OU=HR,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "m.ross" -Groups @("HR-Managers","VPN-Users")
Create-LabUser -First "Daniel" -Last "Martinez" -Title "HR Manager" -Dept "HR" -OU "OU=HR,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "r.taylor" -Groups @("HR-Managers","VPN-Users")
Create-LabUser -First "Olivia" -Last "Clark" -Title "Recruiter" -Dept "HR" -OU "OU=HR,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "d.martinez" -Groups @("HR-Team","VPN-Users")
Create-LabUser -First "Nathan" -Last "Hill" -Title "Recruiter" -Dept "HR" -OU "OU=HR,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "d.martinez" -Groups @("HR-Team","VPN-Users")
Create-LabUser -First "Emily" -Last "Adams" -Title "Benefits Coordinator" -Dept "HR" -OU "OU=HR,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "r.taylor" -Groups @("HR-Team","VPN-Users")
Create-LabUser -First "Tyler" -Last "Scott" -Title "Training Specialist" -Dept "HR" -OU "OU=HR,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "d.martinez" -Groups @("HR-Team","VPN-Users")
Create-LabUser -First "Grace" -Last "Lee" -Title "HR Analyst" -Dept "HR" -OU "OU=HR,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "r.taylor" -Groups @("HR-Team","VPN-Users")
Create-LabUser -First "Jason" -Last "Young" -Title "Compliance Officer" -Dept "HR" -OU "OU=HR,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "r.taylor" -Groups @("HR-Team","VPN-Users")

# =============================================================
# SALES (12)
# =============================================================
Create-LabUser -First "Andrew" -Last "Campbell" -Title "VP Sales" -Dept "Sales" -OU "OU=Sales,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "m.ross" -Groups @("Sales-Managers","VPN-Users")
Create-LabUser -First "Jennifer" -Last "Phillips" -Title "Sales Manager - East" -Dept "Sales" -OU "OU=Sales,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "a.campbell" -Groups @("Sales-Managers","VPN-Users")
Create-LabUser -First "Brian" -Last "Murphy" -Title "Sales Manager - West" -Dept "Sales" -OU "OU=Sales,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "a.campbell" -Groups @("Sales-Managers","VPN-Users")
Create-LabUser -First "Michelle" -Last "Rogers" -Title "Account Executive" -Dept "Sales" -OU "OU=Sales,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "j.phillips" -Groups @("Sales-Team","VPN-Users")
Create-LabUser -First "Eric" -Last "Butler" -Title "Account Executive" -Dept "Sales" -OU "OU=Sales,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "j.phillips" -Groups @("Sales-Team","VPN-Users")
Create-LabUser -First "Rachel" -Last "Foster" -Title "Account Executive" -Dept "Sales" -OU "OU=Sales,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "j.phillips" -Groups @("Sales-Team","VPN-Users")
Create-LabUser -First "Paul" -Last "Price" -Title "Account Executive" -Dept "Sales" -OU "OU=Sales,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "b.murphy" -Groups @("Sales-Team","VPN-Users")
Create-LabUser -First "Stephanie" -Last "Howard" -Title "Account Executive" -Dept "Sales" -OU "OU=Sales,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "b.murphy" -Groups @("Sales-Team","VPN-Users")
Create-LabUser -First "Justin" -Last "Ward" -Title "Sales Engineer" -Dept "Sales" -OU "OU=Sales,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "a.campbell" -Groups @("Sales-Team","VPN-Users")
Create-LabUser -First "Megan" -Last "Cox" -Title "SDR" -Dept "Sales" -OU "OU=Sales,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "j.phillips" -Groups @("Sales-Team","VPN-Users")
Create-LabUser -First "Carlos" -Last "Rivera" -Title "SDR" -Dept "Sales" -OU "OU=Sales,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "b.murphy" -Groups @("Sales-Team","VPN-Users")
Create-LabUser -First "Tiffany" -Last "Gray" -Title "Sales Operations" -Dept "Sales" -OU "OU=Sales,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "a.campbell" -Groups @("Sales-Team","VPN-Users")

# =============================================================
# ENGINEERING (15)
# =============================================================
Create-LabUser -First "Matthew" -Last "Hughes" -Title "VP Engineering" -Dept "Engineering" -OU "OU=Engineering,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "d.torres" -Groups @("Engineering-Leads","VPN-Users","RDP-Servers")
Create-LabUser -First "Amanda" -Last "Brooks" -Title "Engineering Manager" -Dept "Engineering" -OU "OU=Engineering,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "m.hughes" -Groups @("Engineering-Leads","VPN-Users","RDP-Servers")
Create-LabUser -First "William" -Last "Sanders" -Title "Engineering Manager" -Dept "Engineering" -OU "OU=Engineering,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "m.hughes" -Groups @("Engineering-Leads","VPN-Users","RDP-Servers")
Create-LabUser -First "Sophia" -Last "Ramirez" -Title "Senior Developer" -Dept "Engineering" -OU "OU=Engineering,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "a.brooks" -Groups @("Engineering-Team","VPN-Users","RDP-Servers")
Create-LabUser -First "Jack" -Last "Perry" -Title "Senior Developer" -Dept "Engineering" -OU "OU=Engineering,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "w.sanders" -Groups @("Engineering-Team","VPN-Users","RDP-Servers")
Create-LabUser -First "Chloe" -Last "Watson" -Title "Developer" -Dept "Engineering" -OU "OU=Engineering,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "a.brooks" -Groups @("Engineering-Team","VPN-Users")
Create-LabUser -First "Luke" -Last "Powell" -Title "Developer" -Dept "Engineering" -OU "OU=Engineering,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "a.brooks" -Groups @("Engineering-Team","VPN-Users")
Create-LabUser -First "Zoe" -Last "Long" -Title "Developer" -Dept "Engineering" -OU "OU=Engineering,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "w.sanders" -Groups @("Engineering-Team","VPN-Users")
Create-LabUser -First "Ethan" -Last "Barnes" -Title "Developer" -Dept "Engineering" -OU "OU=Engineering,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "w.sanders" -Groups @("Engineering-Team","VPN-Users")
Create-LabUser -First "Lily" -Last "Fisher" -Title "QA Engineer" -Dept "Engineering" -OU "OU=Engineering,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "a.brooks" -Groups @("Engineering-Team","VPN-Users")
Create-LabUser -First "Owen" -Last "Hayes" -Title "QA Engineer" -Dept "Engineering" -OU "OU=Engineering,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "w.sanders" -Groups @("Engineering-Team","VPN-Users")
Create-LabUser -First "Maya" -Last "Jordan" -Title "Security Developer" -Dept "Engineering" -OU "OU=Engineering,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "m.hughes" -Groups @("Engineering-Team","IT-Security","VPN-Users","RDP-Servers")
Create-LabUser -First "Ian" -Last "Griffin" -Title "DBA" -Dept "Engineering" -OU "OU=Engineering,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "m.hughes" -Groups @("Engineering-Team","VPN-Users","RDP-Servers")
Create-LabUser -First "Ava" -Last "Stone" -Title "Site Reliability Engineer" -Dept "Engineering" -OU "OU=Engineering,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "m.hughes" -Groups @("Engineering-Team","IT-DevOps","VPN-Users","RDP-Servers")
Create-LabUser -First "Leo" -Last "Dixon" -Title "Intern" -Dept "Engineering" -OU "OU=Engineering,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "a.brooks" -Groups @("Engineering-Team")

# =============================================================
# CONTRACTORS (5)
# =============================================================
Create-LabUser -First "Hassan" -Last "Omar" -Title "Security Consultant" -Dept "Contractors" -OU "OU=Contractors,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "k.liu" -Groups @("IT-Security","VPN-Users")
Create-LabUser -First "Priya" -Last "Sharma" -Title "Cloud Consultant" -Dept "Contractors" -OU "OU=Contractors,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "a.patel" -Groups @("IT-DevOps","VPN-Users")
Create-LabUser -First "Marco" -Last "Rossi" -Title "Pen Tester" -Dept "Contractors" -OU "OU=Contractors,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "k.liu" -Groups @("VPN-Users")
Create-LabUser -First "Aisha" -Last "Karim" -Title "Data Migration Specialist" -Dept "Contractors" -OU "OU=Contractors,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "j.wilson" -Groups @("VPN-Users","RDP-Servers")
Create-LabUser -First "Tom" -Last "Jenkins" -Title "Network Consultant" -Dept "Contractors" -OU "OU=Contractors,DC=yourlab,DC=local" -Password $DefaultUserPassword -Manager "j.wilson" -Groups @("VPN-Users")

# =============================================================
# SERVICE ACCOUNTS (10) - Key attack targets
# =============================================================
$ServiceAccounts = @(
    @{Name="svc_sql"; SPN="MSSQLSvc/sql01.yourlab.local:1433"; Desc="SQL Server Service"; Pass=$DefaultSvcPassword},
    @{Name="svc_web"; SPN="HTTP/web01.yourlab.local"; Desc="IIS Web Service"; Pass=$DefaultSvcPassword},
    @{Name="svc_exchange"; SPN="exchangeMDB/mail.yourlab.local"; Desc="Exchange Service"; Pass=$DefaultSvcPassword},
    @{Name="svc_sharepoint"; SPN="HTTP/sp01.yourlab.local"; Desc="SharePoint Service"; Pass=$DefaultSvcPassword},
    @{Name="svc_jenkins"; SPN="HTTP/jenkins.yourlab.local:8080"; Desc="Jenkins CI/CD"; Pass=$DefaultSvcPassword},
    @{Name="svc_scan"; SPN="HOST/scanner.yourlab.local"; Desc="Vulnerability Scanner"; Pass=$DefaultSvcPassword},
    @{Name="svc_monitoring"; SPN="HTTP/monitor.yourlab.local"; Desc="Monitoring Service"; Pass=$DefaultSvcPassword},
    @{Name="svc_print"; SPN="HOST/print01.yourlab.local"; Desc="Print Spooler Service"; Pass=$DefaultSvcPassword},
    @{Name="svc_antivirus"; SPN="HOST/av.yourlab.local"; Desc="Antivirus Management"; Pass=$DefaultSvcPassword},
    @{Name="svc_automate"; SPN="HTTP/automate.yourlab.local"; Desc="IT Automation"; Pass=$WeakSvcPassword}
)

foreach ($svc in $ServiceAccounts) {
    try {
        New-ADUser -Name $svc.Name -SamAccountName $svc.Name -UserPrincipalName "$($svc.Name)@yourlab.local" `
            -AccountPassword (ConvertTo-SecureString $svc.Pass -AsPlainText -Force) -Enabled $true `
            -Path "OU=Service Accounts,DC=yourlab,DC=local" -Description $svc.Desc `
            -PasswordNeverExpires $true -CannotChangePassword $true -ErrorAction Stop
        Set-ADUser -Identity $svc.Name -ServicePrincipalNames @{Add=$svc.SPN}
        Write-Host "[+] Created service account: $($svc.Name) with SPN: $($svc.SPN)" -ForegroundColor Cyan
    } catch {
        Write-Host "[*] Service account exists or error: $($svc.Name)" -ForegroundColor Yellow
    }
}

# =============================================================
# ATTACK PATHS - Misconfigurations for BloodHound
# =============================================================
Write-Host "`n[*] Configuring attack paths..." -ForegroundColor Magenta

# 1. IT-Admins get Domain Admin equivalent via GenericAll on Domain
$itAdmins = Get-ADGroup "IT-Admins"
# t.baker (Senior Sysadmin) added to Domain Admins directly - overprivileged
Add-ADGroupMember -Identity "Domain Admins" -Members "t.baker" -ErrorAction SilentlyContinue
Write-Host "[!] t.baker added to Domain Admins (overprivileged sysadmin)" -ForegroundColor Red

# 2. Help Desk can reset passwords (common misconfiguration)
$helpDeskOU = "OU=HR,DC=yourlab,DC=local"
$helpDeskGroup = Get-ADGroup "IT-HelpDesk"
$acl = Get-ACL "AD:\$helpDeskOU"
$helpDeskSID = New-Object System.Security.Principal.SecurityIdentifier $helpDeskGroup.SID
$resetPwdGuid = [GUID]"00299570-246d-11d0-a768-00aa006e0529"
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $helpDeskSID, "ExtendedRight", "Allow", $resetPwdGuid, "Descendents", [GUID]"bf967aba-0de6-11d0-a285-00aa003049e2"
)
$acl.AddAccessRule($ace)
Set-ACL "AD:\$helpDeskOU" $acl
Write-Host "[!] IT-HelpDesk can reset passwords in HR OU (attack path)" -ForegroundColor Red

# 3. svc_automate has GenericAll on IT OU (weak service account with high privs)
$svcAutomate = Get-ADUser "svc_automate"
$itOU = "OU=IT,DC=yourlab,DC=local"
$acl2 = Get-ACL "AD:\$itOU"
$svcSID = New-Object System.Security.Principal.SecurityIdentifier $svcAutomate.SID
$ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $svcSID, "GenericAll", "Allow", "Descendents", [GUID]"bf967aba-0de6-11d0-a285-00aa003049e2"
)
$acl2.AddAccessRule($ace2)
Set-ACL "AD:\$itOU" $acl2
Write-Host "[!] svc_automate has GenericAll on IT OU (Kerberoast -> GenericAll -> DA)" -ForegroundColor Red

# 4. Engineering-Leads can add members to IT-Admins (delegation misconfiguration)
$engLeads = Get-ADGroup "Engineering-Leads"
$itAdminsObj = Get-ADGroup "IT-Admins"
$acl3 = Get-ACL "AD:\CN=IT-Admins,$($itAdminsObj.DistinguishedName -replace 'CN=IT-Admins,','')"
$engSID = New-Object System.Security.Principal.SecurityIdentifier $engLeads.SID
$memberGuid = [GUID]"bf9679c0-0de6-11d0-a285-00aa003049e2"
$ace3 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $engSID, "WriteProperty", "Allow", $memberGuid
)
$acl3.AddAccessRule($ace3)
Set-ACL "AD:\$($itAdminsObj.DistinguishedName)" $acl3
Write-Host "[!] Engineering-Leads can write to IT-Admins membership (privesc path)" -ForegroundColor Red

# 5. Contractors OU - a.karim has WriteDACL on a server (simulated)
Write-Host "[!] Attack paths configured" -ForegroundColor Red

# =============================================================
# SUMMARY
# =============================================================
$userCount = (Get-ADUser -Filter *).Count
$groupCount = (Get-ADGroup -Filter *).Count
$ouCount = (Get-ADOrganizationalUnit -Filter *).Count
$spnCount = (Get-ADUser -Filter {ServicePrincipalName -like "*"}).Count

Write-Host "`n============================================" -ForegroundColor White
Write-Host "  YOURLAB.LOCAL - Population Complete" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor White
Write-Host "  Users:              $userCount" -ForegroundColor Green
Write-Host "  Groups:             $groupCount" -ForegroundColor Green
Write-Host "  OUs:                $ouCount" -ForegroundColor Green
Write-Host "  Kerberoastable:     $spnCount" -ForegroundColor Yellow
Write-Host "============================================" -ForegroundColor White
Write-Host "`n  KEY ATTACK PATHS:" -ForegroundColor Red
Write-Host "  1. svc_automate (weak password) -> Kerberoast -> GenericAll on IT OU -> DA" -ForegroundColor Red
Write-Host "  2. svc_backup -> Kerberoast -> Backup Operators" -ForegroundColor Red
Write-Host "  3. IT-HelpDesk -> Reset HR passwords -> Lateral movement" -ForegroundColor Red
Write-Host "  4. Engineering-Leads -> Write IT-Admins membership -> DA" -ForegroundColor Red
Write-Host "  5. t.baker -> Direct Domain Admin (overprivileged)" -ForegroundColor Red
Write-Host "`n  Run SharpHound again to collect new data for BloodHound!" -ForegroundColor Cyan
