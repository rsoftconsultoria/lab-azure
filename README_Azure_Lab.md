# Azure Lab – Infraestrutura com Ubuntu + Azure CLI (End-to-end)

**Escopo coberto (concluído com sucesso):**
- **1.** Preparar o Ubuntu e o Azure CLI  
- **2.** Rede (VNet, Subnets, NSG)  
- **3.** Azure Bastion  
- **4A.** VM privada **(sem IP público)** + backend Flask como **service** (via Bastion)  
- **4B.** App Service (Linux/Node) + **VNet Integration** + deploy ZIP + **teste ponta‑a‑ponta**  
- **5.** Backup (Recovery Services Vault): habilitar proteção + **Backup Now** + evidências  
- **6.1** Automation Account + Identidade Gerenciada + RBAC  
- **6.2** Runbooks (`Stop‑Lab` / `Start‑Lab`) – **PowerShell** + teste on‑demand  
- **6.3** Schedules (Seg–Sex **08:00/19:00**, fuso São Paulo) + vínculo aos runbooks

> **Nota**: Evitamos a **série B** (ex.: B2s). Para a VM usamos **Standard_D2as_v5** (2 vCPU / 8 GiB), opção econômica e amplamente disponível.

---

## 0) Convenções e Variáveis (definir 1x por sessão)

> Execute no **seu Ubuntu** antes de começar (ou sempre que abrir um novo terminal):

```bash
# Identidade do lab
export PREFIX="lab001"      # ajuste se quiser
export LOCATION="eastus"
export RG="rg-$PREFIX"

# Rede
export VNET="vnet-$PREFIX"
export SN_BACKEND="backend"
export SN_BASTION="AzureBastionSubnet"
export SN_APPSVC="appsvc-int"
export NSG="nsg-$PREFIX"

# Compute/App
export VM="vm-$PREFIX"
export NIC="nic-$PREFIX"
export VM_SIZE="Standard_D2as_v5"

export PLAN="asp-$PREFIX"
export APP="app-$PREFIX"

# Backup
export RSV="rsv-$PREFIX"

# Automação
export AA="aa-$PREFIX"
```

---

## 1) Ubuntu preparado com Azure CLI e login

**Instalação do Azure CLI (script oficial):**
```bash
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
az --version
```

**Login e seleção de assinatura:**
```bash
az login            # ou: az login --use-device-code
az account list -o table
az account set --subscription "<ID ou Nome>"
az account show -o table
```

**Chave SSH (para VMs):**
```bash
ssh-keygen -t ed25519 -C "azure-lab" -f ~/.ssh/id_ed25519
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
ls -l ~/.ssh/id_ed25519*
```

---

## 2) Rede – VNet, Subnets e NSG

**VNet + Subnets (com delegação da subnet de integração):**
```bash
# CIDRs
export VNET_CIDR="10.0.0.0/16"
export BACKEND_CIDR="10.0.1.0/24"
export BASTION_CIDR="10.0.2.0/26"   # requisito do Bastion
export APPSVC_CIDR="10.0.3.0/27"    # subnet p/ VNet Integration

# VNet + backend
az network vnet create -g "$RG" -n "$VNET" --address-prefix "$VNET_CIDR" \
  --subnet-name "$SN_BACKEND" --subnet-prefix "$BACKEND_CIDR"

# Bastion subnet
az network vnet subnet create -g "$RG" --vnet-name "$VNET" -n "$SN_BASTION" \
  --address-prefixes "$BASTION_CIDR"

# App Service Integration (delegada)
az network vnet subnet create -g "$RG" --vnet-name "$VNET" -n "$SN_APPSVC" \
  --address-prefixes "$APPSVC_CIDR" \
  --delegations Microsoft.Web/serverFarms
```

**NSG (22 só do Bastion; 5000/80/443 só do App Service):**
```bash
az network nsg create -g "$RG" -n "$NSG"

az network nsg rule create -g "$RG" --nsg-name "$NSG" -n Allow-SSH-from-Bastion \
  --priority 100 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes "$BASTION_CIDR" --destination-port-ranges 22

az network nsg rule create -g "$RG" --nsg-name "$NSG" -n Allow-App-from-AppService \
  --priority 110 --direction Inbound --access Allow --protocol Tcp \
  --source-address-prefixes "$APPSVC_CIDR" --destination-port-ranges 5000 80 443
```

**Validações/evidências:**
```bash
az network vnet show -g "$RG" -n "$VNET" -o jsonc
az network vnet subnet show -g "$RG" --vnet-name "$VNET" -n "$SN_APPSVC" -o jsonc
az network nsg rule list -g "$RG" --nsg-name "$NSG" -o table
```

---

## 3) Azure Bastion (PIP Standard + subnet /26)

```bash
az network public-ip create -g "$RG" -n "pip-bastion-$PREFIX" --sku Standard --allocation-method Static

az network bastion create -g "$RG" -n "bastion-$PREFIX" -l "$LOCATION" \
  --public-ip-address "pip-bastion-$PREFIX" --vnet-name "$VNET"

az network bastion show -g "$RG" -n "bastion-$PREFIX" -o table
```

> **Conexão via Portal**: VM → **Connect** → **Bastion** → **SSH** → usuário `azureuser` + **sua chave privada** (`~/.ssh/id_ed25519`).

---

## 4A) VM privada + backend Flask como **service** (via Bastion)

**NIC com NSG e VM (sem IP público):**
```bash
az network nic create -g "$RG" -n "$NIC" --vnet-name "$VNET" --subnet "$SN_BACKEND" \
  --network-security-group "$NSG"

az vm create -g "$RG" -n "$VM" --nics "$NIC" --image Ubuntu2204 --size "$VM_SIZE" \
  --admin-username azureuser --ssh-key-values ~/.ssh/id_ed25519.pub \
  --public-ip-address ""

az vm show -d -g "$RG" -n "$VM" --query "{name:name,privateIp:privateIps}" -o table
```

**Dentro da VM (via Bastion/SSH)** – instalar Flask e criar o serviço systemd:
```bash
# 1) Dependências
sudo apt-get update -y
sudo apt-get install -y python3-pip
sudo -H pip3 install --upgrade pip flask

# 2) App Flask (porta 5000)
sudo tee /opt/backend.py >/dev/null <<'PYEOF'
from flask import Flask
app = Flask(__name__)

@app.route("/")
def hi():
    return "Hello from private VM backend!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
PYEOF
sudo chmod 644 /opt/backend.py

# 3) Service
sudo tee /etc/systemd/system/backend.service >/dev/null <<'SYSEOF'
[Unit]
Description=Simple Flask Backend
After=network.target
[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/backend.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
SYSEOF

sudo systemctl daemon-reload
sudo systemctl enable --now backend

# 4) Validação local
sudo systemctl is-active backend
curl -sS http://127.0.0.1:5000
```

> **Aceite esperado:** serviço **active**, `curl` retorna **“Hello from private VM backend!”**.

---

## 4B) App Service + VNet Integration + deploy ZIP + teste

**Plano e Web App (Linux – Node LTS):**
```bash
az appservice plan create -g "$RG" -n "$PLAN" --sku S1 --is-linux
az webapp create -g "$RG" -p "$PLAN" -n "$APP" -r "NODE|20-lts"   # se falhar, use "NODE|18-lts"
```

**VNet Integration (subnet delegada `appsvc-int`):**
```bash
az webapp vnet-integration add -g "$RG" -n "$APP" --vnet "$VNET" --subnet "$SN_APPSVC"
az webapp vnet-integration list -g "$RG" -n "$APP" -o table
```

**Configurar BACKEND_URL com o IP privado da VM (porta 5000):**
```bash
VMIP=$(az vm show -d -g "$RG" -n "$VM" --query privateIps -o tsv)
az webapp config appsettings set -g "$RG" -n "$APP" --settings BACKEND_URL="http://$VMIP:5000"
```

**Aplicativo Node simples (frontend) e deploy ZIP (Kudu):**
```bash
mkdir -p /tmp/app && cd /tmp/app

cat > server.js <<'EOF'
const http=require('http'); const PORT=process.env.PORT||8080; const BACKEND=process.env.BACKEND_URL||'';
http.createServer((req,res)=>{
  if(req.url==='/backend'){
    if(!BACKEND){ res.statusCode=500; return res.end('BACKEND_URL not set'); }
    http.get(BACKEND,(r)=>{let d=''; r.on('data',c=>d+=c); r.on('end',()=>res.end(`Backend says: ${d}\n`));})
      .on('error',e=>{ res.statusCode=502; res.end('ERR '+e.message); });
  } else {
    res.end('Hello Frontend! Try /backend\n');
  }
}).listen(PORT);
EOF

cat > package.json <<'EOF'
{
  "name": "frontend",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": { "start": "node server.js" }
}
EOF

zip -qr app.zip .
az webapp deploy -g "$RG" -n "$APP" --src-path app.zip --type zip --track-status
```

**Teste ponta‑a‑ponta:**
```bash
APPURL="https://${APP}.azurewebsites.net"
curl -sS "$APPURL" && echo
curl -sS "$APPURL/backend" && echo
# Esperado: "Hello Frontend! ..." e "Backend says: Hello from private VM backend!"
```

---

## 5) Backup (RSV) – proteger VM + **Backup Now**

**Criar o cofre e redundância (LRS):**
```bash
az provider register --namespace Microsoft.RecoveryServices >/dev/null

az backup vault create -g "$RG" -n "$RSV" -l "$LOCATION"

# Ajustar LRS (mensagens informativas podem aparecer; comando funciona)
az backup vault backup-properties set -g "$RG" -n "$RSV" --backup-storage-redundancy LocallyRedundant

az backup vault backup-properties show -g "$RG" -n "$RSV" -o table
```

**Habilitar proteção (DefaultPolicy) e listar itens:**
```bash
az backup protection enable-for-vm --vault-name "$RSV" -g "$RG" --vm "$VM" --policy-name "DefaultPolicy"

az backup item list --vault-name "$RSV" -g "$RG" \
  --backup-management-type AzureIaasVM --workload-type VM -o table
```

**Backup Now (formato de data aceito) + acompanhamento do job:**
```bash
# Obter nomes de item e container a partir do item protegido
ITEM_NAME=$(az backup item list --vault-name "$RSV" -g "$RG" \
  --backup-management-type AzureIaasVM --workload-type VM \
  --query "[?properties.friendlyName=='$VM'].name | [0]" -o tsv)

CONTAINER_NAME=$(az backup item list --vault-name "$RSV" -g "$RG" \
  --backup-management-type AzureIaasVM --workload-type VM \
  --query "[?properties.friendlyName=='$VM'].properties.containerName | [0]" -o tsv)

# Retenção (DD-MM-YYYY)
RETENTION=$(date -d "+7 days" '+%d-%m-%Y')

# Disparar Backup Now e capturar o JOBID
JOBID=$(az backup protection backup-now \
  --vault-name "$RSV" -g "$RG" \
  --backup-management-type AzureIaasVM --workload-type VM \
  --container-name "$CONTAINER_NAME" --item-name "$ITEM_NAME" \
  --retain-until "$RETENTION" --query name -o tsv)
echo "JOBID=$JOBID"

# Poll simples até concluir (usa 'job list' para evitar bugs do 'job show')
while true; do
  STATUS=$(az backup job list --vault-name "$RSV" -g "$RG" \
    --query "[?name=='$JOBID'] | [0].properties.status" -o tsv)
  echo "Status: ${STATUS:-<aguardando>}"
  case "$STATUS" in
    Completed|CompletedWithWarnings|Failed) break ;;
  esac
  sleep 15
done

# Evidência do job
az backup job list --vault-name "$RSV" -g "$RG" \
  --query "[?name=='$JOBID'] | [0].{operation:properties.operation,status:properties.status,start:properties.startTime,end:properties.endTime}" -o table
```

---

## 6.1) Automation Account + MI + RBAC

```bash
# Extensão (idempotente)
az config set extension.use_dynamic_install=yes_without_prompt
az extension add -n automation --upgrade

# Criar AA (SKU Basic)
az automation account create -g "$RG" -n "$AA" -l "$LOCATION" --sku Basic

# Habilitar identidade gerenciada (SystemAssigned) e conceder RBAC=Contributor no RG
AA_ID=$(az automation account show -g "$RG" -n "$AA" --query id -o tsv)
az resource update --ids "$AA_ID" --set identity.type=SystemAssigned

MI_PRINCIPAL=$(az resource show --ids "$AA_ID" --query identity.principalId -o tsv)
RG_ID=$(az group show -n "$RG" --query id -o tsv)

az role assignment create --role Contributor \
  --assignee-object-id "$MI_PRINCIPAL" --assignee-principal-type ServicePrincipal \
  --scope "$RG_ID"
```

---

## 6.2) Runbooks `Stop‑Lab` e `Start‑Lab` (PowerShell) + teste on‑demand

**Criar os arquivos dos runbooks (no seu Ubuntu):**
```bash
# Stop-Lab
cat > /tmp/Stop-Lab.ps1 <<'PS1'
param([Parameter(Mandatory=$true)][string]$ResourceGroupName)

Disable-AzContextAutosave -Scope Process
Connect-AzAccount -Identity | Out-Null
Set-AzContext -Subscription (Get-AzContext).Subscription

# WebApps -> Stop
$apps = Get-AzWebApp -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
foreach ($app in $apps) {
  if ($app.State -ne "Stopped") {
    Write-Output "Stopping WebApp: $($app.Name)"
    Stop-AzWebApp -ResourceGroupName $ResourceGroupName -Name $app.Name -ErrorAction Continue
  } else {
    Write-Output "WebApp $($app.Name) já está Stopped"
  }
}

# VMs -> Deallocate
$vms = Get-AzVM -ResourceGroupName $ResourceGroupName -Status -ErrorAction SilentlyContinue
foreach ($vm in $vms) {
  $state = ($vm.Statuses | Where-Object { $_.Code -like "PowerState/*" }).DisplayStatus
  if ($state -notin @("VM deallocated","VM stopped")) {
    Write-Output "Deallocating VM: $($vm.Name) (estado atual: $state)"
    Stop-AzVM -ResourceGroupName $ResourceGroupName -Name $vm.Name -Force -ErrorAction Continue
  } else {
    Write-Output "VM $($vm.Name) já está parada/deallocated (estado: $state)"
  }
}
Write-Output "Stop-Lab finalizado."
PS1

# Start-Lab
cat > /tmp/Start-Lab.ps1 <<'PS2'
param([Parameter(Mandatory=$true)][string]$ResourceGroupName)

Disable-AzContextAutosave -Scope Process
Connect-AzAccount -Identity | Out-Null
Set-AzContext -Subscription (Get-AzContext).Subscription

# VMs -> Start
Get-AzVM -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue | ForEach-Object {
  Write-Output "Starting VM: $($_.Name)"
  Start-AzVM -ResourceGroupName $ResourceGroupName -Name $_.Name -ErrorAction Continue
}

# WebApps -> Start
$apps = Get-AzWebApp -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
foreach ($app in $apps) {
  if ($app.State -ne "Running") {
    Write-Output "Starting WebApp: $($app.Name)"
    Start-AzWebApp -ResourceGroupName $ResourceGroupName -Name $app.Name -ErrorAction Continue
  } else {
    Write-Output "WebApp $($app.Name) já está Running"
  }
}
Write-Output "Start-Lab finalizado."
PS2
```

**Criar, enviar conteúdo e publicar (tipo `PowerShell`):**
```bash
for RB in Stop-Lab Start-Lab; do
  az automation runbook create \
    --resource-group "$RG" --automation-account-name "$AA" \
    --name "$RB" --type PowerShell --location "$LOCATION"

  az automation runbook replace-content \
    --resource-group "$RG" --automation-account-name "$AA" \
    --name "$RB" --content @/tmp/$RB.ps1

  az automation runbook publish \
    --resource-group "$RG" --automation-account-name "$AA" \
    --name "$RB"
done

az automation runbook list -g "$RG" --automation-account-name "$AA" \
  --query "[].{name:name,state:state,runbookType:runbookType}" -o table
# Esperado: Published / PowerShell
```

**Testes on‑demand (Stop → validar → Start → validar):**
```bash
# STOP
JOB_STOP=$(az automation runbook start -g "$RG" --automation-account-name "$AA" \
  --name "Stop-Lab" --parameters ResourceGroupName="$RG" --query jobId -o tsv)

for i in $(seq 1 30); do
  WEBAPP_STATE=$(az webapp show -g "$RG" -n "$APP" --query state -o tsv 2>/dev/null || echo "n/a")
  VM_STATE=$(az vm get-instance-view -g "$RG" -n "$VM" \
    --query "instanceView.statuses[?starts_with(code, 'PowerState/')].displayStatus" -o tsv 2>/dev/null || echo "n/a")
  echo "t+$((i*6))s  WebApp=$WEBAPP_STATE  VM=$VM_STATE"
  [ "$WEBAPP_STATE" = "Stopped" ] && [ "$VM_STATE" = "VM deallocated" ] && break
  sleep 6
done

# START
JOB_START=$(az automation runbook start -g "$RG" --automation-account-name "$AA" \
  --name "Start-Lab" --parameters ResourceGroupName="$RG" --query jobId -o tsv)

for i in $(seq 1 30); do
  WEBAPP_STATE=$(az webapp show -g "$RG" -n "$APP" --query state -o tsv 2>/dev/null || echo "n/a")
  VM_STATE=$(az vm get-instance-view -g "$RG" -n "$VM" \
    --query "instanceView.statuses[?starts_with(code, 'PowerState/')].displayStatus" -o tsv 2>/dev/null || echo "n/a")
  echo "t+$((i*6))s  WebApp=$WEBAPP_STATE  VM=$VM_STATE"
  [ "$WEBAPP_STATE" = "Running" ] && [ "$VM_STATE" = "VM running" ] && break
  sleep 6
done
```

---

## 6.3) Schedules (Seg–Sex 08:00/19:00, fuso São Paulo) + vínculo

**Script PowerShell (device code + `-DaysOfWeek`), salvo e executado:**
```bash
# (Opcional) pegue sua assinatura ativa p/ fixar no PS:
export SUB_ID=$(az account show --query id -o tsv)

cat > /tmp/aa_schedules_v2.ps1 <<'PS1'
$ErrorActionPreference = 'Stop'
$RG = $env:RG; $AA = $env:AA; $SUB_ID = $env:SUB_ID
$TimeZone = 'America/Sao_Paulo'

Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
Install-Module Az.Accounts,Az.Automation -Scope CurrentUser -Force -AllowClobber
Import-Module Az.Accounts; Import-Module Az.Automation
Connect-AzAccount -UseDeviceAuthentication | Out-Null
if ($SUB_ID) { Select-AzSubscription -SubscriptionId $SUB_ID | Out-Null }

function Get-NextLocal([string]$hhmm, [string]$ianaId) {
    $tz=[TimeZoneInfo]::FindSystemTimeZoneById($ianaId)
    $nowLocal=[TimeZoneInfo]::ConvertTimeFromUtc([DateTime]::UtcNow,$tz)
    $h,$m=$hhmm.Split(':'); $candidate=Get-Date -Date $nowLocal.Date -Hour $h -Minute $m -Second 0
    if ($candidate -le $nowLocal) { $candidate=$candidate.AddDays(1) }
    return $candidate
}
$startLocal=Get-NextLocal '08:00' 'America/Sao_Paulo'
$stopLocal =Get-NextLocal '19:00' 'America/Sao_Paulo'

[System.DayOfWeek[]]$weekDays=@(
  [System.DayOfWeek]::Monday,[System.DayOfWeek]::Tuesday,[System.DayOfWeek]::Wednesday,
  [System.DayOfWeek]::Thursday,[System.DayOfWeek]::Friday
)

foreach ($def in @(@{Name='Start-Weekdays-0800';Time=$startLocal}, @{Name='Stop-Weekdays-1900';Time=$stopLocal})) {
  $exists=Get-AzAutomationSchedule -ResourceGroupName $RG -AutomationAccountName $AA -Name $def.Name -ErrorAction SilentlyContinue
  if ($exists) { Remove-AzAutomationSchedule -ResourceGroupName $RG -AutomationAccountName $AA -Name $def.Name -Force -ErrorAction SilentlyContinue }
  New-AzAutomationSchedule -ResourceGroupName $RG -AutomationAccountName $AA -Name $def.Name `
    -StartTime $def.Time -TimeZone $TimeZone -WeekInterval 1 -DaysOfWeek $weekDays | Out-Null
}

Register-AzAutomationScheduledRunbook -ResourceGroupName $RG -AutomationAccountName $AA `
  -RunbookName 'Start-Lab' -ScheduleName 'Start-Weekdays-0800' -Parameters @{ ResourceGroupName=$RG } -ErrorAction SilentlyContinue | Out-Null
Register-AzAutomationScheduledRunbook -ResourceGroupName $RG -AutomationAccountName $AA `
  -RunbookName 'Stop-Lab'  -ScheduleName 'Stop-Weekdays-1900'  -Parameters @{ ResourceGroupName=$RG } -ErrorAction SilentlyContinue | Out-Null

Get-AzAutomationSchedule -ResourceGroupName $RG -AutomationAccountName $AA |
  ? { $_.Name -in 'Start-Weekdays-0800','Stop-Weekdays-1900' } |
  Select Name,StartTime,NextRun,TimeZone,Interval,Frequency,DaysOfWeek | Format-Table -AutoSize

Get-AzAutomationScheduledRunbook -ResourceGroupName $RG -AutomationAccountName $AA |
  ? { $_.ScheduleName -in 'Start-Weekdays-0800','Stop-Weekdays-1900' } |
  Select RunbookName,ScheduleName,LastRunTime | Format-Table -AutoSize
PS1

pwsh -NoLogo -File /tmp/aa_schedules_v2.ps1
```

**Evidências esperadas:**  
- **Schedules** com `TimeZone=America/Sao_Paulo`, `Frequency=Week`, `DaysOfWeek=Mon..Fri`, `NextRun` coerente.  
- **ScheduledRunbook** contendo os dois vínculos (`Start-Lab` ↔ `Start-Weekdays-0800`, `Stop-Lab` ↔ `Stop-Weekdays-1900`).

---

## 7) (Opcional) Teardown do ambiente

```bash
az group delete -n "$RG" --yes --no-wait
```

---

## Dicas de Troubleshooting

- **RunCommand devolvendo “This is a sample script”**  
  → Prefira **Bastion** para executar o bootstrap do backend **dentro da VM** (como acima).  
- **/backend com erro no App Service**  
  → Verifique: serviço Flask **ativo** na VM; **VNet Integration** **ativa**; regra **NSG** permitindo 5000 do **CIDR da subnet appsvc-int**; `BACKEND_URL=http://<IP-privado>:5000`.  
- **Backup Now – retenção inválida**  
  → Use **`DD-MM-YYYY`** (ou `DD-MM-YYYY-HH:MM:SS`) em `--retain-until`.  
- **Automation – ‘Connect‑AzAccount’ não reconhecido**  
  → Atualize módulos **Az** dentro da **Automation Account** (Portal → *Modules* → *Update Az modules*) e republique os runbooks se necessário.  
- **Schedules por CLI**  
  → O `az automation schedule create` **não** oferece parâmetro de dias da semana; por isso usamos **PowerShell** com `-DaysOfWeek` e `-WeekInterval`.
