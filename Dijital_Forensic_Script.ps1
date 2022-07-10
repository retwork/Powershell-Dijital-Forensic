


$header = @"

<style>

    h1 {

        background: #395870;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 25px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;

    } 
	
	h2{
		
		
        background: #395870;
        background: linear-gradient(#49708f, #49708f);
        color: #fff;
        font-size: 15px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;
		
		
	}
	
	table {
		font-size: 12px;
		border: 0px; 
		font-family: Arial, Helvetica, sans-serif;
	} 
	
    td {
		padding: 4px;
		margin: 0px;
		border: 0;
	}
	
    th {
        background: #395870;
        background: linear-gradient(#7E7E80, #293f50);
        color: #fff;
        font-size: 11px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;
	}

    tbody tr:nth-child(even) {
        background: #f0f0f2;
    }

        #CreationDate {

        font-family: Arial, Helvetica, sans-serif;
        color: #ff3300;
        font-size: 12px;

    }
	


</style>

"@

#SİSTEM BİLGİLERİ

$SistemAdi = "<h1>Sistem Bilgileri: $env:computername</h1>" 

$LocalGroupMember = Get-LocalGroupMember -Group "Administrators" | Convertto-html -Fragment -PreContent "<h2>Administrator Grubuna Uye Olan Kullanicilar</h2>"

$StartupProgs = Get-WmiObject Win32_StartupCommand | Select-Object Command, User, Caption | ConvertTo-Html -Fragment -PreContent "<h2>Baslangicta Calisan Programlar</h2>"

$PowershellHistory = Get-History -count 5 | Select-Object id, commandline, startexecutiontime, endexecutiontime | ConvertTo-Html -Fragment -PreContent "<h2>Powershell Uzerinde En son Calistirilan Komutlar</h2>"

$Downloads = Get-ChildItem C:\Users\*\Downloads\* -recurse  |  Select-Object  PSChildName, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { ($_.extension -eq '.exe') -or ($_.extension -eq '.bat') -or ($_.extension -eq '.vbs') -or ($_.extension -eq '.zip') -or ($_.extension -eq '.gz') } | Convertto-html -Fragment -PreContent "<h2>En Son Indirilen Uygulamalar</h2>"

$Antivirus = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName, pathToSignedProductExe, pathToSignedReportingExe, productState, timestamp  | ConvertTo-Html -Fragment -PreContent "<h2>Guvenlik Yazilimlari</h2>"

$TempDosyalari = Get-ChildItem C:\Users\*\AppData\Local\Temp\* -recurse  |  Select-Object  Name, FullName, Extension, CreationTimeUTC, LastAccessTimeUTC, LastWriteTimeUTC, Attributes | Where-Object { ($_.extension -eq '.exe') -or ($_.extension -eq '.bat') -or ($_.extension -eq '.vbs') -or ($_.extension -eq '.zip') -or ($_.extension -eq '.gz') } | Convertto-html -Fragment -PreContent "<h2>Temp Icerisine Indirilen Uygulamalar</h2>"

$WmiObject = Get-WmiObject Win32_ShortcutFile | Select-Object Filename, @{NAME = 'CreationDate'; Expression = { $_.ConvertToDateTime($_.CreationDate) } }, @{Name = 'LastAccessed'; Expression = { $_.ConvertToDateTime($_.LastAccessed) } }, @{Name = 'LastModified'; Expression = { $_.ConvertToDateTime($_.LastModified) } }, Target | Where-Object { $_.LastModified -gt ((Get-Date).AddDays(-1)) } | Convertto-html -Fragment -PreContent "<h2>En Son Erisim Yapilan Uygulamalar</h2>"

$USBGecmisi = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*' | Select-Object FriendlyName, Service, ContainerID | ConvertTo-Html -Fragment -PreContent "<h2>USB Aygit Gecmisi</h2>"

$SistemDiskKlasorleri = Get-ChildItem c:\ | select-Object Mode, LastWriteTime, Length, Name | Convertto-html -Fragment -PreContent "<h2>Windows C:\ Klasor Bilgileri</h2>"

$ZamanlanmisGorevler = Get-ScheduledTask | Select-Object State,Actions,Date,Description,Source,TaskName,TaskPath,Triggers | Where-Object {$_.State -eq "Running"} |ConvertTo-Html -Fragment -PreContent "<h2>Zamanlanmis Gorev Listesi</h2>"

$LokalGrup  = Get-LocalGroup | ConvertTo-Html -Fragment -PreContent "<h2> Lokal Grup Listesi </h2>"

$YukluProgramlar = Get-CimInstance -ClassName win32_product | Select-Object Name, Version, Vendor, InstallDate, InstallSource, PackageName, LocalPackage | ConvertTo-Html -Fragment -PreContent "<h2>Yuklu Programlar</h2>"

$AgAdaptoru = Get-WmiObject -class Win32_NetworkAdapter  | Select-Object -Property AdapterType,ProductName,Description,MACAddress,Availability,NetconnectionStatus,NetEnabled,PhysicalAdapter | ConvertTo-Html -Fragment -PreContent "<h2>Network Interface Bilgileri</h2>"

$SonDosyaOlusturmaIslemleri = Get-WmiObject Win32_ShortcutFile | Select-Object Filename, Caption, @{NAME='CreationDate';Expression={$_.ConvertToDateTime($_.CreationDate)}}, @{Name='LastAccessed';Expression={$_.ConvertToDateTime($_.LastAccessed)}}, @{Name='LastModified';Expression={$_.ConvertToDateTime($_.LastModified)}}, Target | Where-Object {$_.LastModified -gt ((Get-Date).AddDays(-10)) } | Sort-Object LastModified -Descending | ConvertTo-Html -Fragment  -PreContent "<h2>En Son Olusturulan Dosyalar</h2>"

#DNS İSTEMCİ CACHE BİLGİSİ
function Get-DnsClientCache {

    [CmdletBinding()]

    param (

        [string]
        $IpConfigPath = 'C:\Windows\System32\ipconfig.exe',

        [string]
        $IpConfigArgs = '/displaydns',

        [string]
        $TempFile = (Join-Path -Path $env:TEMP -ChildPath $(([System.Guid]::NewGuid().Guid) + '.txt'))

    ) 

    process {

        $SplatArgs = @{ FilePath = $IpConfigPath
                        ArgumentList = $IpConfigArgs
                        NoNewWindow = $true
                        Wait = $true
                        RedirectStandardOutput = $TempFile }

        Start-Process @SplatArgs

        $IpConfigOutput = Get-Content -Path $TempFile

        Remove-Item -Path $TempFile | Out-Null

        $DnsClientCache = @()

        $IpConfigOutput | Select-String -Pattern "Record Name" -Context 0,5 | ForEach-Object {

            $Record = New-Object -TypeName psobject -Property @{

                Name = (($_.Line -split ':')[1]).Trim()
                Type = (($_.Context.PostContext[0] -split ':')[1]).Trim()
                TTL = (($_.Context.PostContext[1] -split ':')[1]).Trim()
                Length = (($_.Context.PostContext[2] -split ':')[1]).Trim()
                Section = (($_.Context.PostContext[3] -split ':')[1]).Trim()
                HostRecord = (($_.Context.PostContext[4] -split ':')[1]).Trim()

            } 

            $DnsClientCache += $Record

        } 

        Write-Output -InputObject $DnsClientCache

    } 
}


$DNSCacheBilgisi = Get-DnsClientCache | ConvertTo-Html -Fragment -PreContent "<h2>DNS Cache Bilgisi</h2>"

#Kullanıcı Günlük Aktiviteleri
function Get-UserActivity {

[CmdletBinding()]
param
(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string[]]$ComputerName = $Env:COMPUTERNAME
)

try {
	
  
    $sessionEvents = @(
        @{ 'Label' = 'Logon'; 'EventType' = 'SessionStart'; 'LogName' = 'Security'; 'ID' = 4624 } ## --> Audit Logon Olayları
        @{ 'Label' = 'Logoff'; 'EventType' = 'SessionStop'; 'LogName' = 'Security'; 'ID' = 4647 } ## --> Audit Logoff Olayları
        @{ 'Label' = 'Startup'; 'EventType' = 'SessionStop'; 'LogName' = 'System'; 'ID' = 6005 }
        @{ 'Label' = 'RdpSessionReconnect'; 'EventType' = 'SessionStart'; 'LogName' = 'Security'; 'ID' = 4778 } ## --> Diğer Audit Logon/Logoff Olayları
        @{ 'Label' = 'RdpSessionDisconnect'; 'EventType' = 'SessionStop'; 'LogName' = 'Security'; 'ID' = 4779 } ## --> Diğer Audit Logon/Logoff Olayları
        @{ 'Label' = 'Locked'; 'EventType' = 'SessionStop'; 'LogName' = 'Security'; 'ID' = 4800 } ## --> Diğer Audit Logon/Logoff Olayları
        @{ 'Label' = 'Unlocked'; 'EventType' = 'SessionStart'; 'LogName' = 'Security'; 'ID' = 4801 } ##  --> Diğer Audit Logon/Logoff Olayları
    )
    

    $sessionStartIds = ($sessionEvents | Where-Object { $_.EventType -eq 'SessionStart' }).ID
    $sessionStopIds = ($sessionEvents | Where-Object { $_.EventType -eq 'SessionStop' }).ID

    $logNames = ($sessionEvents.LogName | Select-Object -Unique)
    $ids = $sessionEvents.Id
		
    $logonXPath = "Event[System[EventID=4624]] and Event[EventData[Data[@Name='TargetDomainName'] != 'Window Manager']] and Event[EventData[Data[@Name='TargetDomainName'] != 'NT AUTHORITY']] and (Event[EventData[Data[@Name='LogonType'] = '2']] or Event[EventData[Data[@Name='LogonType'] = '10']])"
    $otherXpath = 'Event[System[({0})]]' -f "EventID=$(($ids.where({ $_ -ne '4624' })) -join ' or EventID=')"
    $xPath = '({0}) or ({1})' -f $logonXPath, $otherXpath

    foreach ($computer in $ComputerName) {
     
        $events = Get-WinEvent -ComputerName $computer -LogName $logNames -FilterXPath $xPath
        Write-Verbose -Message "Found [$($events.Count)] events to look through"

        
        $output = [ordered]@{
            'ComputerName'          = $computer
            'Username'              = $null
            'StartTime'             = $null
            'StartAction'           = $null
            'StopTime'              = $null
            'StopAction'            = $null
            'Session Active (Days)' = $null
            'Session Active (Min)'  = $null
        }
        
   
        $getGimInstanceParams = @{
            ClassName = 'Win32_ComputerSystem'
        }
        if ($computer -ne $Env:COMPUTERNAME) {
            $getGimInstanceParams.ComputerName = $computer
        }
        $loggedInUsers = Get-CimInstance @getGimInstanceParams | Select-Object -ExpandProperty UserName | ForEach-Object { $_.split('\')[1] }
            
     
        $events.where({ $_.Id -in $sessionStartIds }).foreach({
                try {
                    $logonEvtId = $_.Id
                    $output.StartAction = $sessionEvents.where({ $_.ID -eq $logonEvtId }).Label
                    $xEvt = [xml]$_.ToXml()

                  
                    $output.Username = ($xEvt.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
                    $logonId = ($xEvt.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetLogonId' }).'#text'
                    if (-not $logonId) {
                        $logonId = ($xEvt.Event.EventData.Data | Where-Object { $_.Name -eq 'LogonId' }).'#text'
                    }
                    $output.StartTime = $_.TimeCreated
        
                    Write-Verbose -Message "Yeni oturum başlatma etkinliği bulundu: Etkinlik kimliği [$($logonEvtId)] username [$($output.Username)] logonID [$($logonId)] time [$($output.StartTime)]"
                   
                    if (-not ($sessionEndEvent = $Events.where({ 
                                    $_.TimeCreated -gt $output.StartTime -and
                                    $_.ID -in $sessionStopIds -and
                                    (([xml]$_.ToXml()).Event.EventData.Data | Where-Object { $_.Name -eq 'TargetLogonId' }).'#text' -eq $logonId
                                })) | Select-Object -last 1) {
                        if ($output.UserName -in $loggedInUsers) {
                            $output.StopTime = Get-Date
                            $output.StopAction = 'Still logged in'
                        } else {
                            throw "Oturum acma kimligi icin bir oturum bitis etkinligi bulunamadi [$($logonId)]."
                        }
                    } else {
                       
                        $output.StopTime = $sessionEndEvent.TimeCreated
                        Write-Verbose -Message "Session stop ID is [$($sessionEndEvent.Id)]"
                        $output.StopAction = $sessionEvents.where({ $_.ID -eq $sessionEndEvent.Id }).Label
                    }

                    $sessionTimespan = New-TimeSpan -Start $output.StartTime -End $output.StopTime
                    $output.'Session Active (Days)' = [math]::Round($sessionTimespan.TotalDays, 1)
                    $output.'Session Active (Min)'  = [math]::Round($sessionTimespan.TotalMinutes, 1)
                    
                    [pscustomobject]$output
                } catch {
                    Write-Warning -Message $_.Exception.Message
                }
            })
    }
} catch {
    $PSCmdlet.ThrowTerminatingError($_)
}
    
}


$GunlukKullaniciAktiviteleri = Get-UserActivity | ConvertTo-Html -Fragment -PreContent "<h2>Sistem Kullanici Aktiviteleri</h2>"

#UDP Port Durumu
Function Get-UDPPorts {
   

    [CmdletBinding()]
    Param()

    Begin {}

    Process {
        $Result = Invoke-Expression -Command "netstat -ano" | 
            Select-String -Pattern "\s+(UDP)" | 
            Select-Object -Property @{Name="Data"; Expression={$_.Line.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)}} | 
            Where-Object { $_.Data[1] -notmatch "^\[::"} | 
            ForEach-Object {     
                $localAddress = $_.Data[1].Substring(0, $_.Data[1].LastIndexOf(":"))
                $port = $_.Data[1].Substring($_.Data[1].LastIndexOf(":") + 1)
                $processId = $_.Data[3]
                $processName = Get-Process -Id $processId | Select-Object -ExpandProperty Name
                return New-Object -TypeName PSObject -Property @{"Local Address"=$localAddress;"Port"=$port;"Process Id"=$processId;"Process Name"=$processName}
            }
    }

    End {
        $Result
    }
}


#$UDPPortDurum = Get-UDPPorts | ConvertTo-Html -Fragment -PreContent "<h2>UDP port Durumu</h2>"

#Sistem TCP Port Listesi
Function Get-TCPPorts {
   
    [CmdletBinding()]
    Param()

    Begin {}

    Process {
        $Result = Get-NetTCPConnection -ErrorAction SilentlyContinue | 
            Where-Object {$_.State -eq "Listen" -and $_.LocalAddress -notmatch "^::"} | 
            Select-Object -Property @{Name="Local Address";Expression={$_.LocalAddress}}, 
                                    @{Name="Port";Expression={$_.LocalPort}},
                                    @{Name="Process Id";Expression={$_.OwningProcess}},
                                    @{Name="Process Name";Expression={Get-Process -Id $_.OwningProcess | Select-Object -ExpandProperty Name}}        
    }

    End {
        Write-Output $Result
    }
} 

#$SistemTCPPort = Get-TCPPorts | ConvertTo-Html -Fragment -PreContent "<h2>TCP/IP Port Durumu</h2>"

#Sistem Servis Listesi
    
Function Get-SystemServices {
    

    [CmdletBinding()]
    Param()

    Begin {}

    Process {
        $Result = Get-Service -ErrorAction SilentlyContinue | Select-Object -Property Name,DisplayName,@{Name="Status";Expression={$_.Status.ToString()}}       
    }

    End {
        Write-Output $Result
    }
}   

$SistemServisDurumu = Get-SystemServices | ConvertTo-Html -Fragment -PreContent "<h2>Sistem Servis Durumu</h2>"

#USB Aygıt Durumu

Function Get-USBDevices {
    

    [CmdletBinding()]
    Param()

    Begin {}

    Process {
        $Result = Get-WmiObject -Class Win32_USBControllerDevice -ErrorAction SilentlyContinue | 
            ForEach-Object { [wmi]($_.Dependent)} | 
            Select-Object -Property Name,Description,DeviceID,Service,Present,Status,Manufacturer,@{Name="Install Date";Expression={$_.InstallDate}}
    }

    End {
        Write-Output $Result
    }
}  


$USBAygitDurum = Get-USBDevices | ConvertTo-Html -Fragment -PreContent "<h2>USB Aygit Durumu</h2>"

#Bekleyen Reboot Durumu

Function Get-PendingReboots {
    

    [CmdletBinding()]
    Param()

    Begin {    
        $cbsReboot = $false
        $sccmReboot = $false
    }

    Process {
        $wmi_os = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber -ErrorAction SilentlyContinue | Select-Object -ExpandProperty BuildNumber
        $wuReboot = Test-Path -Path "HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"

        
        if ([Int32]$wmi_os -ge 6001)
        {
            $cbsReboot = $null -ne (Get-ChildItem -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing" | Select-Object -ExpandProperty Name | Where-Object {$_ -contains "RebootPending"})
        }

        #$fileRenameReboot = Test-RegistryEntry -Key "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager" -PropertyName "PendingFileRenameOperations" 

        $computerRenameReboot = (Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName" -Name ComputerName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ComputerName) -ne 
            (Get-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName" -Name ComputerName -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ComputerName)

        try
        {
            $sccmClientSDK = Invoke-WmiMethod -Class CCM_ClientUtilities -Name "DetermineIfRebootPending" -Namespace "ROOT\\ccm\\ClientSDK" -ErrorAction Stop
            $sccmReboot = ($sccmClientSDK.IsHardRebootPending -or $sccmClientSDK.RebootPending)
        }
        catch {}
    }

    End {
        Write-Output (New-Object -TypeName PSObject -Property @{"Windows Update"= $wuReboot;"Component Based Servicing"=$cbsReboot;"File Rename"=$fileRenameReboot;"Computer Rename"=$computerRenameReboot;"CCM Client"=$sccmReboot})
    }
}


$BekleyenReboot= Get-PendingReboots | ConvertTo-Html -Fragment -PreContent "<h2>Bekleyen Reboot Durumu</h2>"



#Windows Update Durumu
Function Get-MicrosoftUpdates {
    
    
    [CmdletBinding()]
    Param()

    Begin {
        #[regex]$Regex = KB\d*
    }

    Process {

        $Session = New-Object -ComObject Microsoft.Update.Session
        $Searcher = $Session.CreateUpdateSearcher()
        $History = $Searcher.GetTotalHistoryCount()

        $Result = $Searcher.QueryHistory(1, $History) | Select-Object -Property @{Name="Hot Fix ID";Expression={$Regex.Match($_.Title).Value}},
        Title,
        @{Name="Operation";Expression={switch($_.Operation) {
                    1 {"Install"};
                    2 {"Uninstall"};
                    3 {"Other"}
                }
            }
        },
        @{Name="Status";Expression={switch($_.ResultCode) {
                    1 {"In Progress"};
                    2 {"Succeeded"};
                    3 {"Succeeded With Errors"};
                    4 {"Failed"};
                    5 {"Aborted"};
                }
            }
        },
        @{Name="Date";Expression={(Get-Date($_.Date) -Format FileDateTimeUniversal).ToString()}}
    }

    End {
        Write-Output $Result
    }
}


$WindowsUpdateDurum = Get-MicrosoftUpdates | ConvertTo-Html -Fragment -PreContent "<h2>Windows Update Durumu</h2>"


#Windows Güncelleme Yapılamayan Paketleri

Function Get-MissingWindowsUpdates {
   
    [CmdletBinding()]
    Param(
        [Parameter(Position=0,ValueFromPipelineByPropertyName=$true)]
        [bool]$RecommendedOnly = $false,
        [Parameter(Position=1,ValueFromPipelineByPropertyName=$true)]
        [string]$ProxyAddress = $null
    )

    Begin {
        $MissingUpdates = @()
    }

    Process {
        try {
            $Session = New-Object -ComObject Microsoft.Update.Session

            if ($null -ne $ProxyAddress) { 
                Write-Verbose "Setting Proxy" 
                $Proxy = New-Object -ComObject Microsoft.Update.WebProxy
                $Session.WebProxy.Address = $ProxyAddress 
                $Session.WebProxy.AutoDetect = $false 
                $Session.WebProxy.BypassProxyOnLocal = $true 
            } 

            $Searcher = $Session.CreateUpdateSearcher()

            if ($RecommendedOnly) {
                $SearchResults = $Searcher.Search("IsInstalled=0 and AutoSelectOnWebsites=1")
            }
            else {
                $SearchResults = $Searcher.Search("IsInstalled=0")
            }

            $SearchResults.RootCategories | ForEach-Object {
                foreach($Update in $_.Updates) {
                    $KB = [Regex]::Match($Update.Title, "^.*\b(KB[0-9]+)\b.*$").Groups[1].Value

                    $UpdateObject = New-Object -TypeName PSObject -Property @{"KB"=$KB;"Category"=$_.Name;"Title"=$Update.Title;"Type"=$Update.Type;"IsDownloaded"=$Update.IsDownloaded}
                    $MissingUpdates += $UpdateObject
                }
            }
        }
        catch [Exception] {

        }
    }

    End {
        Write-Output $MissingUpdates
    }
}

$UpdateDurumu = Get-MissingWindowsUpdates | ConvertTo-Html -Fragment -PreContent "<h2>Windows Yapilamayan Guncellemeler</h2>"

#64 Bit Uygulama Listesi

Function Get-64BitSoftware {
    

    [CmdletBinding()]
    Param()

    Begin {}

    Process {
    $Result = Get-ChildItem -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" -ErrorAction SilentlyContinue | 
        Get-ItemProperty | 
        Where-Object {$_.DisplayName} | 
        Select-Object -Property @{Name="Name"; Expression={$_.DisplayName}},
            @{Name="Version";Expression={$_.DisplayVersion}},
            Publisher,
            #@{Name="Install Date"; Expression={ (Get-Date ($_.InstallDate.Substring(4,2) + "/" + $_.InstallDate.Substring(6,2) + "/" + $_.InstallDate.Substring(0, 4)) -Format FileDateUniversal).ToString()}},
            @{Name="Install Source";Expression={$_.InstallSource}},
            #@{Name="Install Location";Expression={$_.IntallLocation}},
            @{Name="Uninstall String";Expression={$_.UninstallString}}
    }

    End {
        Write-Output $Result
    }
}


$64BitUygulamalar = Get-64BitSoftware | ConvertTo-Html -Fragment -PreContent "<h2>64 Bit Uygulama Bilgileri</h2>"

#32 Bit Uygulama Listesi

Function Get-32BitSoftware {
   

    [CmdletBinding()]
    Param()

    Begin {}

    Process {
        $Result = Get-ChildItem -Path "HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" -ErrorAction SilentlyContinue | 
        Get-ItemProperty | 
        Where-Object {$_.DisplayName} | 
        Select-Object -Property @{Name="Name"; Expression={$_.DisplayName}},
            @{Name="Version";Expression={$_.DisplayVersion}},
            Publisher,
            #@{Name="Install Date"; Expression={ (Get-Date ($_.InstallDate.Substring(4,2) + "/" + $_.InstallDate.Substring(6,2) + "/" + $_.InstallDate.Substring(0, 4)) -Format FileDateUniversal).ToString()}},
            @{Name="Install Source";Expression={$_.InstallSource}},
            #@{Name="Install Location";Expression={$_.IntallLocation}},
            @{Name="Uninstall String";Expression={$_.UninstallString}}
    }

    End {
        Write-Output $Result
    }
}

$32BitUygulamalar = Get-32BitSoftware | ConvertTo-Html -Fragment -PreContent "<h2>32 Bit Uygulama Bilgileri</h2>"

Function Get-NetworkAdapters {
   
    [CmdletBinding()]
    Param()

    Begin {}

    Process {
        $Result = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | 
            Where-Object {$_.IPAddress -match '\S+'} | 
            Select-Object @{Name="DHCP Enabled"; Expression={$_.DHCPEnabled}},
                IPAddress,
                @{Name="Default Gateway"; Expression={$_.DefaultIPGateway}},
                @{Name="DNS Domain"; Expression={$_.DNSDomain}},
                Description,
                Index           
    }

    End {
        Write-Output $Result
    }
}

#Memory İstatistik Bilgisi
Function Get-MemoryStatistics {
    
    [CmdletBinding()]
    Param()

    Begin {}

    Process {
        $Result = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue | 
            Select-Object -Property @{Name="Total Physical Memory (MB)"; Expression={$_.TotalVisibleMemorySize/1MB}},
                @{Name="Free Physical Memory (MB)";Expression={$_.FreePhysicalMemory/1MB}},
                @{Name="Used Physical Memory (MB)";Expression={($_.TotalVisibleMemorySize - $_.FreePhysicalMemory)/1MB}},
                @{Name="Total Virtual Memory (MB)";Expression={$_.TotalVirtualMemorySize/1MB}},
                @{Name="Free Virtual Memory (MB)";Expression={$_.FreeVirtualMemory/1MB}},
                @{Name="Used Virtual Memory (MB)";Expression={($_.TotalVirtualMemorySize - $_.FreeVirtualMemory)/1MB}}
    }

    End {
        Write-Output $Result
    }
}


#$RamIstatistik = Get-MemoryStatistics |ConvertTo-Html -Fragment -PreContent "<h2>Ram Istatistik Bilgileri</h2>"

#İşletim Sistemi Genel Bilgiler
Function Get-OperatingSystem {
    
    [CmdletBinding()]
    Param()

    Begin {}

    Process {

        $Result = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction SilentlyContinue | 
            Select-Object -Property @{Name="Build Number";Expression={$_.BuildNumber}},
                @{Name="Name"; Expression={$_.Caption}},
                CurrentTimeZone,
                @{Name="Install Date"; Expression={(Get-Date($_.ConvertToDateTime($_.InstallDate)) -Format FileDateTimeUniversal).ToString()}},
                @{Name="Boot Time"; Expression={(Get-Date($_.ConvertToDateTime($_.LastBootUpTime)) -Format FileDateTimeUniversal).ToString()}},
                Manufacturer,
                @{Name="Architecture";Expression={$_.OSArchitecture}},
                @{Name="Serial Number";Expression={$_.SerialNumber}},
                @{Name="Service Pack";Expression={$_.ServicePackMajorVersion.ToString() + "." + $_.ServicePackMinorVersion.ToString()}},
                @{Name="System Device"; Expression={$_.SystemDevice}},
                @{Name="System Directory";Expression={$_.SystemDirectory}},
                @{Name="System Drive";Expression={$_.SystemDrive}},
                Version,
                @{Name="Windows Directory";Expression={$_.WindowsDirectory}} 
    }

    End {
        Write-Output $Result
    }
}


$IsletimSistemiGenelBilgi = Get-OperatingSystem |ConvertTo-Html -Fragment -PreContent "<h2>Isletim Sistemi Turu ve Versiyon Bilgisi</h2>"


#CPU Model ve Version Bilgisi
Function Get-CPU {
   

    [CmdletBinding()]
    Param()

    Begin {}

    Process {
        $Result = Get-WmiObject -Class Win32_Processor -ErrorAction SilentlyContinue | Select-Object -Property Name,ProcessorId,MaxClockSpeed,CurrentClockSpeed,NumberOfCores,DeviceID,CurrentVoltage,SocketDesignation,Status,ThreadCount,AddressWidth,DataWidth,Architecture       
    }

    End {
        Write-Output $Result
    }
}


#$CPUBilgisi = Get-CPU |ConvertTo-Html -Fragment -PreContent "<h2>Islemci Turu ve Versiyon Bilgisi</h2>"

#BIOS Sistem Bilgisi
Function Get-BIOSInformation {
    
    [CmdletBinding()]
    Param()

    Begin {}

    Process {
        $Result = Get-WmiObject -Class Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -Property "Name","SerialNumber","Version"
    }

    End {
        Write-Output $Result
    }
}

#$BiosBilgisi = Get-BIOSInformation |ConvertTo-Html -Fragment -PreContent "<h2>BIOS Bilgisi</h2>"


#Sistem Disk Bilgisi
Function Get-DiskInformation {
   
    [CmdletBinding()]
    Param()

    Begin {}

    Process {
        $Result = Get-WmiObject -Class Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction SilentlyContinue | Select-Object DeviceID,
            @{Name="Free Space (MB)";Expression={$_.FreeSpace/1MB}},
            @{Name="Size (MB)";Expression={$_.Size/1MB}}    
    }

    End {
        Write-Output $Result
    }
}


#$DiskBilgisi = Get-DiskInformation |ConvertTo-Html -Fragment -PreContent "<h2>Sistem Disk Bilgisi</h2>"

#Genel Asset Bilgileri
Function Get-ComputerSystemInformation {
   

    [CmdletBinding()]
    Param()

    Begin {}

    Process {
        $Result = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object Name,Domain,Manufacturer,Model
    }

    End {
        Write-Output $Result
    }
}

$SistemBilgileri = Get-ComputerSystemInformation |ConvertTo-Html -Fragment -PreContent "<h2>Cihaz ve Donanim Bilgisi</h2>"


 

        function Get-ChromeHistory {

            [CmdletBinding()]
            [OutputType([psobject])]

            param (

                [string]
                $UserName,

                [string]
                $SearchTerm,

                [string]
                $UrlRegex = '(htt(p|ps))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?',

                [string]
                $UserExpression = '$(Split-Path -Path $(Resolve-Path -Path "$_\..\..\..\..\..\..\..") -Leaf)'

            ) 

            begin {} 

            process {

                Resolve-Path -Path "$env:SystemDrive\Users\*\AppData\Local\Google\Chrome\User Data\Default\History" |

                Where-Object { $($UserExpression | Invoke-Expression) -match $UserName } |

                ForEach-Object {

                    $SourceFile = $_

                    $UserProfile = $($UserExpression | Invoke-Expression)

                    Get-Content -Path $SourceFile |

                    Select-String -Pattern $UrlRegex -AllMatches |

                    ForEach-Object { ($_.Matches).Value } |

                    Sort-Object -Unique |

                    ForEach-Object {

                        $EachUrl = $_

                        $DomainName = $EachUrl -replace 'http:\/\/','' -replace 'https:\/\/','' -replace '\/.*',''

                        New-Object -TypeName psobject -Property @{  UserName = $UserProfile
                                                                    Url = $_
                                                                    ComputerName = $env:COMPUTERNAME
                                                                    Browser = 'Chrome'
                                                                    DomainName = $DomainName }

                    } 

                } | Where-Object { $_.Url -match $SearchTerm }

            } 

            end {} 

        } 

        $TarayiciGecmisi= Get-ChromeHistory |ConvertTo-Html -Fragment -PreContent "<h2>Internet Gecmisi- Chrome</h2>"
      

#NETWORK İSTATİSTİKLERİ

#NETWORK BİLGİLERİ
    
$NetworkName ="<h1>Network Bilgileri: $env:networkname </h1>"
		
function Get-NetworkStatistics 
{ 
    $properties = 'Protocol','LocalAddress','LocalPort' 
    $properties += 'RemoteAddress','RemotePort','State','ProcessName','PID' 

    netstat -ano | Select-String -Pattern '\s+(TCP|UDP)' | ForEach-Object { 

        $item = $_.line.split(" ",[System.StringSplitOptions]::RemoveEmptyEntries) 

        if($item[1] -notmatch '^\[::') 
        {            
            if (($la = $item[1] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') 
            { 
               $localAddress = $la.IPAddressToString 
               $localPort = $item[1].split('\]:')[-1] 
            } 
            else 
            { 
                $localAddress = $item[1].split(':')[0] 
                $localPort = $item[1].split(':')[-1] 
            }  

            if (($ra = $item[2] -as [ipaddress]).AddressFamily -eq 'InterNetworkV6') 
            { 
               $remoteAddress = $ra.IPAddressToString 
               $remotePort = $item[2].split('\]:')[-1] 
            } 
            else 
            { 
               $remoteAddress = $item[2].split(':')[0] 
               $remotePort = $item[2].split(':')[-1] 
            }  

            New-Object PSObject -Property @{ 
                PID = $item[-1] 
                ProcessName = (Get-Process -Id $item[-1] -ErrorAction SilentlyContinue).Name 
                Protocol = $item[0] 
                LocalAddress = $localAddress 
                LocalPort = $localPort 
                RemoteAddress =$remoteAddress 
                RemotePort = $remotePort 
                State = if($item[0] -eq 'tcp') {$item[3]} else {$null} 
            } | Select-Object -Property $properties 
        } 
    } 
}


$NetworkIstatistikleri = Get-NetworkStatistics |ConvertTo-Html -Fragment -PreContent "<h2>Genel Network Istatistikleri</h2>"


$InterfaceKategori= Get-NetConnectionProfile | Select-Object Name, InterfaceAlias, NetworkCategory, IPV4Connectivity, IPv6Connectivity | ConvertTo-Html -Fragment -PreContent "<h2>Interface Kategori Durumu</h2>"
$ARPCacheDurumu  = Get-NetNeighbor | Select-Object State,InterfaceAlias,ipaddress,Store,AddressFamily,ifIndex,EnabledDefault,EnabledState,RequestedState |Where-Object {$_.AddressFamily -ne "IPv6"}  | ConvertTo-Html -fragment -PreContent "<h2>ARP Cache Durumu</h2>"

$RoutePath = Get-NetRoute | Select-Object InterfaceAlias, InterfaceIndex, RouteMetric  | ConvertTo-Html -fragment -PreContent "<h2>Route Path Durumu</h2>"

$Report = ConvertTo-HTML -Body "  $SistemAdi $SistemBilgileri $IsletimSistemiGenelBilgi $LocalGroupMember $LokalGrup $PowershellHistory  $GunlukKullaniciAktiviteleri $Antivirus $Downloads $StartupProgs $ZamanlanmisGorevler $SonDosyaOlusturmaIslemleri $WmiObject $SistemDiskKlasorleri $YukluProgramlar $WindowsUpdateDurum $UpdateDurumu  $SistemServisDurumu $TempDosyalari $BekleyenReboot $64BitUygulamalar $32BitUygulamalar $USBAygitDurum $USBGecmisi  $NetworkName $AgAdaptoru $InterfaceKategori $NetworkIstatistikleri $ARPCacheDurumu $RoutePath $DNSCacheBilgisi $TarayiciGecmisi" ` -Title "Computer Information" -Head $header -PostContent "<p>Creation Date: $(Get-Date)<p>"
$Report | Out-File C:\ForensicReport.html 

#$BiosBilgisi
#$DiskBilgisi
#$CPUBilgisi
#$RamIstatistik
#$SistemTCPPort
#$UDPPortDurum






