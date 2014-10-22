##############################################################################
##
## Send-File
##
## From Windows PowerShell Cookbook (O'Reilly)
## by Lee Holmes (http://www.leeholmes.com/guide)
##
##############################################################################

<#

.SYNOPSIS

Sends a file to a remote session.

.EXAMPLE

PS > $session = New-PsSession leeholmes1c23
PS > Send-File c:\temp\test.exe c:\temp\test.exe $session

#>

function Send-File {

    param(
        ## The path on the local computer
        [Parameter(Mandatory = $true)]
        $Source,

        ## The target path on the remote computer
        [Parameter(Mandatory = $true)]
        $Destination,

        ## The session that represents the remote computer
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.Runspaces.PSSession] $Session
    )

    Set-StrictMode -Version 3

    $remoteScript = {
        param($destination, $bytes)

        ## Convert the destination path to a full filesystem path (to support
        ## relative paths)
        $Destination = $executionContext.SessionState.`
            Path.GetUnresolvedProviderPathFromPSPath($Destination)

        ## Write the content to the new file
        $file = [IO.File]::Open($Destination, "OpenOrCreate")
        $null = $file.Seek(0, "End")
        $null = $file.Write($bytes, 0, $bytes.Length)
        $file.Close()
    }

    ## Get the source file, and then start reading its content
    $sourceFile = Get-Item $source

    ## Delete the previously-existing file if it exists
    Invoke-Command -Session $session {
        if(Test-Path $args[0]) { Remove-Item $args[0] }
    } -ArgumentList $Destination

    ## Now break it into chunks to stream
    Write-Verbose "Sending $Source"
    Write-Progress -Activity "Sending $Source" -Status "Preparing file"

    $streamSize = 1MB
    $position = 0
    $rawBytes = New-Object byte[] $streamSize
    $file = [IO.File]::OpenRead($sourceFile.FullName)

    while(($read = $file.Read($rawBytes, 0, $streamSize)) -gt 0)
    {
        Write-Progress -Activity "Writing $Destination" `
            -Status "Sending file" `
            -PercentComplete ($position / $sourceFile.Length * 100)

        ## Ensure that our array is the same size as what we read
        ## from disk
        if($read -ne $rawBytes.Length)
        {
            [Array]::Resize( [ref] $rawBytes, $read)
        }

        ## And send that array to the remote system
        Invoke-Command -Session $session $remoteScript `
            -ArgumentList $destination,$rawBytes

        ## Ensure that our array is the same size as what we read
        ## from disk
        if($rawBytes.Length -ne $streamSize)
        {
            [Array]::Resize( [ref] $rawBytes, $streamSize)
        }
    
        [GC]::Collect()
        $position += $read
    }

    $file.Close()
}

[hashtable]$script:DemoModuleState = @{}
[string]$script:DemoModuleStateDir = "{0}\AppData\DemoModule" -f $env:USERPROFILE
[string]$script:DemoModuleStatePath = "{0}\DemoModuleState.json" -f $script:DemoModuleStateDir

function ConvertTo-HashtableFromPsCustomObject { 
     param ( 
         [Parameter(  
             Position = 0,   
             Mandatory = $true,   
             ValueFromPipeline = $true,  
             ValueFromPipelineByPropertyName = $true  
         )] [object[]]$psCustomObject 
     )
     
     process { 
         foreach ($myPsObject in $psCustomObject) { 
             $output = @{}; 
             $myPsObject | Get-Member -MemberType *Property | % { 
                 $output.($_.name) = $myPsObject.($_.name); 
             } 
             $output;
         } 
     } 
} 

function Import-DemoModuleState {
    if (Test-Path $script:DemoModuleStatePath) {
        $json = (Get-Content $script:DemoModuleStatePath) -join "`n" | ConvertFrom-Json
        $script:DemoModuleState = ConvertTo-HashtableFromPsCustomObject $json
    }
}

function Export-DemoModuleState {
    if (!(Test-Path $script:DemoModuleStateDir)) {
        New-Item -Path $script:DemoModuleStateDir -ItemType Directory -Force > $null
    }
    $script:DemoModuleState | ConvertTo-Json > $script:DemoModuleStatePath
}

function New-DemoModuleState {
    Param (
        [Parameter(Mandatory=$true)][string]$Name,
        [string]$State,
        [string]$Deployment,
        [hashtable]$DeploymentData
    )
    if ($script:DemoModuleState.ContainsKey($Name.ToLower())) {
        throw "Demo $Name already exists"
    }
    $script:DemoModuleState.Add($Name.ToLower(),@{State=$state;Deployment=$deployment;DeploymentData=$DeploymentData})
    Export-DemoModuleState
}

function Update-DemoModuleState {
    Param (
        [Parameter(Mandatory=$true)][string]$Name,
        [string]$State
    )
    if (!$script:DemoModuleState.ContainsKey($Name.ToLower())) {
        throw "Demo $Name doesn't exist"
    }
    $script:DemoModuleState[$Name.ToLower()].State = $State
    Export-DemoModuleState
}

function Remove-DemoModuleState {
    Param (
        [Parameter(Mandatory=$true)][string]$Name
    )    
    $script:DemoModuleState.Remove($Name.ToLower())
    Export-DemoModuleState
}

function Find-DemoModule {
    Param (        [Parameter()][string]$Name    )    Process {        if (-not $Name.EndsWith("Demo")) {            $Name += "*demo"        }        Find-Module -Name $Name    }
}

function Get-DemoModule {
    Param (        [Parameter()][string]$Name    )    Process {        if (-not $Name.ToLower().EndsWith("demo")) {            $Name += "*demo"        }        if ($script:DemoModuleState.Count -eq 0) {            Import-DemoModuleState        }        Get-Module -ListAvailable | ? {$_.Name -like $Name} | % {             $modState = "Installed"            if ($script:DemoModuleState.ContainsKey($_.Name.ToLower())) {                $state = $script:DemoModuleState[$_.Name]                $modState = $state.state                $_ | Add-Member -MemberType NoteProperty -Name Deployment -Value $state.Deployment                $mod = Get-Module -ListAvailable $_.Name            }            $_.pstypenames.insert(0,"DemoModule")            $_ | Add-Member -MemberType NoteProperty -Name State -Value $modState            $_ | Add-Member -MemberType NoteProperty -Name DeploymentSupported -Value $mod.PrivateData.Deploy.Keys            $_        }    }
}

function Show-DemoDocument {
    Param (        [Parameter(Mandatory=$true)][string]$Name    )    Process {        $module = get-demomodule -Name $Name        if ($module) {            start $module.PrivateData.SlidesURI        }    }
}

function Show-DemoSlides {
    Param (        [Parameter(Mandatory=$true)][string]$Name    )    Process {        $module = get-demomodule -Name $Name        if ($module) {            start $module.PrivateData.SlidesURI        }    }
}

function Show-DemoWebsite {
    Param (        [Parameter(Mandatory=$true)][string]$Name    )    Process {        $module = get-demomodule -Name $Name        if ($module) {            start $module.PrivateData.WebURI        }    }
}

function Connect-DemoModule {
    Param (        [Parameter(Mandatory=$true)][string]$Name    )    if ($script:DemoModuleState.ContainsKey($Name.ToLower())) {
        $deploymentData = $script:DemoModuleState[$Name.ToLower()].DeploymentData
        $rdpPath = "{0}\AppData\DemoModule\{1}.rdp" -f $env:USERPROFILE,$Name
        $rdp = Get-AzureRemoteDesktopFile -ServiceName $deploymentData.ServiceName -Name $deploymentData.VMName -LocalPath $rdpPath
        Add-Content -Encoding Ascii -Path $rdpPath -Value "username:s:$($deploymentData.Administrator)"
        Add-Content -Encoding Ascii -Path $rdpPath -Value "password:s:$($deploymentData.Password)"
        [System.Windows.Forms.Clipboard]::SetText($deploymentData.Password)
        Write-Warning "Note that password has been copied to clipboard"
        Invoke-Item $rdpPath
    }
}

function Start-DemoModule {
    Param (        [Parameter(Mandatory=$true)][string]$Name,        [Parameter(Mandatory=$false)][string]$AzurePublishSettingsFile,        [Parameter(Mandatory=$false)][string]$Deploy="Azure"    )    Process {        $erroractionpreference = "Stop"

        if ($script:DemoModuleState.Count -eq 0) {
            Import-DemoModuleState
        }

        if ($script:DemoModuleState.ContainsKey($Name.ToLower())) {
            Connect-DemoModule $Name
            return
        }
        
        Write-Verbose "Checking dependencies"

        # check dependencies
        Write-Verbose "Checking if running as admin"
        $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()`
            ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        if (-not $IsAdmin) {
            Write-Error "Please rerun in an elevated PowerShell session"
            return
        }

        Write-Verbose "Checking if Azure PowerShell SDK is available"
        $m = Get-Module -ListAvailable Azure
        if (!$m) {
            Write-Warning "Azure PowerShell SDK is not currently installed"

            $title = "Download Azure PowerShell SDK"
            $message = "Do you want to download the Azure PowerShell SDK?"

            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
                "Open Web Browser"

            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
                "Manually install youself"

            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

            $result = $host.ui.PromptForChoice($title, $message, $options, 0) 

            switch ($result)
            {
                0 { 
                    Write-Warning "You'll need to open a new PowerShell window after installing the SDK for the module to work"
                    start "http://go.microsoft.com/?linkid=9811175&clcid=0x409" }
                1 { Write-Error "Please install the Azure PowerShell SDK manually and rerun this cmdlet"
                    return }
            }
        }
        ipmo Azure

        if ($AzurePublishSettingsFile -eq [string]::Empty) {
            Write-Warning "AzurePublishSettingsFile needs to be downloaded locally and passed as a parameter"
            $title = "Download Azure Publish Settings File"
            $message = "Do you want to download the Azure Publish Settings File?"

            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
                "Open Web Browser"

            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
                "Manually download youself"

            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

            $result = $host.ui.PromptForChoice($title, $message, $options, 0) 

            switch ($result)
            {
                0 { Get-AzurePublishSettingsFile; return }
                1 { Write-Error "Please manually download your AzurePublishSettingsFile and rerun this cmdlet"
                    return }
            }
        }

        Write-Verbose "Checking for xAzure DSC resource"
        $m = get-module -ListAvailable xAzure
        if (!$m) {
            Write-Warning "xAzure DSC Resource is not currently installed"

            $title = "Install xAzure DSC Resource"
            $message = "Do you want to install the xAzure DSC Resource?"

            $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", `
                "Install xAzure"

            $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", `
                "Manually install youself"

            $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)

            $result = $host.ui.PromptForChoice($title, $message, $options, 0) 

            switch ($result)
            {
                0 { Install-Module xAzure
                    Write-Warning "Stopping WMIPrvse (WMI Provider host) processes"
                    Stop-Process -Name wmiprvse -Force }
                1 { Write-Error "Please install the xAzure DSC Resource manually and rerun this cmdlet" 
                    return }
            }
        }

        [Reflection.Assembly]::LoadWithPartialName("System.Web") > $NULL        $defaultPassword = [System.Web.Security.Membership]::GeneratePassword(10,0)        $module = Get-DemoModule -Name $Name
        if ($module) {            $deployScript = $module.PrivateData.Deploy[$Deploy]
            if ($deployScript -eq $null) {
                Write-Error "Deployment option '$deploy' is not supported by this demo"
                return
            }
            Write-Verbose "Deploying to $deploy"
            $cmd = "{0}\{1}" -f $module.ModuleBase, $deployScript
            $instance = & $cmd -AzurePublishSettingsFile "$AzurePublishSettingsFile" -Password "$defaultPassword"
        } else {
            Write-Error "Demo module '$Name' not found"
        }

        Import-AzurePublishSettingsFile $AzurePublishSettingsFile
        New-DemoModuleState -Name $Name.ToLower() -State "Started" -Deployment $Deploy -DeploymentData @{Administrator=$instance.Admin;
            Password=$defaultPassword;
            ServiceName=$instance.ServiceName;
            VMName=$instance.Name}

        #wait on VM
        Write-Verbose "Waiting on VM to be in ready state"
        [int]$progress = 0
        while ($true) {
            $vm = Get-AzureVM -ServiceName $instance.ServiceName -Name $instance.Name
            Write-Progress -Activity "VM Status" -Status "$($vm.PowerState) : $($vm.Status)" -PercentComplete $progress
            # wait for reboot after WMF5 install
            if ($vm.Status -eq "ReadyRole") {
                Write-Progress -Activity "VM Status" -Completed
                break
            }
            Start-Sleep -Seconds 10
            $progress += $progress + 1
            if ($progress -gt 95) {
                $progress = 95
            }
        }

        Update-DemoModuleState -Name $Name -State "Provisioning"
        Write-Verbose "Waiting on demo specific provisioning of the VM to complete"
        #wait on reboot due to software install
        $winrmURI = $vm | Get-AzureWinRMUri
        $opt = New-CimSessionOption -UseSsl -SkipCACheck -SkipCNCheck -SkipRevocationCheck
        $passText = ConvertTo-SecureString $defaultPassword -AsPlainText -Force
        $cred = New-Object Management.Automation.PSCredential($instance.Admin,$passText)
        $sess = New-CimSession -ComputerName $winrmURI.Host -Port $winrmURI.Port -Authentication Negotiate -Credential $cred -SessionOption $opt
        $progress = 0
        while ($true) {
            Write-Progress -Activity "Software Install Status" -PercentComplete $progress
            $qfe = Get-CimInstance -CimSession $sess -Query "select * from Win32_QuickFixEngineering where HotFixID='KB2894868'"
            if ($qfe -ne $null) {
                Write-Progress -Activity "Software Install Status" -Completed
                break
            }
            Start-Sleep -Seconds 10
            $progress += $progress + 1
            if ($progress -gt 95) {
                $progress = 95
            }
        }

        Write-Verbose "Copying support files to VM"
        #copy demo files and manifest
        $opt = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
        $sess = New-PSSession -ComputerName $winrmURI.Host -Port $winrmURI.Port -Authentication Negotiate -Credential $cred -SessionOption $opt -UseSSL
        $demoFiles = $module.PrivateData.DemoFiles
        $userprofile = Invoke-Command -Session $sess -ScriptBlock {$env:USERPROFILE}
        foreach ($file in $demoFiles.Keys) {
            $demoFile = "{0}\demofiles\{1}.ps1" -f $module.ModuleBase, $file
            $dest = "{0}\{1}.ps1" -f $userprofile, $file
            Send-File -session $sess -Source $demoFile -Destination $dest
        }
        $dest = "{0}\module.psd1" -f $userprofile
        Send-File -Session $sess -Source $module.Path -Destination $dest

        $workingdir = split-path $myinvocation.mycommand.module.path

        $files = "DemoMenu.ps1","Format-Color.ps1","Start-DemoScript.ps1"
        foreach ($file in $files) {
            $dest = "{0}\{1}" -f $userprofile, $file
            $src = "{0}\{1}" -f $workingdir, $file
            Send-File -Session $sess -Source $src -Destination $dest
        }
        
        Update-DemoModuleState -Name $Name -State "Running"
        Connect-DemoModule $Name
    }
}

function Stop-DemooooModule {
    # clean-up Azure resources
    Param (        [Parameter(Mandatory=$true)][string]$Name    )

    Write-Verbose "Removing Azure resources associated to demo"
    if ($script:DemoModuleState.ContainsKey($Name.ToLower())) {
        $deploymentData = $script:DemoModuleState[$Name.ToLower()].DeploymentData
        $service = Get-AzureService -ServiceName $deploymentData.ServiceName
        $service | Remove-AzureService -Force
        Get-AzureDisk | ? { $_.AffinityGroup -eq $service.AffinityGroup } | Remove-AzureDisk
        Get-AzureStorageAccount | ? { $_.AffinityGroup -eq $service.AffinityGroup } | Remove-AzureStorageAccount
        Remove-DemoModuleState $Name
    }
}