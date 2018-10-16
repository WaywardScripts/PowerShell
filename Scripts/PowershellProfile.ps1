#region DefaultScriptFunctions
	function Is-Admin {  
		$user = [Security.Principal.WindowsIdentity]::GetCurrent();
		return (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
	}
	function Write-Log {
        [cmdletbinding(defaultparametersetname='info')]
		param(
			[Parameter(Mandatory,Position=0)]
                $Message,
			    $Path,
			    [switch] $NoDate,
            [Parameter(parametersetname='error')]
                [switch] $Error,
            [Parameter(parametersetname='info')]
                [switch] $Info,
            [Parameter(parametersetname='warn')]
                [switch] $Warning
		)
        $Message = $Message.ToString().split("`n").trim() -join "`n`t"
		if (-not $NoDate) {
			$Message = "$(get-date -format "G"): $Message"
		}
        #Default to writing the message to host
        $temp = $Message.split("`n").trim() -join " "
        $temp = $temp -split "\. " | ? {$_ -ne "" -or $_ -ne $null}
        $temp = $temp -join ".`n`t"
		Write-Verbose ("`n" + $temp.trim())
        if ($Path) {
            $global:LogPath = $Path
        }
        # If the parent directory of the LogPath doesn't exist, try to create it.
        if (-not (Test-Path (Split-Path $global:LogPath -Parent) -ErrorAction Stop)) {
            try {
                mkdir (Split-path $global:LogPath -Parent) | Out-Null
            } catch {
                $global:PSLog += $Message
                Write-Warning "Could not write to $global:LogPath. Ensure parent folder exists and you have proper permissions. Log available in `$global:PSLog"
                return
            }
        }
        Write-Verbose "Writing to: $global:LogPath"
        Add-Content -Path $global:LogPath -Value $Message
	}
#endregion

$defaultScriptRoot = '\\server\share$\Powershell\'
$defaultISEModules = @()
$defaultConsoleModules = @('PowerTab')
$defaultAliasNames = @(
    @('Notepad++','np'),
    @('Explorer++','ex')
)
$local:datetime = (Get-Date).ToString('yyyy.MM.dd.hh.mm.ss')
# If running interactively, make it a better experience.
if ([Environment]::UserInteractive) {
    $global:myDebug = $true
    $ScriptRoot = ''
    if (Test-Path $defaultScriptRoot) {
        $ScriptRoot = $defaultScriptRoot
    } elseif (Test-Path "$env:USERPROFILE\Documents\WindowsPowershell") {
        $ScriptRoot = "$env:USERPROFILE\Documents\WindowsPowershell"
    } else {
        try {
            mkdir "$env:USERPROFILE\Documents\WindowsPowershell" -ErrorAction stop | Out-Null
            $ScriptRoot = "$env:USERPROFILE\Documents\WindowsPowershell"
        } catch {
            Write-Warning "Permissions are awry... You do not have permissions to $env:USERPROFILE\Documents. Might want to get that looked at."
            $NoScriptRoot = $true
        }
    }
    if (-not $NoScriptRoot) {
        if (Test-Path "$ScriptRoot\Modules") {
            $env:PSModulePath = $env:PSModulePath + ";$(Join-Path $ScriptRoot 'Modules')"
        } else {
            try {
                mkdir "$ScriptRoot\Modules" -ErrorAction Stop | Out-Null
                $env:PSModulePath = $env:PSModulePath + ";$(Join-Path $ScriptRoot 'Modules')"
            } catch {
                Write-Warning "Unable to add $ScriptRoot\Modules to `$env:PSModulePath"
            }
        }
        cd $ScriptRoot
        if (Test-Path (Join-Path $ScriptRoot 'PowershellProfile.ps1')) {
            # Quick trick to do a full copy of objects. Isn't really
            # necessary for $profile, but should make it a habit.
            $oldProfile = $Profile | % {$_}
            $Profile = Join-Path $ScriptRoot 'PowershellProfile.ps1'
            $oldProfile | gm | ? {$_.MemberType -eq "NoteProperty"} | select -ExpandProperty Name | % {$Profile | Add-Member -MemberType NoteProperty -Name $_ -Value $oldProfile."$_" }
        }
    }
    # If running under powershell console (not ISE)
    if ($host.name -eq 'ConsoleHost') {
        foreach ($module in $defaultConsoleModules) {
	        Import-Module $module -ErrorAction Continue | Out-Null
        }
    # Else (running under ISE)
    } else {
        foreach ($module in $defaultISEModules) {
	        Import-Module $module -ErrorAction Continue | Out-Null
        }
    }
    # If the tools directory exists, then try setting the tools
    # NOTE: Will only set tools with a single EXE in the base folder.
    if (Test-Path .\Tools) {
        $tools = gci .\Tools -Directory
        foreach ($tool in $tools) {
            $alias = $defaultAliasNames | ? {$_[0] -match [Regex]::Escape($tool.basename)}
            $path = gci $tool.FullName -Filter "*.exe"
            if ($path.count -ne 1) {
                continue
            } else {
                Set-Alias $alias[1] $path.FullName
            }
        }
    }
    if (Test-Path (Join-Path $ScriptRoot "console.msc")) {
        Set-Alias mmc (Join-Path $ScriptRoot "console.msc")
    }
    function remote {
        param(
            [Parameter(Mandatory,Position=0)]
            [string]$ComputerName
        )
        Enter-PSSession -ComputerName $ComputerName
    }
    function prompt {
        if ((pwd).path -match "::") {
            ((pwd).path -split "::")[1] + ">"
        } else {
            (pwd).path + ">"
        }
        $time = (Get-Date).ToString("h:mm:ss tt")
        $domain = $env:USERDNSDOMAIN.split('.')[0]
        if (Is-Admin) {
            $WindowTitle = "[Administrator] $domain\$env:USERNAME` - $time"
        } else {
            $WindowTitle = "[Non-Administrator] $domain\$env:USERNAME` - $time"
        }
        $host.ui.RawUI.WindowTitle = $WindowTitle
    }
    #Set default log path to $defaultScriptRoot\Users\$env:username
    $AppName = "Users\$env:USERNAME"
} else {
    if (-not ($global:PSScriptInfo)) {
        $global:PSScriptInfo = (Get-PSCallStack)[1]
        $global:PSScriptInfo | Add-Member -MemberType NoteProperty -Name Error    -TypeName boolean -Value $false -Force
        $global:PSScriptInfo | Add-Member -MemberType NoteProperty -Name Warning  -TypeName boolean -Value $false -Force
        $global:PSScriptInfo | Add-Member -MemberType NoteProperty -Name Errors   -Value @() -Force
        $global:PSScriptInfo | Add-Member -MemberType NoteProperty -Name Warnings -Value @() -Force
    }
    #Set default log path to $defaultScriptRoot\[Scripts Parent Folder Name]
    $AppName = Split-path -Leaf $PSScriptRoot
}

if (-not (Test-Path "\\$defaultScriptRoot\Logs\$AppName")) {
    try {
        mkdir "\\$defaultScriptRoot\Logs\$AppName" -ErrorAction Stop | Out-Null
        $global:LogPath = "\\$defaultScriptRoot\Logs\$AppName"
    } catch {
        $global:LogPath = $env:TEMP
    }
    $global:LogPath = "$global:LogPath\PSLog-$datetime.log"
}

#Default Email Settings
$global:EmailSettings = @{
    To         = ''
    From       = 'AutoSender@domain.net'
    Subject    = 'PowerShell'
    SmtpServer = 'relay.domain.net'
    Body       = ''
    BodyAsHTML = $true
}
$global:EmailHeader =@"
    <style>
	    body { 
            font-family:Monospace;
            font-size:10pt;
        }
        td, th {
            border:0px solid black;
            border-collapse:collapse;
        }
        th {
            color:black;
            background-color: gray;
        }
        table, tr, td, th {
            padding:2px;
            margin:0px;
            white-space:pre;
        }
        tbody tr:nth-child(odd) {
            background-color: lightgray
        }
    </style>
"@

#Default Eventlog Details
$global:EventLogName = "Windows PowerShell"

#Set Transcript Path and Start logging
if (-not ($global:TranscriptPath)) {
    try {
        $TranscriptPath = Join-Path $ScriptRoot "Transcripts\$env:USERNAME\$env:COMPUTERNAME"
        if (-not (Test-Path $TranscriptPath)) {
            mkdir $TranscriptPath | Out-Null
        }
        $TranscriptPath = Join-Path $TranscriptPath "$datetime.log"
        Sleep -Seconds 1
    } catch {
        if (Test-Path "$env:USERPROFILE\Documents\") {
            $TranscriptPath = "$env:USERPROFILE\Documents\$datetime.log"
        } else {
            $TranscriptPath = "$env:TEMP\PowershellTranscript.$datetime.log"
        }
    }
    $global:TranscriptPath = $TranscriptPath
    Start-Transcript -Path $TranscriptPath | Out-Null
}
