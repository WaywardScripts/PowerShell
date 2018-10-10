#region DefaultScriptFunctions
	function Is-Admin {
		$user = [Security.Principal.WindowsIdentity]::GetCurrent();
		return (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
	}
    
    function Restore-FSPermissionsFromBackup {
        param(
            [Parameter(Mandatory)]
            [ValidateScript({ If (Test-Path $_) {$True} Else { Throw "`'$_`' doesn't exist!" } })]
                [string] $BackupLocation,
            [Parameter(Mandatory)]
            [ValidateScript({ If (Test-Path $_) {$True} Else { Throw "`'$_`' doesn't exist!" } })]
                [string] $RestoreLocation
        )
        $BackupLocation = Get-Item $BackupLocation | select -ExpandProperty FullName
        $RestoreLocation = Get-Item $RestoreLocation | select -ExpandProperty FullName
        try {
            $ACL = Get-ACL $BackupLocation -ErrorAction Stop -ErrorVariable 'global:Errors'
        } catch {
            throw "Unable to access $BackupLocation"
        }
        try {
            Set-ACL -Path $RestoreLocation -AclObject $ACL -ErrorAction Stop -ErrorVariable 'global:Errors'
        } catch {
            throw "Unable to access $RestoreLocation"
        }
        Get-ChildItem $BackupLocation -Recurse | % {
            $leafPath = ($_.FullName -split [Regex]::Escape($BackupLocation))[1]
            $RestorePath = Join-Path $RestoreLocation $leafPath
            try {
                $ACL = Get-ACL $_.FullName
                Set-Acl -Path $RestorePath -AclObject $ACL -ErrorVariable 'global:Errors'
                Write-Host ("Set: $RestorePath") -ForegroundColor Cyan
            } catch {
                Write-Warning "Unable to set permissions on $RestorePath" -WarningVariable 'global:Warnings'
            }
        }
        Write-Verbose "Checking Files..."
        Get-ChildItem $RestoreLocation -Recurse | % {
            $leafPath = ($_.FullName -split [Regex]::Escape($RestoreLocation))[1]
            $BackupPath = Join-Path $BackupLocation $leafPath
            if (-not (Test-Path $BackupPath)) {
                Write-Warning "'$leafPath' does not exist in $BackupLocation. Check permissions." -WarningVariable 'global:Warnings'
            }
        }
        Write-Verbose 'All warnings saved in $Warnings'
        Write-Verbose 'All errors saved in $Errors'
    }

function Write-Log {
	[cmdletbinding(defaultparametersetname='info')]
	param(
		[Parameter(Position=0,Mandatory)]
			[string[]] $Message,
		[Parameter(Position=1)]
		[ValidateScript({
			if ($_.Trim() -ne "") {
			    try {
				return (Test-Path (Split-Path $_ -Parent -ErrorAction Stop) -ErrorAction Stop)
			    } catch {
				throw "Unable to locate path '$_'"
			    }
			}
			return $false
		})]
			[string]   $Path,
			[switch]   $NoDate,
		[Parameter(parametersetname='error')]
			[switch]   $Error,
		[Parameter(parametersetname='info')]
			[switch]   $Info,
		[Parameter(parametersetname='warn')]
			[switch]   $Warning
	)
		if (-not $NoDate) {
			$Message = "$(get-date -format "G"): $Message"
		}
        if ($PSBoundParameters.ContainsKey('Verbose')) {
            $temp = $Message.split("`n").trim() -join " "
            $temp = $temp -split "\. " | ? {$_ -ne "" -or $_ -ne $null}
            $temp = $temp -join ".`n`t"
		    Write-Verbose ("`n" + $temp.trim())
        }
        if ($PSBoundParameters.ContainsKey('Path')) {
            $global:LogPath = $Path
        }
        if ($global:LogPath) {
            Write-Verbose "Writing to: $global:LogPath"
            Add-Content -Path $global:LogPath -Value $Message -ErrorAction Stop
        } else {
            Write-Warning 'No path specified or known. Log saved to $PSLog'
            $global:PSLog += $Message
        }
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
        cd $ScriptRoot
        if (Test-Path (Join-Path $ScriptRoot 'Modules')) {
            $env:PSModulePath = $env:PSModulePath + ";$(Join-Path $ScriptRoot 'Modules')"
        } else {
            try {
                mkdir "$ScriptRoot\Modules" -ErrorAction Stop | Out-Null
                $env:PSModulePath = $env:PSModulePath + ";$(Join-Path $ScriptRoot 'Modules')"
            } catch {}
        }
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
    if (Test-Path (Join-Path $ScriptRoot 'console.msc')) {
        Set-Alias mmc (Join-Path $ScriptRoot 'console.msc')
    }
    function rdp {
	    param(
		    [Parameter(Mandatory)]
                [string] $Server,
		        [switch] $Wait
	    )
	    if ($PSBoundParameters.ContainsKey('Wait')) {
		    Start-Process mstsc.exe -ArgumentList "/v:$server" -PassThru | Wait-Process
	    } else {
		    Start-Process mstsc.exe -ArgumentList "/v:$server"
	    }
    }
    function remote {
        param(
            [Parameter(Mandatory,Position=0)]
            [string]$ComputerName
        )
        Enter-PSSession -ComputerName $ComputerName
    }
    function prompt {
        switch ([IntPtr]::Size) {
            4 {$bitness = '(x32)'}
            8 {$bitness = '(x64)'}
        }
        $time = (Get-Date).ToString("h:mm:ss tt")
        $domain = $env:USERDNSDOMAIN.split('.')[0]
        if (Is-Admin) {
            $WindowTitle = "[Administrator] $domain\$env:USERNAME` - $time - $bitness"
        } else {
            $WindowTitle = "[Non-Administrator] $domain\$env:USERNAME` - $time - $bitness"
        }
        $host.ui.RawUI.WindowTitle = $WindowTitle
        if ($PSDebugContext) {
            $console = '[DBG]: '
        }
        if ((pwd).path -match "::") {
            $console = $console + ((pwd).path -split "::")[1] + ">"
        } else {
            $console = $console + (pwd).path + ">"
        }
        return $console
    }
    #Set default log path to $defaultScriptRoot\Users\$env:username
    $AppName = "Users\$env:USERNAME"
} else {
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
    From       = 'PowerShell@domain.net'
    Subject    = 'PowerShell'
    SmtpServer = ''
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
$global:EventLogName = 'Windows PowerShell'

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
        if (Test-Path (Join-Path $env:USERPROFILE 'Documents')) {
            $TranscriptPath = "$env:USERPROFILE\Documents\PowershellTranscript.$datetime.log"
        } else {
            $TranscriptPath = "$env:TEMP\PowershellTranscript.$datetime.log"
        }
    }
    $global:TranscriptPath = $TranscriptPath
    Start-Transcript -Path $TranscriptPath | Out-Null
}
