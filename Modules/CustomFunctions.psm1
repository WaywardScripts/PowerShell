# #region Functions
<# Allow-BadSSLConnections
.Description
Forces SSL certificate validation request to be accepted. Useful for
connecting to domain machines that have not been registered with the CA.
.Notes
Author: WaywardScripts - 2018/4/25
#>
function Allow-BadSSLConnections {
	Set-Variable -Name ServicePointManagerCertificatePolicy -Value ([System.Net.ServicePointManager]::CertificatePolicy) -Description "Unmodified certificate policy." -Option ReadOnly
	$type = @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;

    namespace CustomPolicy
    {
        public class MyPolicy : ICertificatePolicy
        {
            //ServicePointManager.CertificatePolicy = new MyPolicy();
            public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem)
            {
                //Return True to force the certificate to be accepted.
                return true;
            }
        }
    }
"@
    Add-Type -TypeDefinition $type
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName CustomPolicy.MyPolicy
}
<# Backup-Permissions
.Description
Will backup all ACLs of every file/folder in the given path.
.Notes
Author: WaywardScripts - 2018/5/31
#>
function Backup-Permissions {
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$false,Position=0)][string]$Path,
		[Parameter(Mandatory=$true,ValueFromPipeline=$false,Position=1)][string]$OutputFile
    )
	if (Test-Path $OutputFile) {
		$response = Read-Host -Prompt (Write-Warning "The file $OutputFile already Exists!`n         Would you like to overwrite? [Y/N] (if you select no, all info will be appended)")
		if ($response -match "^y") {
			"" > $OutputFile
		} elseif ($response -match "^n") {
		} else {
			Write-Error "Invalid Response." 
			return
		}
	}
	Write-Warning "Backing up permissions. This make take a while..."
	"`"Path`",`"SDDL`"" | Out-File -FilePath $OutputFile
    gci $Path -Recurse | % {
		$sddl = (Get-acl $_.FullName).Sddl
        ("`"" + ($_.FullName) + "`",`"" + ($sddl) + "`"") | Out-File -FilePath $OutputFile -Append
	}
}
<# Compare-DirHash
Compare the files and hashes of two directories, one at a time. Useful
for checking for what's changed between two similar directories. Not
useful for completely different directories..hence only one for loop..
#>
function Compare-DirHash {
    param([Parameter(Mandatory=$true)]$dir1,[Parameter(Mandatory=$true)]$dir2)
    $filelist1 = gci -Path $dir1 -File -Recurse | sort FullName
    $filelist2 = gci -Path $dir2 -File -Recurse | sort FullName
    for ($i = 0 ; $i -lt $filelist1.count ; $i++) {
        Write-Host $("First  Directory :" + (Get-FileHash $filelist1[$i].FullName).hash)
        Write-Host $("Second Directory :" + (Get-FileHash $filelist2[$i].FullName).hash)
        pause
    }
}
<# Compress-DirectoryAndDelete
Use 7zip to compress the given directory and then delete it.
#>
function Compress-DirectoryAndDelete {
    param(
        [Parameter(Mandatory=$true)]
		[ValidateScript({(gci $path) -is [System.IO.DirectoryInfo]})]
            [string] $Path,
        [Parameter(Mandatory=$false)]
            [string[]] $ExcludeFileType,
        [Parameter(Mandatory=$false)]
            [int32] $Threads = 4,
		[Parameter(Mandatory=$true)]
			[string]$7ZipLocation
    )
    $Path = $Path.TrimEnd('\')
    if ($ExcludeFileType) {
        $ExcludeFileType = ($ExcludeFileType.split(',').trim() | % {"-xr!*.$_"})
        & '$7ZipLocation' a "$Path.7z" $Path @ExcludeFileType -mx9 -sni "-mmt$threads"
        Remove-Item -Path $Path -Recurse -Force
    } else {
        & '$7ZipLocation' a "$Path.7z" $Path -mx9 -sni "-mmt$threads"
        Remove-Item -Path $Path -Recurse -Force
    }
}
<#  ConvertFrom-Rtf
.Description
Converts RFT files to plaintext.
.Notes
Author: Can't remember. Found somewhere on the web.
#>
function ConvertFrom-Rtf {
	param(
		[Parameter(Mandatory=$true)][string]$Path
	)
    $Rtb = New-Object -TypeName System.Windows.Forms.RichTextBox
    $Rtb.Rtf = [System.IO.File]::ReadAllText($Path)
    $Rtb.Text
    Remove-Variable Rtb -ErrorAction SilentlyContinue
}
<#  Deserialize-Object
.Description
Expects a string that is the serialized representation of an object.
Converts this string back into an object
.Notes
Author: WaywardScripts - 2018/5/31
#>
function Deserialize-Object {
	param(
		[Parameter(Mandatory=$true)]
		[object]$Obj
	)
	[System.Management.Automation.PSSerializer]::Deserialize($obj)
}
<#  Disable-WinRM
.Description
Disables WinRM on a remote computer.
.Notes
Author: WaywardScripts - 2018/5/31
#>
function Disable-WinRM {
	param([string[]]$Servers)
	foreach ($server in $Servers) {
		Write-Host Disabling WinRM on $server...
		& $sysinternals\PsExec.exe \\$server PowerShell.exe -ExecutionPolicy bypass -Command Disable-PSRemoting -Force
	}
}
<# Disallow-BadSSLConnections
.Description
Reverses the affects of running Allow-BadSSLConnections.
.Notes
Author: WaywardScripts - 2018/4/25
#>
function Disallow-BadSSLConnections {
	if ($ServicePointManagerCertificatePolicy -ne $null) {
		[System.Net.ServicePointManager]::CertificatePolicy = $ServicePointManagerCertificatePolicy
	}
}
<# Enable-WinRM
.Description
Enables WinRM on a remote computer.
.Notes
Author: WaywardScripts - 2018/5/31
#>
function Enable-WinRM {
	param([parameter(ValueFromPipeline=$true,Mandatory=$true)][string[]]$Servers)
	foreach ($server in $Servers) {
		Write-Host Enabling WinRM on $server...
		& $sysinternals\PsExec.exe \\$server cmd /c winrm quickconfig
	}
}
<# Get-AllSubFiles
.Description
I don't recommend using this.
I made it to solve an issue I was having with "Get-ChildItem -Recurse" following sybolic links that lead to a 
parent directory. That causes a recursive loop that then errors out because the path becomes too long.
.Notes
Author: WaywardScripts - 2018/2
#>
function Get-AllSubFiles {
	param([Parameter(Mandatory=$true)]$path = ".\")
	gci $path -file
	gci $path -Attributes !ReparsePoint -Force -Directory -ErrorAction Stop | % {Get-AllSubFiles $_.FullName}
}

<# Get-DirHash
.Description
Get a hash that represents the state of all files in the given directory.
It uses the path of the file (relative to the given directory), the name,
and the byte data to generate a unique hash for that file. By default,
metadata does not affect the hash. i.e. Date Modified, Last Access Time,
etc., does not affect the hash. To include metadata in the hash
calculation, use the -Forensic switch.
.Notes
Author: WaywardScripts - 2018/2

!!Requires the following functions to use the -Forensic switch:
	- Get-FileMetaData
	- Serialize-Object
#>
function Get-DirHash {
    param(
        [ValidateScript({ If (Test-Path $_) {$true} Else { Throw "`'$_`' doesn't exist!" } })]
		[Parameter(Mandatory=$true)]$FolderPath,
		[string]$ExcludeFileTypes = "",
		[switch]$Forensic=$false
	)
	$folderpath = $folderpath.TrimEnd("\")
    $Folder = (Get-Item $FolderPath).FullName + "\"
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $endhash = New-Object byte[] 20
	try {
		$filelist = gci -Path $FolderPath -Attributes !ReparsePoint -File -Recurse 
	} catch [System.IO.IOException] {
		$filepath = $_.TargetObject
		$filepath | clip
		$errorMessage = "Hash cannot be accurately computed, there was a problem accessing some files. This is due to either file paths being too long or you do not have proper permissions to access all the files in the directory. The file path is shown below, and has been copied to the clipboard.`nFile Path: " + $filepath + "`n"
		Write-Error -exception $error[0].exception -Message $errorMessage
		return
	} catch {
		throw $error[0]
		return
	}
	$ExcludeFileTypes = $ExcludeFileTypes.split(',').Trim('.')
	$filelist = $filelist | ? { $excludefiletypes -notcontains $_.Extension.Trim('.')}
	Write-Host "File Count $($filelist.count) "
	Write-Host "Generating hash..."
	$starttime = [DateTime]::now
	$currenthash = [byte[]]
	$lasthash = [byte[]]
    foreach ($file in $filelist) {
        $name = ($file.FullName -split [regex]::Escape($Folder))[1]
        $name = [System.Text.Encoding]::UTF8.GetBytes($name)
        $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
		if ($Forensic) {
			$metadata = Get-FileMetaData -Path $file.fullname
			$metadata = Serialize-Object -Obj $metadata
			$metadatabytes = [System.Text.Encoding]::UTF8.GetBytes($metadata)
			
			$currenthash = $hasher.ComputeHash($bytes) + $metadatabytes
			$currenthash += $lasthash
			$lasthash = $hasher.ComputeHash($currenthash)
		} else {
			$currenthash = $hasher.ComputeHash($bytes)
			$currenthash += $lasthash
			$lasthash = $hasher.ComputeHash($currenthash)
		}
    }
	$endtime = [DateTime]::now
	$difference = $endtime - $starttime
	$average = $difference.totalseconds / [double]($filelist.count)
	Write-Host "Total time taken: $difference"
	Write-Host "Average time per file: $average seconds"
    return [System.Convert]::ToBase64String($lasthash)
}
<# Get-ExcelData
.Description
Effectively the same as 'Import-CSV' except it works with
Excel spreadsheets. You have to have office installed.
Well not really. Just the OLEDB files.
.Notes
Author: WaywardScripts - 2018/5/31
#>
function Get-ExcelData {
    [CmdletBinding(DefaultParameterSetName='Worksheet')]
    Param(
        [Parameter(Mandatory=$true, Position=0)]
			[String] $Path,
        [Parameter(Position=1, ParameterSetName='Worksheet')]
			[String] $WorksheetName = "",
        [Parameter(Position=1, ParameterSetName='Query')]
			[String] $Query = ""
    )
	if ($path -match ":") {
		$WorksheetName = $Path.split(':')[1]
		$Path = $Path.split(':')[0]
	}
    $Path = (Get-Item $path).FullName
    # Create the scriptblock to run in a job
    $JobCode = {
        Param($Path, $WorksheetName, $Query)
        # This is to avoid problems reading from files that are open.
		$newPath = $env:temp + "\" + (random).ToString()
		Copy-Item $Path $newPath
		$Path = $newPath
		$Provider = 'Microsoft.Jet.OLEDB.4.0'
		$ExtendedProperties = 'Excel 8.0;HDR=YES;IMEX=1'
        # Build the connection string and connection object
        $ConnectionString = 'Data Source={0};Extended Properties="{1}";Provider={2};Mode=Read' -f $Path,$ExtendedProperties,$Provider
        $Connection = New-Object System.Data.OleDb.OleDbConnection $ConnectionString
        try {
            # Open the connection to the file, and fill the datatable
            $Connection.Open()
            $TableNames = $connection.GetOleDbSchemaTable([System.Data.OleDb.OleDbSchemaGuid]::Tables,$null).TABLE_NAME
            if ($TableNames.count -gt 1) {
                if ($WorksheetName -eq "") {
                    Write-Warning "`nMultiple sheets found in excel file. Provide the name of the sheet you want to read from with 'Path:SheetName' or using -WorksheetName`nAvailable worksheets:`n`t$($TableNames -join `"`n`t`")"
                    return
                } else {
                    $table = $WorksheetName
                }
            } else {
                  $table = $TableNames          
            }
            $Query = "SELECT * FROM [$table]"
            $Adapter = New-Object -TypeName System.Data.OleDb.OleDbDataAdapter $Query, $Connection
            $temp = New-Object System.Data.DataTable
            $Adapter.Fill($temp) | Out-Null
            $temp | ConvertTo-Csv -NoTypeInformation | ConvertFrom-Csv
        } catch {
            # something went wrong
            Write-Error $_.Exception.Message
            Write-Warning "Query: $Query"
            Write-Warning "TableNames: $TableNames"
        } finally {
            # Close the connection
            if ($Connection.State -eq 'Open') {
                $Connection.Close()
            }
        }
        # Return the results as an array
        return ,$DataTable
    }
    # Run the code in a 32bit job, since the provider is 32bit only
    $job = Start-Job $JobCode -RunAs32 -ArgumentList $Path, $WorksheetName, $Query
    $job | Wait-Job | Receive-Job | Select-Object * -ExcludeProperty RunspaceId, PSSourceJobInstanceId,PSComputerName,PSShowComputer
    Remove-Job $job
}
<# Get-FileMetaData
.Description
Returns an object whose properties are the the file metadata that is passed into the function.
.Notes
Author: WaywardScripts - 2018/5/31
#>
function Get-FileMetaData {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Mandatory=$true)]
        [Alias('FullName', 'PSPath')]
        [string[]]$Path
    )
    begin {
        $oShell = New-Object -ComObject Shell.Application
    }
    process {
        $Path | ForEach-Object {
            if (Test-Path -Path $_ -PathType Leaf) {
				$FileItem = Get-Item -Path $_ -Force -ErrorAction Stop
                $oFolder = $oShell.Namespace($FileItem.DirectoryName)
                $oItem = $oFolder.ParseName($FileItem.Name)
 
                $props = @{}
 
                0..287 | ForEach-Object {
                    $ExtPropName = $oFolder.GetDetailsOf($oFolder.Items, $_)
                    $ExtValName = $oFolder.GetDetailsOf($oItem, $_)
               
                    if (-not $props.ContainsKey($ExtPropName) -and ($ExtPropName -ne '')) {
						$props.Add($ExtPropName, $ExtValName)
                    }
                }
                New-Object PSObject -Property $props
            }
        }
 
    } end {
        $oShell = $null
    }
}
<# Get-RemoteProcess
.Description
Gets the currently running process on a remote computer.
.Notes
Author: WaywardScripts - 2018/5/31
#>
function Get-RemoteProcess {
    param(
        [Parameter(ValueFromPipeline=$true,Mandatory=$true,Position=0)][string]$ComputerName,
		[Parameter(ValueFromPipeline=$true,Position=1)][string]$username = ".*"
    )
	$proclist = Get-CimInstance -ClassName win32_process -ComputerName $ComputerName
	$proclist | % {
		$owner = (Invoke-CimMethod -InputObject $_ -MethodName GetOwner)
		if ($owner.user -match "$username") {
			$owner = $owner.Domain + "\" + $owner.user
			$_ | Add-Member -MemberType NoteProperty -Name UserName -Value $owner -Force -PassThru
		}
	}
}
<# Get-SecurityReport
.Description
Gets an easy to understand security report, and outputs it to $OutputFile
.Notes
Author: WaywardScripts - 2017/11/30
#>
function Get-SecurityReport {
    ##
    # Function can be improved by changing to read (gci) items from
    # pipeline, rather than setting a variable. For future work...
    ##
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)][string]$Path,
		[Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=1)][string]$OutputFile,
        [switch]$File = $false,
        [switch]$Directory = $false
        #[switch]$Verbose
    )
    "`"FullPath`",`"InheritanceEnabled`",`"Permission`",`"Identity`"`n" >> $OutputFile
    Write-Host Gathering child items from $Path...
    if ($Directory -and -not $File) {
        Write-Host Gathering only directories...
        $dir = gci $Path -Recurse -Directory
    } elseif ($File -and -not $Directory) {
        Write-Host Gathering only files...
        $dir = gci $Path -Recurse -File
    } else {
        Write-Host Defaulting to gathering all files and directories...
        $dir = gci $Path -Recurse
    }
    $count = 0
    $errorCount = 0
    $errors = @()
    $dir | % {
        $count++
        $filename = $_.FullName
        $acl = Get-acl $filename
        $csv = "`"" + $filename + "`",`"" + ($acl.Access.isinherited -contains $true) + "`","
        $acl.Access | % {
            try {
                $csv += "`"" + $_.FileSystemRights.ToString() + "`",`"" + $_.IdentityReference.Value + "`"`n" + "`"`",`"`","
            } catch {
                $errorCount++
                $errors += $filename
            }
        }
        $csv = $csv.Substring(0,$csv.Length - 7)
        $csv | Out-File -FilePath $OutputFile -NoNewline
        if ($count%100 -eq 0 -and -not $verbose) {
            $count
        }
        if ($verbose) {
            $count + " / " + $dir.count + " : " + $_.FullName
        }
    }
    if ($errorCount -ne 0) {
        $out = (get-item $OutputFile).Directory.FullName + "\errors.txt"
        Write-Warning "There were $errorCount errors. The files that had issues are listed in $out"
        $errors -join "`n" | out-file -FilePath $out
    }
}
<# Is-Admin
.Description
Determines if the currently running user is running under and administrative context.
.Notes
Author: WaywardScripts - 2018/5/31
#>
function Is-Admin {  
	$user = [Security.Principal.WindowsIdentity]::GetCurrent();
	return (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
<# Serialize-Object
.Description
Takes an object, and returns a string that represents the object. Can be reversed with Deserialize-Object
.Notes
Author: WaywardScripts - 2018/5/31
#>
function Serialize-Object {
	param(
		[Parameter(Mandatory=$true)]
		[object]$Obj
	)
	[System.Management.Automation.PSSerializer]::Serialize($obj)
}
<# New-SymbolicLink
.Description
Creates a new symbolic link.
Target: $Path
Link Location: $SymName
#>
Function New-SymbolicLink {
    [cmdletbinding( DefaultParameterSetName = 'Directory', SupportsShouldProcess=$True )]
    Param (
		[parameter(Position=0,ParameterSetName='Directory',ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True,Mandatory=$True)]
		[parameter(Position=0,ParameterSetName='File',ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True,Mandatory=$True)]
		[ValidateScript({ If (Test-Path $_) {$True} Else { Throw "`'$_`' doesn't exist!" } })]
        [string]$Path,
		
        [parameter(Position=1,ParameterSetName='Directory')]
        [parameter(Position=1,ParameterSetName='File')]
        [string]$SymName,
		
        [parameter(Position=2,ParameterSetName='File')]
        [switch]$File,
		
        [parameter(Position=2,ParameterSetName='Directory')]
        [switch]$Directory
    )
    Begin {
        Try {
            $null = [mklink.symlink]
        } Catch {
            Add-Type @"
            using System;
            using System.Runtime.InteropServices;
 
            namespace mklink
            {
                public class symlink
                {
                    [DllImport("kernel32.dll")]
                    public static extern bool CreateSymbolicLink(string lpSymlinkFileName, string lpTargetFileName, int dwFlags);
                }
            }
"@
        }
    }
    Process {
        #Assume target Symlink is on current directory if not giving full path or UNC
        If ($SymName -notmatch "^(?:[a-z]:\\)|(?:\\\\\w+\\[a-z]\$)") {
            $SymName = "{0}\{1}" -f $pwd,$SymName
        }
        $Flag = @{
            File = 0
            Directory = 1
        }
        If ($PScmdlet.ShouldProcess($Path,'Create Symbolic Link')) {
            Try {
                $return = [mklink.symlink]::CreateSymbolicLink($SymName,$Path,$Flag[$PScmdlet.ParameterSetName])
                If ($return) {
                    $object = New-Object PSObject -Property @{
                        SymLink = $SymName
                        Target = $Path
                        Type = $PScmdlet.ParameterSetName
                    }
                    $object.pstypenames.insert(0,'System.File.SymbolicLink')
                    $object
                } Else {
                    Throw "Unable to create symbolic link!"
                }
            } Catch {
                Write-warning ("{0}: {1}" -f $path,$_.Exception.Message)
            }
        }
    }
 }
<# Purge-StoredCredentials
.Description
Clears all saved RDP credtials stored on the local machine.
.Notes
Author: WaywardScripts - 2018/5/31
#>
function Purge-StoredCredentials {
	(cmdkey /list | Select-String "target").Line | % {$_.split("=")[1]} | % {cmdkey /delete:$_}
}
<# rdp
.Description
Opens a remote desktop connection to the specified server.
.Notes
Author: WaywardScripts - 2018/5/28
#>
function rdp {
#####
# Will replace with Connect-Mstsc.ps1 when I can get around to implementing PoShKeepass
#####
	param(
		[Parameter(Mandatory=$true,Position=0)]$server,
		[switch]$wait = $false
	)
	if ($wait) {
		Start-Process mstsc.exe -ArgumentList "/v:$server" -PassThru | Wait-Process
	} else {
		Start-Process mstsc.exe -ArgumentList "/v:$server"
	}
}
<# Reload-Profile
.Description
Reloads the powershell profile. Useful for when you make changes to it, and are running as administrator.
So you don't have to exit and reload powershell.
.Notes
Author: WaywardScripts - 2018/5/31
#>
function Reload-Profile {
	& $profile.AllUsersAllHosts
}
<# Reset-FSInheritance
.Description
Resets the permissions on all child objects to inherit from its parent.
Useful for when files somehow get stripped of all their permissions.
.Notes
Author: WaywardScripts - 2018/5/31
#>
function Reset-FSInheritance {
    gci -Path .\ -Recurse | ? {$_.GetAccessControl().Access.Count -lt 5} | % {
		$acl = Get-acl $_.FullName
		$acl.SetAccessRuleProtection($true,$false)
		Set-Acl -Path $acl.Path -AclObject $acl
		$acl.SetAccessRuleProtection($false,$false)
		Set-Acl -Path $acl.Path -AclObject $acl
		"Changed " + $_.FullName
	}
}
<# Sign
.Description
Cryptographically signs the script that is passed in, with the current
running users certificate.
.Notes
Author: WaywardScripts - 2018/5/31
#>
function Sign {
	param([string]$Path)
	$cert = gci cert:\CurrentUser\My -CodeSigning
	Set-AuthenticodeSignature $path $cert -TimestampServer http://timestamp.verisign.com/scripts/timstamp.dll
}
<# Stop-RemoteProcess
.Description
Stops a process on a remote machine.
.Notes
Author: WaywardScripts - 2018/5/31
#>
function Stop-RemoteProcess {
    param(
        [Parameter(ValueFromPipeline=$true,Mandatory=$true)][CimInstance] $RemoteProcess
    )
    $RemoteProcess | Invoke-CimMethod $_ -MethodName Terminate
}
<# Test-IsNonInteractiveShell
.Description
Determines whether the current shell session is running as a
user interactive console, or not.
.Notes
Author: WaywardScripts - 2018/5/31
#>
function Test-IsNonInteractiveShell {
	##
	# Returns true if the current session is being ran in a non-interactive
	# console. Ex. Scheduled task runs script. This function is called, and
	# returns true. Will return false if a user has any ability to interact
	# with the console session. Good for any scripts that need to be ran in
	# user console (manually) and also that can run without user input.
	##
    if ([Environment]::UserInteractive) {
        foreach ($arg in [Environment]::GetCommandLineArgs()) {
            # Test each Arg for match of abbreviated '-NonInteractive' command.
            if ($arg -like '-NonI*') {
                return $true
            }
        }
    }
    return $false
}
<# To-UnixTime
.Description
Converts a passed in DateTime object to its equivalent representation
in Unix. If no object is passed in, it defaults to the current date and time.
.Notes
Author: WaywardScripts - 2018/5/31
#>
function To-UnixTime {
    param(
        [Parameter(Mandatory=$false)][DateTime]$date
    )
    if ($date) {
        [Math]::Floor([decimal](Get-Date($date).ToUniversalTime()-uformat "%s"))
    } else {
        [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))
    }
}
#endregion

#region Settings
function Matrix {
	$Host.UI.RawUI.BackgroundColor = "black"
	$Host.UI.RawUI.ForegroundColor = "green"
}
if (Is-Admin) {
	$host.ui.RawUI.WindowTitle = "[Administrator] $env:USERDOMAIN\$env:USERNAME"
} else {
	$host.ui.RawUI.WindowTitle = "[Non-Administrator] $env:USERDOMAIN\$env:USERNAME"
}
if (Test-Path 'C:\Program Files (x86)\Notepad++\notepad++.exe') {
	Set-Alias notepad 'C:\Program Files (x86)\Notepad++\notepad++.exe'
} elseif ('C:\Program Files\Notepad++\notepad++.exe') {
	Set-Alias notepad 'C:\Program Files\Notepad++\notepad++.exe'
} else {
	Write-Warning "Notepad++ executable not found."
}
if (Test-Path 'C:\Program Files (x86)\7-Zip\7z.exe') { 
	Set-Alias sz 'C:\Program Files (x86)\7-Zip\7z.exe'
} elseif (Test-Path 'C:\Program Files\7-Zip\7z.exe') {
	Set-Alias sz 'C:\Program Files\7-Zip\7z.exe'
} else {
	Write-Warning 7-Zip executable not found 
}
Set-Alias remote Enter-Pssession
#endregion
