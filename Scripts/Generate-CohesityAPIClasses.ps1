function Get-PropertyNames {
    param(
        [Parameter(Mandatory,ValueFromPipeline)]
            $Property
    )
    $return = $property | gm | ? {$_.MemberType -eq 'NoteProperty'} | select -ExpandProperty name
    return $return
}

function Generate-CohesityClass {
    [CmdletBinding()]
    param(
        $Name,
        $Definition,
        $outputFile = ".\CohesityClasses.ps1"
    )
    if ((cat $outputFile -ErrorAction SilentlyContinue) -match "^class $Name \{$") {
        Write-Warning "$Name already exists!"
        continue
    }
    $properties = @($definition.properties | Get-PropertyNames | % {
        $definition.properties."$_" | `
            Add-Member -MemberType NoteProperty -Name Name -Value $_ -PassThru -Force
    })
    $propertyCode = Generate-CohesityClassProperties -Properties $properties
    if (0 -eq $propertyCode) {
        return 0
    }
    $constructor = @"
    $Name() {}
"@
    $output = @"
class $Name {
$propertyCode
$constructor
}
"@
    Write-Host "Generated $Name"
    $output | out-file $outputFile -Append
}

function Generate-CohesityClassProperties {
    [cmdletbinding()]
    param(
        [array] $Properties
    )
    $return = @()
    foreach ($property in $Properties) {
        $type = ''
        if ($property.enum) {
            ##
            # handle enums
            ##
        }
        switch ($property.type) {
            'array'  {
                switch ($property.items.type) {
                    'array'  {$type = 'array'}
                    'object' {
                        $type = $property.Name
                        if ($property.items.title -match "\(.*\)$") {
                            $type = ($property.items.title -split ".*\(")[1].trim(")")
                        } else {
                            throw "Cannot determine type for $($property.Name + " : " + $property)"
                        }
                    }
                    ''       {$type = ($property.items.'$ref' -split "definitions\/")[1]}
                    default  {
                        if ($property.type -eq 'integer') {
                            $type = 'int'
                        } elseif ($property.type -eq 'number') {
                            $type = 'int'
                        } else {
                            $type = $property.type
                        }
                    }
                }
                $type = "$type[]"
            }
            'object' {
                $breakpoint
                $type = $property.Name
                Generate-CohesityClass -Name $type -Definition $property
            }
            ''       {$type = ($property.'$ref' -split "definitions\/")[1]}
            default  {
                if ($property.type -eq 'integer') {
                    $type = 'int'
                } elseif ($property.type -eq 'number') {
                    $type = 'int'
                } else {
                    $type = $property.type
                }
            }
        }
        $return += "`t[$type] `$$($property.Name)"
    }
    return ($return -join "`n")
}

if (-not (Test-Path .\cohesity.json)) {
    Import-Module powershell-yaml -ErrorAction Stop
    Cohesity\Allow-BadSSLConnections
    Invoke-WebRequest -Uri 'http://cohesity.domain.net/docs/restApiDocs/browse/spec-files/cohesity_api.yaml' -OutFile '.\cohesity.yaml'
    # Convert to json because it's easier to handle than it is to 
    #  handle the key collections in YAML... and also because
    #  KeyCollections isn't naturaly enumerable. Can use
    #  .GetEnumerator() but it's still too much work.
    (cat '.\cohesity.yaml') -join "`n" | ConvertFrom-Yaml | ConvertTo-Yaml -JsonCompatible | Out-File .\cohesity.json
}

$json = (cat .\cohesity.json) -join "`n" | ConvertFrom-Json

$errorCount = 0
$ClassNames = $json.definitions | Get-PropertyNames
foreach ($ClassName in $ClassNames) {
    $return = Generate-CohesityClass -Name $ClassName -Definition $json.definitions."$ClassName"
    if ($return -eq 0) {
        $errorCount++
        Write-Warning $ClassName
    }
}
