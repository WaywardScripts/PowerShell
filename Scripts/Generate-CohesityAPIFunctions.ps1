#Last Update 2018/9/25
function Get-PropertyNames {
    param(
        [Parameter(Mandatory,ValueFromPipeline)]
            $Property
    )
    $return = $property | gm | ? {$_.MemberType -eq 'NoteProperty'} | select -ExpandProperty name
    return $return
}

function Get-ProperName {
    param(
        [Parameter(Mandatory,ValueFromPipeline)]
            [string[]] $Value
    )
    $value | % {$_ = $_[0].ToString().ToUpper() + ($_[1..$_.Length] -join "");Write-Output $_}
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

$URIs = $json.paths | Get-PropertyNames
$x = @()
foreach ($URI in $URIs) {
    $Noun = ($URI -split "public\/")[1].split('/') | % {Get-ProperName $_}
    if ($Noun -match "\{.*\}") {
        $HasURIInput = $true
        $URIParam = ($Noun -match "\{.*\}").trim('{').trim('}')
        $breakpoint
    }
    $Noun = ($Noun | ? {$_ -notmatch "\{.*\}"}) -join ""
    $Verbs = $json.paths.$URI | Get-PropertyNames | % {$_ | Get-ProperName}
    foreach ($Verb in $verbs) {
        $Parameters = @()
        foreach ($parameter in $json.paths.$URI.$Verb.parameters) {
            
            continue
            if ($parameter.name -ne 'body') {
                $type = ''
                switch ($parameter.type) {
                    '' {
                        $parameter.type
                        $breakpoint
                    }
                    'array' {
                        $parameter.items.type
                        $breakpoint
                        switch ($parameter.items.type) {
                            '' {
                            }
                            'array' {
                            }
                        }

                    }
                    default { $type = $parameter.type }
                }
            }
            continue
            $Parameters += New-ScriptParameter `
                -ParameterName ($parameter.name | Get-ProperName) `
                -Mandatory:$parameter.required `
                -HelpMessage $parameter.description `
                -Type 
        }
        continue
        New-ScriptFunction -Name "$Verb-$Noun"
    }
}
