function New-ScriptParameter {
    [CmdletBinding(DefaultParameterSetName='Manual')]
    param(
        [Parameter(Mandatory,ValueFromPipeline,ParameterSetName='OnTheFly',Position=1)]
            [System.Management.Automation.ParameterAttribute] $Parameter = $null,

        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='OnTheFly',Position=0)]
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='Manual',Position=0)]
            [string] $ParameterName,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='Manual',Position=1)]
            [string] $ParameterSetName = $null,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='Manual',Position=2)]
            [string[]] $Aliases = $null,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='Manual',Position=3)]
            [int] $Position = $null,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='Manual',Position=4)]
            [string] $HelpMessage = $null,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='Manual',Position=5)]
            [string] $Type,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='Manual',Position=6)]
            [switch] $Mandatory,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='Manual',Position=7)]
            [switch] $ValueFromPipeline,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='Manual',Position=8)]
            [switch] $ValueFromPipelineByPropertyName,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName,ParameterSetName='Manual',Position=9)]
            [switch] $ValueFromRemainingArguments
    )
    if ($Parameter) {
        New-ScriptParameter `
            -ParameterName $ParameterName `
            -ParameterSetName $Parameter.ParameterSetName `
            <#-Aliases is not a property of Management.Automation.ParameterAttribute#> `
            -Position $Parameter.Position `
            -HelpMessage $Parameter.HelpMessage `
            -Type $Parameter.TypeId `
            -Mandatory $Parameter.Mandatory `
            -ValueFromPipeline $Parameter.ValueFromPipeline `
            -ValueFromPipelineByPropertyName $Parameter.ValueFromPipelineByPropertyName `
            -ValueFromRemainingArguments $Parameter.ValueFromRemainingArguments
    } else {
        $hasParameterAttributes = $false
        $attributes = @()
        switch ($true) {
            $HelpMessage                     {$attributes += "HelpMessage='$HelpMessage'"}
            $Position                        {$attributes += "Position=$Position"}
            $Mandatory                       {$attributes += 'Mandatory=$true'}
            $ValueFromPipeline               {$attributes += 'ValueFromPipeline=$true'}
            $ValueFromPipelineByPropertyName {$attributes += 'ValueFromPipelineByPropertyName=$true'}
            $ValueFromRemainingArguments     {$attributes += 'ValueFromRemainingArguments=$true'}
            $ParameterSetName  {
                if ($ParameterName -is [Array] -or ($ParameterSetName -match ',')) {
                    $exception = [System.Exception]::new("Only one parameter set can be specified.")
                    Write-Error -Exception $exception
                    return
                }
                $attributes += "ParameterSetName='$ParameterSetName'"
            }
        }
        $attributes = $attributes -join ','
        if ("" -ne $attributes) {
            $attributes = @("[Parameter($attributes)]")
            $hasParameterAttributes = $true
        }
        if ($Aliases) {
            $a = @()
            $Aliases.split(',') | % {$a += '"$_"'}
            $a = $a -join ','
            $attributes += "[Alias($a)]"
            $hasParameterAttributes = $true
        }
        if ($Type) {
            $attributes += "[$Type]"
            $hasParameterAttributes = $true
        }
        if ($hasParameterAttributes) {
            $script = "`t" + ($attributes -join "`n") + "`n`t`t`$$ParameterName"
        } else {
            $script = "`t`$$ParameterName"   
        }
        return $script
    }
}
function New-ScriptFunction {
    param(
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=0)]
            [string] $Name,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName,Position=1)]
            [System.Management.Automation.ParameterAttribute[]] $Parameters,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName,Position=2)]
            [scriptblock] $Definition,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
            [type[]] $ReturnType,
        [Parameter(ValueFromPipeline,ValueFromPipelineByPropertyName)]
            [switch]$CmdletBinding
    )
    $internalScript = ""
    if ($CmdletBinding) {
        $internalScript += @"
    [CmdletBinding()]

"@
    }
    if ($ReturnType) {
        $ReturnType | % {
            $internalScript += @"
    [OutputType([$_])]

"@
        }
    }
    if ($Parameters) {
        $scriptParameters = $Parameters | % {New-ScriptParameter -Parameter $_}
        $scriptParameters = $scriptParameters -join ",`n"
        $internalScript += @"
    param(
$scriptParameters
    )

"@
    } else {
        $internalScript += @"
    param()

"@
    }
    $internalScript += @"
$Definition
"@
    $script = @"
function $Name {
$internalScript
}
"@
    return $script
}
function New-ParameterAttribute {
    param(
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=0)]
            [string] $ParameterName,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=1)]
            [string] $ParameterSetName = $null,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=2)]
            [string[]] $Aliases = $null,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=3)]
            [int32] $Position = $null,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=4)]
            [string] $HelpMessage = $null,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=5)]
            [string] $Type,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=6)]
            [switch] $Mandatory,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=7)]
            [switch] $ValueFromPipeline,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=8)]
            [switch] $ValueFromPipelineByPropertyName,
        [Parameter(Mandatory,ValueFromPipeline,ValueFromPipelineByPropertyName,Position=9)]
            [switch] $ValueFromRemainingArguments
    )
    $attribute = New-Object System.Management.Automation.ParameterAttribute
    $attribute.ParameterName = $ParameterName
    $attribute.ParameterSetName = $ParameterSetName
    $attribute.Position = $Position
    $attribute.HelpMessage = $HelpMessage
    $attribute.Type = $TypeId
    $attribute.Mandatory = $Mandatory
    $attribute.ValueFromPipeline = $ValueFromPipeline
    $attribute.ValueFromPipelineByPropertyName = $ValueFromPipelineByPropertyName
    $attribute.ValueFromRemainingArguments = $ValueFromRemainingArguments
    return $attribute
}
