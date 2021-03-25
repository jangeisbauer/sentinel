# --------------------------------------------------------------------------------------------------------------
# Import AlertRules from e.g. GitHub in YAML format to Azure Sentinel 
# 
# start script by: . .\alertRuleFromGHToSentinel.ps1
# then use function: New-AzSentinelAlertRuleFromGitHub
# provide -resourceGroupName -workspaceName and -gitHubRawUrl (e.g.: "https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Detections/SecurityEvent/ExcessiveLogonFailures.yaml")
#
# Requirements: Az.SecurityInsights (Sentinel PS Module) & powershell-yaml module
# (Both will be automatically installed)
# 
# Author: @janvonkirchheim | Blog: emptyDC.com
# --------------------------------------------------------------------------------------------------------------

# Check if needed modules are installed if not install them
if (Get-Module -ListAvailable -Name Az.SecurityInsights) {
    Write-Host "Module Az.SecurityInsights exists"
} 
else {
    Write-Host "Module Az.SecurityInsights does not exist, installing it."
    install-module Az.SecurityInsights
}
if (Get-Module -ListAvailable -Name powershell-yaml) {
    Write-Host "Module powershell-yaml exists"
} 
else {
    Write-Host "Module powershell-yaml does not exist, installing it."
    install-module powershell-yaml
}
function New-AzSentinelAlertRuleFromGitHub {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$resourceGroupName,
        [Parameter(Mandatory=$true)][string]$workspaceName,
        [Parameter(Mandatory=$true)][string]$gitHubRawUrl,
        [Parameter(Mandatory=$false)][bool]$isGitHubDirectoryUrl = $false
    )

    # connect to Azure
    Connect-AzAccount

    if($isGitHubDirectoryUrl)
    {
        $gitDir = Invoke-WebRequest $gitHubRawUrl                                                                                               
        $gitRules = ($gitDir.Links.outerhtml | ?{$_ -like "*.yaml*"} | %{[regex]::match($_,'master.*yaml"').Value}).Replace('"',"") | %{if($_ -ne ""){"https://raw.githubusercontent.com/Azure/Azure-Sentinel/" + $_}}
        write-host "found those rules on the page:" -ForegroundColor Green
        $gitRules
        # write all alert rules from github dir to sentinel
        foreach($rawLink in $gitRules)
        {
            New-SingleAlertRuleFromGitHub -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName -gitHubRawUrl $rawLink
        }
    }
    else {
        # write alert rule to sentinel
        New-SingleAlertRuleFromGitHub -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName -gitHubRawUrl $gitHubRawUrl
    }
}

function New-SingleAlertRuleFromGitHub {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][string]$resourceGroupName,
        [Parameter(Mandatory=$true)][string]$workspaceName,
        [Parameter(Mandatory=$true)][string]$gitHubRawUrl
    )

    # connect to gitHub and read raw yaml
    $global:yaml= convertfrom-yaml (Invoke-RestMethod $gitHubRawUrl)
    Write-Host "GH-RAW-URL: " $gitHubRawUrl -ForegroundColor Yellow
    # convert compare parameters
    $global:compHT = @{}
    $compHT.add("gt","GreaterThan")
    $compHT.add("eq","Equal")
    $compHT.add("lt","LessThan")
    $compHT.add("ne","NotEqual")

    # create timespans for queryperiod and queryfrequency
    if($yaml.QueryPeriod.contains("d"))
    {
        $QueryPeriod = New-TimeSpan -days $yaml.QueryPeriod.replace("d","")
    }
    if($yaml.queryFrequency.contains("d"))
    {
        $QueryFrequency = New-TimeSpan -days $yaml.queryFrequency.replace("d","")
    }
    if($yaml.QueryPeriod.contains("h"))
    {
        $QueryPeriod = New-TimeSpan -hours $yaml.QueryPeriod.replace("h","")
    }
    if($yaml.queryFrequency.contains("h"))
    {
        $QueryFrequency = New-TimeSpan -hours $yaml.queryFrequency.replace("h","")
    }
    # lookup compare parameter
    $cp = $compHT[$yaml.TriggerOperator]
    New-AzSentinelAlertRule -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName -Scheduled -Enabled -description $yaml.description -DisplayName $yaml.name -Severity $yaml.Severity -Query $yaml.Query -QueryFrequency $QueryFrequency -QueryPeriod $QueryPeriod -TriggerThreshold $yaml.TriggerThreshold -TriggerOperator $cp
    $rDisplayName = $yaml.name
    Write-Output "Rule created:" $rDisplayName
}
