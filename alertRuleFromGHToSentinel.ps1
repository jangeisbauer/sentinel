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
        $resourceGroupName,
        $workspaceName,
        $gitHubRawUrl
    )

    # connect to gitHub and read raw yaml
    $git = $gitHubRawUrl
    $yaml= convertfrom-yaml (Invoke-RestMethod $git)
    
    # convert compare parameters
    $compHT = @{}
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
    # connect to Azure
    Connect-AzAccount
    # write alert rule to sentinel
    New-AzSentinelAlertRule -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName -Scheduled -Enabled -description $yaml.description -DisplayName $yaml.name -Severity $yaml.Severity -Query $yaml.Query -QueryFrequency $QueryFrequency -QueryPeriod $QueryPeriod -TriggerThreshold $yaml.TriggerThreshold -TriggerOperator $cp
}
