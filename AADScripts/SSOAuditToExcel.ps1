$tenant = Get-AzTenant
$tenantIdentifier = $tenant.DefaultDomain
$AuditContext = New-Object System.Collections.ArrayList

$AADAppServicePrincipals = Get-AzADServicePrincipal | Where-Object { $_.ServicePrincipalType -eq "Application" }

foreach ($AADAppServicePrincipal in $AADAppServicePrincipals) {

    $SSOMode = $AADAppServicePrincipal.PreferredSingleSignOnMode
    $appId = $AADAppServicePrincipal.AppId
    $displayName = $AADAppServicePrincipal.DisplayName
    $objectId = $AADAppServicePrincipal.Id
    $SingleSignOnEnabled = if ($SSOMode) { $true } else { $false }
    if (-not $SSOMode) {
        $AADApp = Get-AzADApplication -ApplicationId $appId
        if ($AADApp) {
            if ($AADApp.Spa.RedirectUri.Count -gt 0 -or $AADApp.Web.RedirectUri.Count -gt 0 -or $AADApp.PublicClient.RedirectUri.Count -gt 0) {
                $SSOMode = "OpenIDConnect"
                $SingleSignOnEnabled = $true
            } else {
                $SSOMode = "Disabled"
                $SingleSignOnEnabled = $false
            }
        } else {
            $SSOMode = "NA"
            $SingleSignOnEnabled = $false
        }
    }

    $AuditContext.Add([PSCustomObject]@{
        DisplayName = $displayName
        AppId = $appId
        ObjectId = $objectId
        SingleSignOnEnabled = $SingleSignOnEnabled
        SingleSignOnMode = $SSOMode
        Link = "https://portal.azure.com/#$tenantIdentifier/#view/Microsoft_AAD_IAM/ApplicationsMenuBlade/~/Overview/appId/" + $appId
    }) | Out-Null
}

$AuditContext | Export-Csv -Path "./sso_audit_metrics.csv" -NoTypeInformation