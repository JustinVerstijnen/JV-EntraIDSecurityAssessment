<#
.SYNOPSIS
    Runs a read-only Microsoft Entra ID security assessment and generates a modern HTML report.

.DESCRIPTION
    This script reads Microsoft Entra ID objects through Microsoft Graph PowerShell authentication
    and Microsoft Graph REST calls. The report contains tabs for Users, Groups,
    Service Principals, Conditional Access Policies and Findings.

.NOTES
    Requirements: PowerShell 7+ is recommended and Microsoft.Graph.Authentication.
    The script is read-only. It does not modify Microsoft Entra ID.

    Example:
        .\JVEntraIDSecurityAssessment.ps1 -OutputPath .\JVEntraIDSecurityAssessment.html -OpenReport

    By default, this script uses classic browser sign-in through Microsoft.Graph.Authentication 2.33.0.
    v2.2: English report/UI, Findings tab moved to the end, Scan warnings tab removed, footer links to GitHub,
          non-informative unknown API permission placeholders are filtered, and higher-risk permissions are sorted first.
    v2.1: More robust user detail and service principal processing; fixed owner format-operator bug.
    v1.9: Graph GET helper parses raw JSON to PSCustomObject and uses ArrayList for paging to avoid type binding issues.
    v1.8: Graph GET helper uses HttpResponseMessage + raw JSON parsing to avoid SDK object conversion issues.
    v1.4: Removed invalid delegated scope AppRoleAssignment.Read.All; Application.Read.All is used for appRoleAssignments.
    If another Graph-auth assembly is already loaded in the current session, the script relaunches itself in a clean PowerShell session.
    This helps avoid WAM issues and requires no app registration or certificate in the customer tenant.

    Latest Graph auth module with WAM:
        .\JVEntraIDSecurityAssessment.ps1 -UseWamAuth -OpenReport

    App-only certificate authentication:
        .\JVEntraIDSecurityAssessment.ps1 -TenantId <tenant-id> -ClientId <app-id> -CertificateThumbprint <thumbprint> -OpenReport

    Device code sign-in:
        .\JVEntraIDSecurityAssessment.ps1 -UseDeviceCode -OpenReport
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path (Get-Location) ("JVEntraIDSecurityAssessment_{0}.html" -f (Get-Date -Format "yyyyMMdd_HHmmss"))),

    [string[]]$Scopes = @(
        "User.Read.All",
        "Group.Read.All",
        "Application.Read.All",
        "Directory.Read.All",
        "RoleManagement.Read.Directory",
        "Policy.Read.All",
        "DelegatedPermissionGrant.Read.All"
    ),

    [string]$TenantId,

    [string]$ClientId,

    [string]$CertificateThumbprint,

    [switch]$UseDeviceCode,

    [switch]$UseWamAuth,

    [switch]$UseLegacyGraphAuthModule,

    [switch]$SkipCAGroupMemberExpansion,

    [switch]$OpenReport,

    [int]$RequestDelayMs = 0,

    [string]$AccentColor = "#77B0DE"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$script:OriginalBoundParameters = @{} + $PSBoundParameters

$script:GraphBaseUri = "https://graph.microsoft.com/v1.0"
$script:ScanWarnings = New-Object System.Collections.ArrayList
$script:Findings = New-Object System.Collections.ArrayList

$script:UserById = @{}
$script:GroupById = @{}
$script:ServicePrincipalById = @{}
$script:RoleDefinitionById = @{}
$script:RoleDefinitionByTemplateId = @{}
$script:RoleAssignmentsByPrincipalId = @{}
$script:GroupMembersCache = @{}
$script:AllRoleAssignments = @()
$script:StopAfterCleanRelaunch = $false
$script:GraphRequestMode = $null

function Write-ScanLog {
    param(
        [Parameter(Mandatory)] [string]$Message,
        [ValidateSet("Info", "Warn", "Error", "Done")] [string]$Level = "Info"
    )

    $prefix = switch ($Level) {
        "Info"  { "[INFO]" }
        "Warn"  { "[WARN]" }
        "Error" { "[ERROR]" }
        "Done"  { "[DONE]" }
    }

    Write-Host "$prefix $Message"
}

function Add-ScanWarning {
    param(
        [Parameter(Mandatory)] [string]$Context,
        [Parameter(Mandatory)] [string]$Message
    )

    $script:ScanWarnings.Add([pscustomobject]@{
        Context = $Context
        Message = $Message
    }) | Out-Null
}

function Add-Finding {
    param(
        [ValidateSet("Info", "Low", "Medium", "High")] [string]$Severity,
        [Parameter(Mandatory)] [string]$Area,
        [Parameter(Mandatory)] [string]$ObjectName,
        [Parameter(Mandatory)] [string]$Detail
    )

    $script:Findings.Add([pscustomobject]@{
        Severity = $Severity
        Area = $Area
        ObjectName = $ObjectName
        Detail = $Detail
    }) | Out-Null
}

function Get-ObjectProperty {
    param(
        [AllowNull()] [object]$InputObject,
        [Parameter(Mandatory)] [string]$Name
    )

    if ($null -eq $InputObject) {
        return $null
    }

    # Invoke-MgGraphRequest kan afhankelijk van moduleversie hashtables,
    # dictionaries, PSCustomObjects, JsonElement-achtige objects of SDK response objects teruggeven.
    # Everything is intentionally wrapped in try/catch blocks so one unexpected output type does not break the entire scan.
    if ($InputObject -is [System.Collections.IDictionary]) {
        try {
            if ($InputObject.Contains($Name)) {
                return $InputObject[$Name]
            }
        }
        catch { }

        try {
            if ($InputObject.ContainsKey($Name)) {
                return $InputObject[$Name]
            }
        }
        catch { }

        try {
            foreach ($key in @($InputObject.Keys)) {
                if ([string]$key -eq $Name) {
                    return $InputObject[$key]
                }
            }
        }
        catch { }

        return $null
    }

    try {
        $property = $InputObject.PSObject.Properties | Where-Object { $_.Name -eq $Name } | Select-Object -First 1
        if ($null -ne $property) {
            return $property.Value
        }
    }
    catch { }

    try {
        return ($InputObject | Select-Object -ExpandProperty $Name -ErrorAction Stop)
    }
    catch { }

    return $null
}

function ConvertTo-SafeArray {
    param([AllowNull()] [object]$Value)

    if ($null -eq $Value) {
        return @()
    }

    if ($Value -is [string]) {
        if ([string]::IsNullOrWhiteSpace($Value)) {
            return @()
        }
        return @($Value)
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        return @($Value)
    }

    return @($Value)
}

function ConvertTo-HtmlEncodedText {
    param([AllowNull()] [object]$Value)

    if ($null -eq $Value) {
        return ""
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-JsonSafe {
    param([AllowNull()] [object]$Value)

    if ($null -eq $Value) {
        return ""
    }

    try {
        return ($Value | ConvertTo-Json -Depth 50)
    }
    catch {
        return [string]$Value
    }
}

function Get-FullGraphUri {
    param([Parameter(Mandatory)] [string]$Uri)

    if ($Uri -match "^https?://") {
        return $Uri
    }

    if ($Uri.StartsWith("/")) {
        return "$script:GraphBaseUri$Uri"
    }

    return "$script:GraphBaseUri/$Uri"
}

function ConvertFrom-JsonTextSafe {
    param([AllowNull()] [string]$JsonText)

    if ([string]::IsNullOrWhiteSpace($JsonText)) {
        return $null
    }

    # Bewust géén -AsHashtable: sommige PowerShell/Graph combinaties leveren daarna
    # dictionary-types op die bij property/indexer binding "Argument types do not match" geven.
    # PSCustomObject is hier voorspelbaarder, ook voor @odata.nextLink via PSObject.Properties.
    try {
        return ($JsonText | ConvertFrom-Json -Depth 100)
    }
    catch {
        return $JsonText
    }
}

function Convert-GraphResponse {
    param([AllowNull()] [object]$Response)

    if ($null -eq $Response) {
        return $null
    }

    # Meest robuuste pad: raw HTTP response uitlezen en zélf JSON parsen.
    # Daarmee vermijden we de objectconversie van Microsoft.Graph.Authentication,
    # die in sommige module-combinaties "Argument types do not match" kan geven.
    if ($Response -is [System.Net.Http.HttpResponseMessage]) {
        $statusCode = [int]$Response.StatusCode
        $rawBody = $null
        try {
            $rawBody = $Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        }
        catch {
            $rawBody = ""
        }

        if (-not $Response.IsSuccessStatusCode) {
            $bodyPreview = if ([string]::IsNullOrWhiteSpace($rawBody)) { "<geen response body>" } else { $rawBody }
            throw "Graph HTTP $statusCode $($Response.ReasonPhrase): $bodyPreview"
        }

        return (ConvertFrom-JsonTextSafe -JsonText $rawBody)
    }

    if ($Response -is [string]) {
        return (ConvertFrom-JsonTextSafe -JsonText $Response)
    }

    # Sommige moduleversies geven een wrapper met Content terug in plaats van een echte HttpResponseMessage.
    try {
        $contentProperty = $Response.PSObject.Properties | Where-Object { $_.Name -eq "Content" } | Select-Object -First 1
        if ($null -ne $contentProperty -and $null -ne $contentProperty.Value) {
            $content = $contentProperty.Value
            if ($content -is [string]) {
                return (ConvertFrom-JsonTextSafe -JsonText $content)
            }
            if ($content.PSObject.Methods.Name -contains "ReadAsStringAsync") {
                $rawBody = $content.ReadAsStringAsync().GetAwaiter().GetResult()
                return (ConvertFrom-JsonTextSafe -JsonText $rawBody)
            }
        }
    }
    catch { }

    return $Response
}

function Get-ExceptionText {
    param([Parameter(Mandatory)] [object]$ErrorRecord)

    $parts = New-Object System.Collections.ArrayList
    try { $parts.Add($ErrorRecord.Exception.Message) | Out-Null } catch { }
    try {
        if ($ErrorRecord.InvocationInfo -and $ErrorRecord.InvocationInfo.ScriptLineNumber) {
            $parts.Add(("line {0}" -f $ErrorRecord.InvocationInfo.ScriptLineNumber)) | Out-Null
        }
    }
    catch { }
    try {
        if ($ErrorRecord.Exception.GetType().FullName) {
            $parts.Add($ErrorRecord.Exception.GetType().FullName) | Out-Null
        }
    }
    catch { }
    try {
        if ($ErrorRecord.ScriptStackTrace) {
            $stackLine = (($ErrorRecord.ScriptStackTrace -split "`r?`n") | Select-Object -First 1)
            if (-not [string]::IsNullOrWhiteSpace($stackLine)) {
                $parts.Add($stackLine) | Out-Null
            }
        }
    }
    catch { }

    return ($parts -join " | ")
}

function Invoke-MgGraphRequestCompat {
    param([Parameter(Mandatory)] [string]$FullUri)

    $errors = New-Object System.Collections.ArrayList

    # HttpResponseMessage eerst. Dit geeft de meest voorspelbare response: raw HTTP + raw JSON.
    # JSON/default output is only attempted afterwards as fallback.
    $attempts = @(
        @{ Name = "HttpResponseStringUri"; Script = { param($u) Invoke-MgGraphRequest -Method GET -Uri $u -OutputType HttpResponseMessage -ErrorAction Stop } },
        @{ Name = "HttpResponseUriObject"; Script = { param($u) Invoke-MgGraphRequest -Method GET -Uri ([System.Uri]$u) -OutputType HttpResponseMessage -ErrorAction Stop } },
        @{ Name = "JsonStringUri";         Script = { param($u) Invoke-MgGraphRequest -Method GET -Uri $u -OutputType Json -ErrorAction Stop } },
        @{ Name = "JsonUriObject";         Script = { param($u) Invoke-MgGraphRequest -Method GET -Uri ([System.Uri]$u) -OutputType Json -ErrorAction Stop } },
        @{ Name = "DefaultStringUri";      Script = { param($u) Invoke-MgGraphRequest -Method GET -Uri $u -ErrorAction Stop } },
        @{ Name = "SplatStringUri";        Script = { param($u) $p = @{ Method = "GET"; Uri = $u; ErrorAction = "Stop" }; Invoke-MgGraphRequest @p } }
    )

    foreach ($attempt in $attempts) {
        try {
            $response = & $attempt.Script $FullUri
            $converted = Convert-GraphResponse -Response $response
            if (-not $script:GraphRequestMode) {
                $script:GraphRequestMode = $attempt.Name
                Write-ScanLog "Graph request mode selected: $($attempt.Name)." "Info"
            }
            return $converted
        }
        catch {
            $errors.Add(("{0}: {1}" -f $attempt.Name, (Get-ExceptionText -ErrorRecord $_))) | Out-Null
        }
    }

    throw ($errors -join " | ")
}

function Invoke-GraphGetRaw {
    param(
        [Parameter(Mandatory)] [string]$Uri,
        [int]$MaxRetry = 5
    )

    $fullUri = Get-FullGraphUri -Uri $Uri
    $attempt = 0

    while ($true) {
        try {
            return (Invoke-MgGraphRequestCompat -FullUri $fullUri)
        }
        catch {
            $attempt++
            $statusCode = $null
            try {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            catch {
                $statusCode = $null
            }

            if (($statusCode -in @(429, 500, 502, 503, 504)) -and ($attempt -le $MaxRetry)) {
                $sleepSeconds = [Math]::Min(60, [Math]::Pow(2, $attempt))
                Write-ScanLog "Graph throttling/temporary error on $fullUri. Retry in $sleepSeconds seconds." "Warn"
                Start-Sleep -Seconds $sleepSeconds
                continue
            }

            throw
        }
    }
}

function Invoke-GraphGetAll {
    param([Parameter(Mandatory)] [string]$Uri)

    # ArrayList i.p.v. Generic Lists: voorkomt generic method binding issues
    # met Graph/JSON objects in sommige PowerShell builds.
    $items = New-Object System.Collections.ArrayList
    $nextLink = Get-FullGraphUri -Uri $Uri

    while (-not [string]::IsNullOrWhiteSpace($nextLink)) {
        $response = Invoke-GraphGetRaw -Uri $nextLink
        $value = Get-ObjectProperty -InputObject $response -Name "value"

        if ($null -ne $value) {
            foreach ($item in @($value)) {
                [void]$items.Add($item)
            }
            $nextLinkValue = Get-ObjectProperty -InputObject $response -Name "@odata.nextLink"
            if ($null -eq $nextLinkValue) {
                $nextLink = $null
            }
            else {
                $nextLink = [string]$nextLinkValue
            }
        }
        else {
            [void]$items.Add($response)
            $nextLink = $null
        }

        if ($RequestDelayMs -gt 0) {
            Start-Sleep -Milliseconds $RequestDelayMs
        }
    }

    return @($items.ToArray())
}

function Invoke-GraphGetAllSafe {
    param(
        [Parameter(Mandatory)] [string]$Uri,
        [Parameter(Mandatory)] [string]$Context
    )

    try {
        return @(Invoke-GraphGetAll -Uri $Uri)
    }
    catch {
        $message = Get-ExceptionText -ErrorRecord $_
        Add-ScanWarning -Context $Context -Message $message
        Write-ScanLog "$Context could not be retrieved: $message" "Warn"
        return @()
    }
}

function Get-DirectoryObjectType {
    param([AllowNull()] [object]$Object)

    $type = Get-ObjectProperty -InputObject $Object -Name "@odata.type"
    if ([string]::IsNullOrWhiteSpace($type)) {
        return "directoryObject"
    }

    return ($type -replace "#microsoft.graph.", "")
}

function Get-UserLabel {
    param([AllowNull()] [object]$User)

    if ($null -eq $User) {
        return "Unknown user"
    }

    $displayName = Get-ObjectProperty -InputObject $User -Name "displayName"
    $upn = Get-ObjectProperty -InputObject $User -Name "userPrincipalName"
    $mail = Get-ObjectProperty -InputObject $User -Name "mail"
    $id = Get-ObjectProperty -InputObject $User -Name "id"

    if (-not [string]::IsNullOrWhiteSpace($displayName) -and -not [string]::IsNullOrWhiteSpace($upn)) {
        return "$displayName <$upn>"
    }

    if (-not [string]::IsNullOrWhiteSpace($displayName) -and -not [string]::IsNullOrWhiteSpace($mail)) {
        return "$displayName <$mail>"
    }

    if (-not [string]::IsNullOrWhiteSpace($displayName)) {
        return $displayName
    }

    if (-not [string]::IsNullOrWhiteSpace($upn)) {
        return $upn
    }

    if (-not [string]::IsNullOrWhiteSpace($id)) {
        return $id
    }

    return "Unknown user"
}

function Get-GroupLabel {
    param([AllowNull()] [object]$Group)

    if ($null -eq $Group) {
        return "Unknown group"
    }

    $displayName = Get-ObjectProperty -InputObject $Group -Name "displayName"
    $id = Get-ObjectProperty -InputObject $Group -Name "id"

    if (-not [string]::IsNullOrWhiteSpace($displayName)) {
        return $displayName
    }

    if (-not [string]::IsNullOrWhiteSpace($id)) {
        return $id
    }

    return "Unknown group"
}

function Get-ServicePrincipalLabel {
    param([AllowNull()] [object]$ServicePrincipal)

    if ($null -eq $ServicePrincipal) {
        return "Unknown service principal"
    }

    $displayName = Get-ObjectProperty -InputObject $ServicePrincipal -Name "displayName"
    $appId = Get-ObjectProperty -InputObject $ServicePrincipal -Name "appId"
    $id = Get-ObjectProperty -InputObject $ServicePrincipal -Name "id"

    if (-not [string]::IsNullOrWhiteSpace($displayName) -and -not [string]::IsNullOrWhiteSpace($appId)) {
        return "$displayName [$appId]"
    }

    if (-not [string]::IsNullOrWhiteSpace($displayName)) {
        return $displayName
    }

    if (-not [string]::IsNullOrWhiteSpace($id)) {
        return $id
    }

    return "Unknown service principal"
}

function Get-RoleName {
    param([AllowNull()] [string]$RoleDefinitionId)

    if ([string]::IsNullOrWhiteSpace($RoleDefinitionId)) {
        return "Unknown role"
    }

    if ($script:RoleDefinitionById.ContainsKey($RoleDefinitionId)) {
        $role = $script:RoleDefinitionById[$RoleDefinitionId]
        $displayName = Get-ObjectProperty -InputObject $role -Name "displayName"
        if (-not [string]::IsNullOrWhiteSpace($displayName)) {
            return $displayName
        }
    }

    if ($script:RoleDefinitionByTemplateId.ContainsKey($RoleDefinitionId)) {
        $role = $script:RoleDefinitionByTemplateId[$RoleDefinitionId]
        $displayName = Get-ObjectProperty -InputObject $role -Name "displayName"
        if (-not [string]::IsNullOrWhiteSpace($displayName)) {
            return $displayName
        }
    }

    return $RoleDefinitionId
}

function Get-RoleDefinitionFromAnyId {
    param([AllowNull()] [string]$RoleId)

    if ([string]::IsNullOrWhiteSpace($RoleId)) {
        return $null
    }

    if ($script:RoleDefinitionById.ContainsKey($RoleId)) {
        return $script:RoleDefinitionById[$RoleId]
    }

    if ($script:RoleDefinitionByTemplateId.ContainsKey($RoleId)) {
        return $script:RoleDefinitionByTemplateId[$RoleId]
    }

    return $null
}

function Get-PrincipalTypeById {
    param([AllowNull()] [string]$Id)

    if ([string]::IsNullOrWhiteSpace($Id)) {
        return "Unknown"
    }

    if ($script:UserById.ContainsKey($Id)) {
        return "User"
    }

    if ($script:GroupById.ContainsKey($Id)) {
        return "Group"
    }

    if ($script:ServicePrincipalById.ContainsKey($Id)) {
        return "ServicePrincipal"
    }

    return "Unknown"
}

function Get-PrincipalLabelById {
    param([AllowNull()] [string]$Id)

    if ([string]::IsNullOrWhiteSpace($Id)) {
        return "Unknown principal"
    }

    if ($script:UserById.ContainsKey($Id)) {
        return Get-UserLabel -User $script:UserById[$Id]
    }

    if ($script:GroupById.ContainsKey($Id)) {
        return Get-GroupLabel -Group $script:GroupById[$Id]
    }

    if ($script:ServicePrincipalById.ContainsKey($Id)) {
        return Get-ServicePrincipalLabel -ServicePrincipal $script:ServicePrincipalById[$Id]
    }

    return $Id
}

function Get-RoleAssignmentsForPrincipal {
    param([AllowNull()] [string]$PrincipalId)

    if ([string]::IsNullOrWhiteSpace($PrincipalId)) {
        return @()
    }

    if ($script:RoleAssignmentsByPrincipalId.ContainsKey($PrincipalId)) {
        return @(ConvertTo-SafeArray -Value $script:RoleAssignmentsByPrincipalId[$PrincipalId])
    }

    return @()
}

function Get-GroupMembersTransitiveUsers {
    param(
        [Parameter(Mandatory)] [string]$GroupId,
        [string]$Context = "Group members"
    )

    if ($script:GroupMembersCache.ContainsKey($GroupId)) {
        return @(ConvertTo-SafeArray -Value $script:GroupMembersCache[$GroupId])
    }

    $members = @(Invoke-GraphGetAllSafe -Uri "/groups/$GroupId/transitiveMembers/microsoft.graph.user?`$select=id,displayName,userPrincipalName,accountEnabled&`$top=999" -Context $Context)
    $script:GroupMembersCache[$GroupId] = $members
    return $members
}

function Resolve-UserIdsToLabels {
    param([AllowNull()] [object]$Ids)

    $labels = New-Object System.Collections.ArrayList

    foreach ($id in @(ConvertTo-SafeArray -Value $Ids)) {
        if ([string]::IsNullOrWhiteSpace([string]$id)) {
            continue
        }

        if ($id -in @("All", "None", "GuestsOrExternalUsers")) {
            $labels.Add("Special value: $id") | Out-Null
            continue
        }

        if ($script:UserById.ContainsKey([string]$id)) {
            $labels.Add((Get-UserLabel -User $script:UserById[[string]$id])) | Out-Null
        }
        else {
            $labels.Add("Unknown/deleted: $id") | Out-Null
        }
    }

    return @($labels)
}

function Resolve-GroupIdsToLabels {
    param([AllowNull()] [object]$Ids)

    $labels = New-Object System.Collections.ArrayList

    foreach ($id in @(ConvertTo-SafeArray -Value $Ids)) {
        if ([string]::IsNullOrWhiteSpace([string]$id)) {
            continue
        }

        if ($script:GroupById.ContainsKey([string]$id)) {
            $labels.Add((Get-GroupLabel -Group $script:GroupById[[string]$id])) | Out-Null
        }
        else {
            $labels.Add("Unknown/deleted: $id") | Out-Null
        }
    }

    return @($labels)
}

function Resolve-RoleIdsToLabels {
    param([AllowNull()] [object]$Ids)

    $labels = New-Object System.Collections.ArrayList

    foreach ($id in @(ConvertTo-SafeArray -Value $Ids)) {
        if ([string]::IsNullOrWhiteSpace([string]$id)) {
            continue
        }

        $labels.Add((Get-RoleName -RoleDefinitionId ([string]$id))) | Out-Null
    }

    return @($labels)
}

function New-HtmlList {
    param(
        [AllowNull()] [object]$Items,
        [string]$EmptyText = "None"
    )

    $cleanItems = @($Items | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($cleanItems.Count -eq 0) {
        return "<span class='muted'>$(ConvertTo-HtmlEncodedText $EmptyText)</span>"
    }

    $listItems = ($cleanItems | ForEach-Object { "<li>$(ConvertTo-HtmlEncodedText $_)</li>" }) -join ""
    return "<ul class='mini-list'>$listItems</ul>"
}

function New-HtmlDetailsList {
    param(
        [AllowNull()] [object]$Items,
        [string]$SummaryPrefix = "items",
        [string]$EmptyText = "None"
    )

    $cleanItems = @($Items | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($cleanItems.Count -eq 0) {
        return "<span class='muted'>$(ConvertTo-HtmlEncodedText $EmptyText)</span>"
    }

    $list = New-HtmlList -Items $cleanItems -EmptyText $EmptyText
    return "<details><summary>$($cleanItems.Count) $(ConvertTo-HtmlEncodedText $SummaryPrefix)</summary>$list</details>"
}

function New-Badge {
    param(
        [AllowNull()] [object]$Text,
        [string]$Class = ""
    )

    return "<span class='badge $Class'>$(ConvertTo-HtmlEncodedText $Text)</span>"
}

function New-BoolBadge {
    param([AllowNull()] [object]$Value)

    if ($Value -eq $true) {
        return New-Badge -Text "Yes" -Class "warn"
    }

    if ($Value -eq $false) {
        return New-Badge -Text "No" -Class "ok"
    }

    return New-Badge -Text "Unknown" -Class "neutral"
}

function New-TableRows {
    param(
        [AllowEmptyCollection()] [object[]]$Rows,
        [Parameter(Mandatory)] [string[]]$Columns
    )

    $htmlRows = New-Object System.Collections.ArrayList

    foreach ($row in $Rows) {
        $cells = New-Object System.Collections.ArrayList
        foreach ($column in $Columns) {
            $value = Get-ObjectProperty -InputObject $row -Name $column
            if ($null -eq $value) {
                $value = ""
            }
            $cells.Add("<td>$value</td>") | Out-Null
        }
        $htmlRows.Add(("<tr>{0}</tr>" -f ($cells -join ""))) | Out-Null
    }

    return ($htmlRows -join "`n")
}

function New-DataTableHtml {
    param(
        [Parameter(Mandatory)] [string]$Id,
        [Parameter(Mandatory)] [string]$Title,
        [AllowEmptyCollection()] [object[]]$Rows,
        [Parameter(Mandatory)] [string[]]$Columns,
        [Parameter(Mandatory)] [hashtable]$ColumnLabels
    )

    $headers = ($Columns | ForEach-Object { "<th>$(ConvertTo-HtmlEncodedText $ColumnLabels[$_])</th>" }) -join ""
    $tableRows = New-TableRows -Rows $Rows -Columns $Columns
    $count = @($Rows).Count

    if ($count -eq 0) {
        $colSpan = @($Columns).Count
        $tableRows = "<tr><td colspan='$colSpan'><span class='muted'>No objects found or insufficient permissions.</span></td></tr>"
    }

    return @"
<div class="table-card">
    <div class="table-card-header">
        <div>
            <h2>$([System.Net.WebUtility]::HtmlEncode($Title))</h2>
            <p>$count objects</p>
        </div>
        <input class="table-search" type="search" placeholder="Search..." oninput="filterTable('$Id', this.value)" />
    </div>
    <div class="table-wrap">
        <table id="$Id">
            <thead><tr>$headers</tr></thead>
            <tbody>
$tableRows
            </tbody>
        </table>
    </div>
</div>
"@
}

function Resolve-ApplicationPermissionLabel {
    param([AllowNull()] [object]$AppRoleAssignment)

    $resourceId = Get-ObjectProperty -InputObject $AppRoleAssignment -Name "resourceId"
    $resourceDisplayName = Get-ObjectProperty -InputObject $AppRoleAssignment -Name "resourceDisplayName"
    $appRoleId = Get-ObjectProperty -InputObject $AppRoleAssignment -Name "appRoleId"

    $permissionName = $null
    if (-not [string]::IsNullOrWhiteSpace($resourceId) -and $script:ServicePrincipalById.ContainsKey([string]$resourceId)) {
        $resourceSp = $script:ServicePrincipalById[[string]$resourceId]
        $appRoles = ConvertTo-SafeArray -Value (Get-ObjectProperty -InputObject $resourceSp -Name "appRoles")
        foreach ($role in $appRoles) {
            $roleId = Get-ObjectProperty -InputObject $role -Name "id"
            if ([string]$roleId -eq [string]$appRoleId) {
                $permissionName = Get-ObjectProperty -InputObject $role -Name "value"
                if ([string]::IsNullOrWhiteSpace($permissionName)) {
                    $permissionName = Get-ObjectProperty -InputObject $role -Name "displayName"
                }
                break
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($permissionName)) {
        $permissionName = $appRoleId
    }

    if ([string]::IsNullOrWhiteSpace($resourceDisplayName) -and -not [string]::IsNullOrWhiteSpace($resourceId) -and $script:ServicePrincipalById.ContainsKey([string]$resourceId)) {
        $resourceDisplayName = Get-ObjectProperty -InputObject $script:ServicePrincipalById[[string]$resourceId] -Name "displayName"
    }

    if ([string]::IsNullOrWhiteSpace($resourceDisplayName)) {
        $resourceDisplayName = "Unknown API"
    }

    if ([string]::IsNullOrWhiteSpace($permissionName)) {
        return $null
    }

    return "$resourceDisplayName :: $permissionName"
}

function Resolve-DelegatedPermissionLabels {
    param([AllowNull()] [object]$Oauth2PermissionGrants)

    $labels = New-Object System.Collections.ArrayList

    foreach ($grant in @(ConvertTo-SafeArray -Value $Oauth2PermissionGrants)) {
        $resourceId = Get-ObjectProperty -InputObject $grant -Name "resourceId"
        $scope = Get-ObjectProperty -InputObject $grant -Name "scope"
        $consentType = Get-ObjectProperty -InputObject $grant -Name "consentType"
        $principalId = Get-ObjectProperty -InputObject $grant -Name "principalId"

        if ([string]::IsNullOrWhiteSpace($scope)) {
            continue
        }

        $resourceName = "Unknown API"
        if (-not [string]::IsNullOrWhiteSpace($resourceId) -and $script:ServicePrincipalById.ContainsKey([string]$resourceId)) {
            $resourceName = Get-ObjectProperty -InputObject $script:ServicePrincipalById[[string]$resourceId] -Name "displayName"
        }

        $subject = $consentType
        if ($consentType -eq "Principal" -and -not [string]::IsNullOrWhiteSpace($principalId)) {
            $subject = "Principal: $(Get-PrincipalLabelById -Id $principalId)"
        }

        foreach ($scopeName in @($scope -split " " | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
            $labels.Add("$resourceName :: $scopeName ($subject)") | Out-Null
        }
    }

    return @($labels)
}

function Test-EmptyPermissionLabel {
    param([AllowNull()] [object]$PermissionLabel)

    if ($null -eq $PermissionLabel) {
        return $true
    }

    $label = ([string]$PermissionLabel).Trim()
    if ([string]::IsNullOrWhiteSpace($label)) {
        return $true
    }

    # Some tenants/resources return an appRoleAssignment placeholder without a resolvable API or permission value.
    # These do not add actionable permission information to the report.
    if ($label -match '^Unknown API\s*::\s*$') {
        return $true
    }

    if ($label -match '^Unknown API\s*::\s*00000000-0000-0000-0000-000000000000\s*$') {
        return $true
    }

    return $false
}

function Get-PermissionRiskWeight {
    param([AllowNull()] [object]$PermissionLabel)

    if ($null -eq $PermissionLabel) {
        return 0
    }

    $permission = [string]$PermissionLabel

    # [Inference] This is a pragmatic display ordering, not a formal risk score.
    # Broad write/admin permissions are shown first, broad read permissions second, then everything else.
    if ($permission -match '(?i)(RoleManagement\.ReadWrite|Directory\.ReadWrite|AppRoleAssignment\.ReadWrite|Application\.ReadWrite\.All|Policy\.ReadWrite\.ConditionalAccess|PrivilegedAccess\.ReadWrite|User\.ReadWrite\.All|Group\.ReadWrite\.All|GroupMember\.ReadWrite|DeviceManagement.*ReadWrite|Sites\.FullControl|FullControl|\.ReadWrite\.All|Mail\.ReadWrite|Mail\.Send|Files\.ReadWrite\.All|Calendars\.ReadWrite|MailboxSettings\.ReadWrite|Exchange\.ManageAsApp)') {
        return 100
    }

    if ($permission -match '(?i)(\.Read\.All|Directory\.Read\.All|User\.Read\.All|Group\.Read\.All|Application\.Read\.All|AuditLog\.Read\.All|Reports\.Read\.All|Policy\.Read\.All|SecurityEvents\.Read\.All|Mail\.Read|Files\.Read\.All|Sites\.Read\.All)') {
        return 60
    }

    return 10
}

function Sort-PermissionLabels {
    param([AllowNull()] [object]$PermissionLabels)

    $clean = New-Object System.Collections.ArrayList
    foreach ($label in @(ConvertTo-SafeArray -Value $PermissionLabels)) {
        if (Test-EmptyPermissionLabel -PermissionLabel $label) {
            continue
        }
        [void]$clean.Add([string]$label)
    }

    return @($clean | Sort-Object @{ Expression = { Get-PermissionRiskWeight -PermissionLabel $_ }; Descending = $true }, @{ Expression = { $_ }; Ascending = $true } -Unique)
}

function Get-ConditionalAccessExpandedExcludedUsers {
    param(
        [AllowNull()] [object]$ExcludeUsers,
        [AllowNull()] [object]$ExcludeGroups,
        [AllowNull()] [object]$ExcludeRoles,
        [Parameter(Mandatory)] [string]$PolicyName
    )

    $excluded = @{}

    foreach ($userId in @(ConvertTo-SafeArray -Value $ExcludeUsers)) {
        if ([string]::IsNullOrWhiteSpace([string]$userId)) {
            continue
        }

        if ($userId -in @("All", "None", "GuestsOrExternalUsers")) {
            continue
        }

        if ($script:UserById.ContainsKey([string]$userId)) {
            $excluded[[string]$userId] = [pscustomobject]@{
                User = $script:UserById[[string]$userId]
                Sources = New-Object System.Collections.ArrayList
            }
            $excluded[[string]$userId].Sources.Add("Direct user exclusion") | Out-Null
        }
        else {
            Add-ScanWarning -Context "Conditional Access: $PolicyName" -Message "Excluded user ID not found: $userId"
        }
    }

    if (-not $SkipCAGroupMemberExpansion) {
        foreach ($groupId in @(ConvertTo-SafeArray -Value $ExcludeGroups)) {
            if ([string]::IsNullOrWhiteSpace([string]$groupId)) {
                continue
            }

            $groupName = $groupId
            if ($script:GroupById.ContainsKey([string]$groupId)) {
                $groupName = Get-GroupLabel -Group $script:GroupById[[string]$groupId]
            }

            $members = @(Get-GroupMembersTransitiveUsers -GroupId ([string]$groupId) -Context "Conditional Access '$PolicyName' excluded group '$groupName'")
            foreach ($member in $members) {
                $memberId = Get-ObjectProperty -InputObject $member -Name "id"
                if ([string]::IsNullOrWhiteSpace($memberId)) {
                    continue
                }

                if (-not $excluded.ContainsKey([string]$memberId)) {
                    $excluded[[string]$memberId] = [pscustomobject]@{
                        User = $member
                        Sources = New-Object System.Collections.ArrayList
                    }
                }
                $excluded[[string]$memberId].Sources.Add("Group: $groupName") | Out-Null
            }
        }
    }

    foreach ($roleId in @(ConvertTo-SafeArray -Value $ExcludeRoles)) {
        if ([string]::IsNullOrWhiteSpace([string]$roleId)) {
            continue
        }

        $roleDefinition = Get-RoleDefinitionFromAnyId -RoleId ([string]$roleId)
        if ($null -eq $roleDefinition) {
            Add-ScanWarning -Context "Conditional Access: $PolicyName" -Message "Excluded role ID could not be mapped to a role definition: $roleId"
            continue
        }

        $resolvedRoleId = Get-ObjectProperty -InputObject $roleDefinition -Name "id"
        $roleName = Get-ObjectProperty -InputObject $roleDefinition -Name "displayName"
        $matchingAssignments = @($script:AllRoleAssignments | Where-Object { [string](Get-ObjectProperty -InputObject $_ -Name "roleDefinitionId") -eq [string]$resolvedRoleId })

        foreach ($assignment in $matchingAssignments) {
            $principalId = Get-ObjectProperty -InputObject $assignment -Name "principalId"
            $principalType = Get-PrincipalTypeById -Id $principalId

            if ($principalType -eq "User") {
                if (-not $excluded.ContainsKey([string]$principalId)) {
                    $excluded[[string]$principalId] = [pscustomobject]@{
                        User = $script:UserById[[string]$principalId]
                        Sources = New-Object System.Collections.ArrayList
                    }
                }
                $excluded[[string]$principalId].Sources.Add("Directory role: $roleName") | Out-Null
            }
            elseif ($principalType -eq "Group" -and -not $SkipCAGroupMemberExpansion) {
                $groupName = Get-PrincipalLabelById -Id $principalId
                $members = @(Get-GroupMembersTransitiveUsers -GroupId ([string]$principalId) -Context "Conditional Access '$PolicyName' excluded role group '$groupName'")
                foreach ($member in $members) {
                    $memberId = Get-ObjectProperty -InputObject $member -Name "id"
                    if ([string]::IsNullOrWhiteSpace($memberId)) {
                        continue
                    }

                    if (-not $excluded.ContainsKey([string]$memberId)) {
                        $excluded[[string]$memberId] = [pscustomobject]@{
                            User = $member
                            Sources = New-Object System.Collections.ArrayList
                        }
                    }
                    $excluded[[string]$memberId].Sources.Add("Directory role: $roleName via group $groupName") | Out-Null
                }
            }
        }
    }

    $labels = New-Object System.Collections.ArrayList
    foreach ($entry in $excluded.GetEnumerator() | Sort-Object Name) {
        $userLabel = Get-UserLabel -User $entry.Value.User
        $sources = (@($entry.Value.Sources) | Sort-Object -Unique) -join "; "
        $labels.Add("$userLabel — $sources") | Out-Null
    }

    return @($labels)
}


function ConvertTo-ForwardArgumentList {
    param(
        [Parameter(Mandatory)] [hashtable]$Parameters
    )

    $arguments = New-Object System.Collections.ArrayList

    foreach ($entry in $Parameters.GetEnumerator()) {
        $name = [string]$entry.Key
        $value = $entry.Value

        if ($null -eq $value) {
            continue
        }

        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ($value.IsPresent) {
                $arguments.Add("-$name") | Out-Null
            }
            continue
        }

        if ($value -is [bool]) {
            if ($value) {
                $arguments.Add("-$name") | Out-Null
            }
            continue
        }

        $arguments.Add("-$name") | Out-Null

        if ($value -is [array] -and -not ($value -is [string])) {
            foreach ($item in $value) {
                if ($null -ne $item) {
                    $arguments.Add([string]$item) | Out-Null
                }
            }
        }
        else {
            $arguments.Add([string]$value) | Out-Null
        }
    }

    return @($arguments)
}

function Get-LoadedGraphAuthenticationAssemblyVersion {
    $assembly = [System.AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object { $_.GetName().Name -eq "Microsoft.Graph.Authentication" } |
        Select-Object -First 1

    if ($null -eq $assembly) {
        return $null
    }

    return $assembly.GetName().Version
}

function Invoke-CleanPowerShellRelaunch {
    param(
        [Parameter(Mandatory)] [string]$Reason,
        [Parameter(Mandatory)] [hashtable]$BoundParametersToForward
    )

    if ($env:JV_EIDSA_CLEAN_RELAUNCH -eq "1") {
        throw "A clean PowerShell session has already been started, but the Graph-auth assembly conflict remains. Close all PowerShell windows and run the script again with: pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -OpenReport"
    }

    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        throw "The script path could not be determined. Run the script as a file, for example: .\JVEntraIDSecurityAssessment.ps1 -OpenReport"
    }

    $pwshCommand = Get-Command pwsh -ErrorAction SilentlyContinue
    if ($null -eq $pwshCommand) {
        $pwshCommand = Get-Command powershell -ErrorAction SilentlyContinue
    }

    if ($null -eq $pwshCommand) {
        throw "No pwsh or powershell executable was found to start a clean session. Open a new PowerShell 7 session and run the script again."
    }

    Write-ScanLog $Reason "Warn"
    Write-ScanLog "Automatically relaunching in a clean PowerShell session without profile: $($pwshCommand.Source)" "Info"

    $forwardArgs = ConvertTo-ForwardArgumentList -Parameters $BoundParametersToForward
    $env:JV_EIDSA_CLEAN_RELAUNCH = "1"

    try {
        & $pwshCommand.Source -NoLogo -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath @forwardArgs
        $exitCode = $LASTEXITCODE
    }
    finally {
        Remove-Item Env:\JV_EIDSA_CLEAN_RELAUNCH -ErrorAction SilentlyContinue
    }

    if ($null -ne $exitCode -and $exitCode -ne 0) {
        throw "The clean PowerShell session stopped with exit code $exitCode."
    }

    $script:StopAfterCleanRelaunch = $true
}

function Ensure-MicrosoftGraphAuthenticationModule {
    param(
        [switch]$UseLegacyGraphAuthModule
    )

    $moduleName = "Microsoft.Graph.Authentication"

    if ($UseLegacyGraphAuthModule) {
        $requiredVersion = "2.33.0"
        $requiredAssemblyVersion = [version]"2.33.0.0"
        $loadedAssemblyVersion = Get-LoadedGraphAuthenticationAssemblyVersion

        if ($null -ne $loadedAssemblyVersion -and $loadedAssemblyVersion -ne $requiredAssemblyVersion) {
            Invoke-CleanPowerShellRelaunch `
                -Reason "Microsoft.Graph.Authentication assembly $loadedAssemblyVersion is already loaded in this session. Version $requiredAssemblyVersion is required for classic browser authentication without WAM." `
                -BoundParametersToForward $script:OriginalBoundParameters
            return
        }

        $exactModule = Get-Module -ListAvailable -Name $moduleName | Where-Object { $_.Version -eq [version]$requiredVersion } | Select-Object -First 1

        if ($null -eq $exactModule) {
            Write-ScanLog "$moduleName $requiredVersion was not found. Installation will be attempted from PowerShell Gallery." "Warn"
            Install-Module $moduleName -RequiredVersion $requiredVersion -Scope CurrentUser -Force -AllowClobber
        }

        foreach ($loadedModule in @(Get-Module -Name $moduleName)) {
            Remove-Module $loadedModule.Name -Force -ErrorAction SilentlyContinue
        }

        try {
            Import-Module $moduleName -RequiredVersion $requiredVersion -Force -ErrorAction Stop
        }
        catch {
            if ($_.Exception.Message -match "Assembly with same name is already loaded") {
                Invoke-CleanPowerShellRelaunch `
                    -Reason "PowerShell has already loaded another Graph-auth assembly in this session. A clean session is required to load version $requiredAssemblyVersion ." `
                    -BoundParametersToForward $script:OriginalBoundParameters
                return
            }

            throw
        }

        Write-ScanLog "$moduleName $requiredVersion geladen voor legacy browser-authenticatie zonder WAM."
        return
    }

    $module = Get-Module -ListAvailable -Name $moduleName | Sort-Object Version -Descending | Select-Object -First 1
    if ($null -eq $module) {
        Write-ScanLog "$moduleName was not found. Installation will be attempted from PowerShell Gallery." "Warn"
        Install-Module $moduleName -Scope CurrentUser -Force -AllowClobber
    }

    Import-Module $moduleName -ErrorAction Stop
}

Write-ScanLog "Checking modules..."
$useCertificateAuth = (-not [string]::IsNullOrWhiteSpace($ClientId) -and -not [string]::IsNullOrWhiteSpace($CertificateThumbprint))
$useClassicBrowserAuth = (-not $UseWamAuth -and -not $UseDeviceCode -and -not $useCertificateAuth)

if ($UseLegacyGraphAuthModule) {
    $useClassicBrowserAuth = $true
}

Ensure-MicrosoftGraphAuthenticationModule -UseLegacyGraphAuthModule:$useClassicBrowserAuth

if ($script:StopAfterCleanRelaunch) {
    return
}

Write-ScanLog "Connecting to Microsoft Graph..."
$connectCommand = Get-Command Connect-MgGraph -ErrorAction Stop

if ($useClassicBrowserAuth) {
    try {
        Set-MgGraphOption -DisableLoginByWAM $true -ErrorAction SilentlyContinue
    }
    catch {
        Write-ScanLog "The WAM-disable option could not be set. The loaded Graph version determines whether this has any effect." "Warn"
    }

    Write-ScanLog "Classic browser sign-in is active through Microsoft.Graph.Authentication 2.33.0. No tenant preparation is required; consent uses the standard Microsoft Graph tooling app."
}
elseif ($UseWamAuth) {
    Write-ScanLog "WAM authentication is active through the latest Microsoft.Graph.Authentication module."
}

if ($ClientId -and $CertificateThumbprint) {
    if ([string]::IsNullOrWhiteSpace($TenantId)) {
        throw "TenantId is required when ClientId and CertificateThumbprint are used."
    }

    $connectParams = @{
        TenantId              = $TenantId
        ClientId              = $ClientId
        CertificateThumbprint = $CertificateThumbprint
    }

    if ($connectCommand.Parameters.ContainsKey("NoWelcome")) {
        $connectParams["NoWelcome"] = $true
    }

    if ($connectCommand.Parameters.ContainsKey("ContextScope")) {
        $connectParams["ContextScope"] = "Process"
    }

    Write-ScanLog "Connecting through app-only certificate authentication."
    Connect-MgGraph @connectParams | Out-Null
}
else {
    $connectParams = @{
        Scopes = $Scopes
    }

    if (-not [string]::IsNullOrWhiteSpace($TenantId)) {
        $connectParams["TenantId"] = $TenantId
    }

    if (-not [string]::IsNullOrWhiteSpace($ClientId)) {
        $connectParams["ClientId"] = $ClientId
    }

    if ($connectCommand.Parameters.ContainsKey("NoWelcome")) {
        $connectParams["NoWelcome"] = $true
    }

    if ($connectCommand.Parameters.ContainsKey("ContextScope")) {
        $connectParams["ContextScope"] = "Process"
    }

    if ($UseDeviceCode) {
        if ($connectCommand.Parameters.ContainsKey("UseDeviceCode")) {
            $connectParams["UseDeviceCode"] = $true
        }
        elseif ($connectCommand.Parameters.ContainsKey("UseDeviceAuthentication")) {
            $connectParams["UseDeviceAuthentication"] = $true
        }
        else {
            Write-ScanLog "This version of Connect-MgGraph does not appear to have a device-code parameter. Interactive sign-in will be used." "Warn"
        }
    }

    Connect-MgGraph @connectParams | Out-Null
}
$context = Get-MgContext
$contextTenantId = Get-ObjectProperty -InputObject $context -Name "TenantId"
$contextAccount = Get-ObjectProperty -InputObject $context -Name "Account"
Write-ScanLog "Connected to tenant $contextTenantId as $contextAccount."

Write-ScanLog "Retrieving base objects: users, groups, service principals, roles, role assignments and CA policies..."
$allUsers = @(Invoke-GraphGetAllSafe -Uri "/users?`$select=id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime&`$top=999" -Context "Users")
$allGroups = @(Invoke-GraphGetAllSafe -Uri "/groups?`$select=id,displayName,description,mail,mailEnabled,securityEnabled,groupTypes,isAssignableToRole,visibility,createdDateTime&`$top=999" -Context "Groups")
$allServicePrincipals = @(Invoke-GraphGetAllSafe -Uri "/servicePrincipals?`$select=id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId,createdDateTime,tags,appRoles,publishedPermissionScopes&`$top=999" -Context "Service principals")
$allRoleDefinitions = @(Invoke-GraphGetAllSafe -Uri "/roleManagement/directory/roleDefinitions" -Context "Role definitions")
$script:AllRoleAssignments = @(Invoke-GraphGetAllSafe -Uri "/roleManagement/directory/roleAssignments" -Context "Role assignments")
$allConditionalAccessPolicies = @(Invoke-GraphGetAllSafe -Uri "/identity/conditionalAccess/policies?`$top=999" -Context "Conditional Access policies")

foreach ($user in $allUsers) {
    $id = Get-ObjectProperty -InputObject $user -Name "id"
    if (-not [string]::IsNullOrWhiteSpace($id)) {
        $script:UserById[[string]$id] = $user
    }
}

foreach ($group in $allGroups) {
    $id = Get-ObjectProperty -InputObject $group -Name "id"
    if (-not [string]::IsNullOrWhiteSpace($id)) {
        $script:GroupById[[string]$id] = $group
    }
}

foreach ($sp in $allServicePrincipals) {
    $id = Get-ObjectProperty -InputObject $sp -Name "id"
    if (-not [string]::IsNullOrWhiteSpace($id)) {
        $script:ServicePrincipalById[[string]$id] = $sp
    }
}

foreach ($roleDefinition in $allRoleDefinitions) {
    $id = Get-ObjectProperty -InputObject $roleDefinition -Name "id"
    $templateId = Get-ObjectProperty -InputObject $roleDefinition -Name "templateId"

    if (-not [string]::IsNullOrWhiteSpace($id)) {
        $script:RoleDefinitionById[[string]$id] = $roleDefinition
    }

    if (-not [string]::IsNullOrWhiteSpace($templateId)) {
        $script:RoleDefinitionByTemplateId[[string]$templateId] = $roleDefinition
    }
}

foreach ($assignment in $script:AllRoleAssignments) {
    $principalId = Get-ObjectProperty -InputObject $assignment -Name "principalId"
    if ([string]::IsNullOrWhiteSpace($principalId)) {
        continue
    }

    if (-not $script:RoleAssignmentsByPrincipalId.ContainsKey([string]$principalId)) {
        $script:RoleAssignmentsByPrincipalId[[string]$principalId] = New-Object System.Collections.ArrayList
    }

    $script:RoleAssignmentsByPrincipalId[[string]$principalId].Add($assignment) | Out-Null
}

Write-ScanLog "Retrieving user details: group memberships and owned objects..."
$userRows = New-Object System.Collections.ArrayList
$userIndex = 0
$usersToProcess = [object[]]@(ConvertTo-SafeArray -Value $allUsers)
for ($userPosition = 0; $userPosition -lt $usersToProcess.Count; $userPosition++) {
    $user = $usersToProcess[$userPosition]
    $userIndex++
    if (($userIndex % 25) -eq 0) {
        Write-ScanLog "Users processed: $userIndex / $($usersToProcess.Count)"
    }

    $userId = $null
    $userName = "Unknown user"

    try {
        $userId = [string](Get-ObjectProperty -InputObject $user -Name "id")
        $userName = Get-UserLabel -User $user

        if ([string]::IsNullOrWhiteSpace($userId)) {
            Add-ScanWarning -Context "Users" -Message "User without id skipped: $userName"
            continue
        }

        $safeUserId = [System.Uri]::EscapeDataString($userId)
        $memberships = @(Invoke-GraphGetAllSafe -Uri "/users/$safeUserId/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName,mailEnabled,securityEnabled,isAssignableToRole&`$top=999" -Context "Group memberships for user $userName")
        $ownedObjects = @(Invoke-GraphGetAllSafe -Uri "/users/$safeUserId/ownedObjects?`$select=id,displayName,userPrincipalName,appId&`$top=999" -Context "Owned objects for user $userName")

        $directRoleLabels = New-Object System.Collections.ArrayList
        foreach ($assignment in @(Get-RoleAssignmentsForPrincipal -PrincipalId $userId)) {
            $roleDefinitionId = Get-ObjectProperty -InputObject $assignment -Name "roleDefinitionId"
            $scope = Get-ObjectProperty -InputObject $assignment -Name "directoryScopeId"
            if ([string]::IsNullOrWhiteSpace($scope)) { $scope = Get-ObjectProperty -InputObject $assignment -Name "appScopeId" }
            if ([string]::IsNullOrWhiteSpace($scope)) { $scope = "/" }
            [void]$directRoleLabels.Add("$(Get-RoleName -RoleDefinitionId $roleDefinitionId) (Direct, scope: $scope)")
        }

        $groupRoleLabels = New-Object System.Collections.ArrayList
        foreach ($group in @(ConvertTo-SafeArray -Value $memberships)) {
            $groupId = Get-ObjectProperty -InputObject $group -Name "id"
            $groupName = Get-GroupLabel -Group $group
            foreach ($assignment in @(Get-RoleAssignmentsForPrincipal -PrincipalId $groupId)) {
                $roleDefinitionId = Get-ObjectProperty -InputObject $assignment -Name "roleDefinitionId"
                [void]$groupRoleLabels.Add("$(Get-RoleName -RoleDefinitionId $roleDefinitionId) (Via group: $groupName)")
            }
        }

        $allRoleLabels = @((@($directRoleLabels) + @($groupRoleLabels)) | Sort-Object -Unique)
        if ($allRoleLabels.Count -gt 0) {
            Add-Finding -Severity "Medium" -Area "Users" -ObjectName $userName -Detail ("Directory role(s): " + (($allRoleLabels | Select-Object -First 5) -join "; "))
        }

        $ownedObjectLabels = @($ownedObjects | ForEach-Object {
            $type = Get-DirectoryObjectType -Object $_
            $name = Get-ObjectProperty -InputObject $_ -Name "displayName"
            if ([string]::IsNullOrWhiteSpace($name)) { $name = Get-ObjectProperty -InputObject $_ -Name "userPrincipalName" }
            if ([string]::IsNullOrWhiteSpace($name)) { $name = Get-ObjectProperty -InputObject $_ -Name "appId" }
            if ([string]::IsNullOrWhiteSpace($name)) { $name = Get-ObjectProperty -InputObject $_ -Name "id" }
            [string]::Format("{0}: {1}", $type, $name)
        } | Sort-Object -Unique)

        $groupLabels = @($memberships | ForEach-Object { Get-GroupLabel -Group $_ } | Sort-Object -Unique)

        [void]$userRows.Add([pscustomobject]@{
            Name = ConvertTo-HtmlEncodedText $userName
            Enabled = if ((Get-ObjectProperty -InputObject $user -Name "accountEnabled") -eq $true) { New-Badge -Text "Enabled" -Class "ok" } else { New-Badge -Text "Disabled" -Class "neutral" }
            UserType = ConvertTo-HtmlEncodedText (Get-ObjectProperty -InputObject $user -Name "userType")
            DirectoryRoles = New-HtmlDetailsList -Items $allRoleLabels -SummaryPrefix "roles" -EmptyText "No active direct or group-based directory roles found"
            OwnedObjects = New-HtmlDetailsList -Items $ownedObjectLabels -SummaryPrefix "owned objects" -EmptyText "No owned objects found"
            Groups = New-HtmlDetailsList -Items $groupLabels -SummaryPrefix "groups" -EmptyText "No groups found"
        })
    }
    catch {
        $message = Get-ExceptionText -ErrorRecord $_
        Add-ScanWarning -Context "Usersdetails $userName" -Message $message
        Write-ScanLog "User skipped due to error: $userName - $message" "Warn"
        continue
    }
}

Write-ScanLog "Processing groups..."
$groupRows = New-Object System.Collections.ArrayList
foreach ($group in @(ConvertTo-SafeArray -Value $allGroups)) {
    $groupId = Get-ObjectProperty -InputObject $group -Name "id"
    $groupName = Get-GroupLabel -Group $group
    $isAssignableToRole = Get-ObjectProperty -InputObject $group -Name "isAssignableToRole"
    $groupTypes = ConvertTo-SafeArray -Value (Get-ObjectProperty -InputObject $group -Name "groupTypes")

    $roleLabels = New-Object System.Collections.ArrayList
    foreach ($assignment in @(Get-RoleAssignmentsForPrincipal -PrincipalId $groupId)) {
        $roleDefinitionId = Get-ObjectProperty -InputObject $assignment -Name "roleDefinitionId"
        $scope = Get-ObjectProperty -InputObject $assignment -Name "directoryScopeId"
        if ([string]::IsNullOrWhiteSpace($scope)) { $scope = Get-ObjectProperty -InputObject $assignment -Name "appScopeId" }
        if ([string]::IsNullOrWhiteSpace($scope)) { $scope = "/" }
        $roleLabels.Add("$(Get-RoleName -RoleDefinitionId $roleDefinitionId) (scope: $scope)") | Out-Null
    }

    if ($isAssignableToRole -eq $true) {
        Add-Finding -Severity "Medium" -Area "Groups" -ObjectName $groupName -Detail "Group is role-assignable. Review ownership, membership governance and PIM/Access Reviews."
    }

    if ($roleLabels.Count -gt 0) {
        Add-Finding -Severity "High" -Area "Groups" -ObjectName $groupName -Detail ("Group has directory role assignment(s): " + ($roleLabels -join "; "))
    }

    $groupRows.Add([pscustomobject]@{
        Name = ConvertTo-HtmlEncodedText $groupName
        RoleAssignable = New-BoolBadge -Value $isAssignableToRole
        SecurityEnabled = New-BoolBadge -Value (Get-ObjectProperty -InputObject $group -Name "securityEnabled")
        MailEnabled = New-BoolBadge -Value (Get-ObjectProperty -InputObject $group -Name "mailEnabled")
        GroupTypes = New-HtmlList -Items $groupTypes -EmptyText "None"
        DirectoryRoles = New-HtmlDetailsList -Items (@($roleLabels | Sort-Object -Unique)) -SummaryPrefix "roles" -EmptyText "No directory roles"
    }) | Out-Null
}

Write-ScanLog "Processing service principals: API permissions, directory roles and owners..."
$servicePrincipalRows = New-Object System.Collections.ArrayList
$spIndex = 0
foreach ($sp in @(ConvertTo-SafeArray -Value $allServicePrincipals)) {
    $spIndex++
    if (($spIndex % 50) -eq 0) {
        Write-ScanLog "Service principals processed: $spIndex / $($allServicePrincipals.Count)"
    }

    $spId = Get-ObjectProperty -InputObject $sp -Name "id"
    $spName = Get-ServicePrincipalLabel -ServicePrincipal $sp

    try {
        if ([string]::IsNullOrWhiteSpace([string]$spId)) {
            Add-ScanWarning -Context "Service principals" -Message "Service principal without id skipped: $spName"
            continue
        }

        $safeSpId = [System.Uri]::EscapeDataString([string]$spId)
        $appRoleAssignments = @(Invoke-GraphGetAllSafe -Uri "/servicePrincipals/$safeSpId/appRoleAssignments?`$select=id,appRoleId,createdDateTime,principalDisplayName,principalId,principalType,resourceDisplayName,resourceId&`$top=999" -Context "Application permissions service principal $spName")
        $oauth2PermissionGrants = @(Invoke-GraphGetAllSafe -Uri "/servicePrincipals/$safeSpId/oauth2PermissionGrants?`$top=999" -Context "Delegated permissions service principal $spName")
        $owners = @(Invoke-GraphGetAllSafe -Uri "/servicePrincipals/$safeSpId/owners?`$select=id,displayName,userPrincipalName,mail,appId&`$top=999" -Context "Owners service principal $spName")

        $applicationPermissionLabels = @(Sort-PermissionLabels -PermissionLabels @($appRoleAssignments | ForEach-Object { Resolve-ApplicationPermissionLabel -AppRoleAssignment $_ }))
        $delegatedPermissionLabels = @(Sort-PermissionLabels -PermissionLabels (Resolve-DelegatedPermissionLabels -Oauth2PermissionGrants $oauth2PermissionGrants))

    $directoryRoleLabels = New-Object System.Collections.ArrayList
    foreach ($assignment in @(Get-RoleAssignmentsForPrincipal -PrincipalId $spId)) {
        $roleDefinitionId = Get-ObjectProperty -InputObject $assignment -Name "roleDefinitionId"
        $scope = Get-ObjectProperty -InputObject $assignment -Name "directoryScopeId"
        if ([string]::IsNullOrWhiteSpace($scope)) { $scope = Get-ObjectProperty -InputObject $assignment -Name "appScopeId" }
        if ([string]::IsNullOrWhiteSpace($scope)) { $scope = "/" }
        $directoryRoleLabels.Add("$(Get-RoleName -RoleDefinitionId $roleDefinitionId) (scope: $scope)") | Out-Null
    }

    $userOwnerLabels = New-Object System.Collections.ArrayList
    $nonUserOwnerLabels = New-Object System.Collections.ArrayList
    foreach ($owner in $owners) {
        $type = Get-DirectoryObjectType -Object $owner
        if ($type -eq "user") {
            $userOwnerLabels.Add((Get-UserLabel -User $owner)) | Out-Null
        }
        else {
            $ownerName = Get-ObjectProperty -InputObject $owner -Name "displayName"
            if ([string]::IsNullOrWhiteSpace($ownerName)) { $ownerName = Get-ObjectProperty -InputObject $owner -Name "appId" }
            if ([string]::IsNullOrWhiteSpace($ownerName)) { $ownerName = Get-ObjectProperty -InputObject $owner -Name "id" }
            [void]$nonUserOwnerLabels.Add(("{0}: {1}" -f $type, $ownerName))
        }
    }

    if ($userOwnerLabels.Count -eq 0) {
        Add-Finding -Severity "High" -Area "Service Principals" -ObjectName $spName -Detail "No user owner found on the service principal."
    }

    if ($applicationPermissionLabels.Count -gt 0) {
        Add-Finding -Severity "Medium" -Area "Service Principals" -ObjectName $spName -Detail ("Application permissions: " + (($applicationPermissionLabels | Select-Object -First 5) -join "; "))
    }

    if ($directoryRoleLabels.Count -gt 0) {
        Add-Finding -Severity "High" -Area "Service Principals" -ObjectName $spName -Detail ("Directory role(s): " + ($directoryRoleLabels -join "; "))
    }

        [void]$servicePrincipalRows.Add([pscustomobject]@{
            Name = ConvertTo-HtmlEncodedText $spName
            Type = ConvertTo-HtmlEncodedText (Get-ObjectProperty -InputObject $sp -Name "servicePrincipalType")
            Enabled = if ((Get-ObjectProperty -InputObject $sp -Name "accountEnabled") -eq $true) { New-Badge -Text "Enabled" -Class "ok" } else { New-Badge -Text "Disabled" -Class "neutral" }
            ApplicationPermissions = New-HtmlDetailsList -Items $applicationPermissionLabels -SummaryPrefix "application permissions" -EmptyText "No application permissions found"
            DelegatedPermissions = New-HtmlDetailsList -Items $delegatedPermissionLabels -SummaryPrefix "delegated permissions" -EmptyText "No delegated permissions found"
            DirectoryRoles = New-HtmlDetailsList -Items (@($directoryRoleLabels | Sort-Object -Unique)) -SummaryPrefix "directory roles" -EmptyText "No directory roles"
            UserOwners = New-HtmlDetailsList -Items (@($userOwnerLabels | Sort-Object -Unique)) -SummaryPrefix "user owners" -EmptyText "No user owners"
            OtherOwners = New-HtmlDetailsList -Items (@($nonUserOwnerLabels | Sort-Object -Unique)) -SummaryPrefix "other owners" -EmptyText "No other owners"
        })
    }
    catch {
        $message = Get-ExceptionText -ErrorRecord $_
        Add-ScanWarning -Context "Service principal $spName" -Message $message
        Write-ScanLog "Service principal skipped due to error: $spName - $message" "Warn"
        continue
    }
}

Write-ScanLog "Processing Conditional Access policies..."
$conditionalAccessRows = New-Object System.Collections.ArrayList
foreach ($policy in $allConditionalAccessPolicies | Sort-Object @{ Expression = { Get-ObjectProperty -InputObject $_ -Name "displayName" } }) {
    $policyName = Get-ObjectProperty -InputObject $policy -Name "displayName"
    if ([string]::IsNullOrWhiteSpace($policyName)) {
        $policyName = Get-ObjectProperty -InputObject $policy -Name "id"
    }

    $conditions = Get-ObjectProperty -InputObject $policy -Name "conditions"
    $usersCondition = Get-ObjectProperty -InputObject $conditions -Name "users"
    $applicationsCondition = Get-ObjectProperty -InputObject $conditions -Name "applications"

    $includeUsers = @(ConvertTo-SafeArray -Value (Get-ObjectProperty -InputObject $usersCondition -Name "includeUsers"))
    $excludeUsers = @(ConvertTo-SafeArray -Value (Get-ObjectProperty -InputObject $usersCondition -Name "excludeUsers"))
    $includeGroups = @(ConvertTo-SafeArray -Value (Get-ObjectProperty -InputObject $usersCondition -Name "includeGroups"))
    $excludeGroups = @(ConvertTo-SafeArray -Value (Get-ObjectProperty -InputObject $usersCondition -Name "excludeGroups"))
    $includeRoles = @(ConvertTo-SafeArray -Value (Get-ObjectProperty -InputObject $usersCondition -Name "includeRoles"))
    $excludeRoles = @(ConvertTo-SafeArray -Value (Get-ObjectProperty -InputObject $usersCondition -Name "excludeRoles"))

    $includeApplicationIds = @(ConvertTo-SafeArray -Value (Get-ObjectProperty -InputObject $applicationsCondition -Name "includeApplications"))
    $excludeApplicationIds = @(ConvertTo-SafeArray -Value (Get-ObjectProperty -InputObject $applicationsCondition -Name "excludeApplications"))

    $directExcludedUserLabels = @(Resolve-UserIdsToLabels -Ids $excludeUsers | Sort-Object -Unique)
    $excludedGroupLabels = @(Resolve-GroupIdsToLabels -Ids $excludeGroups | Sort-Object -Unique)
    $excludedRoleLabels = @(Resolve-RoleIdsToLabels -Ids $excludeRoles | Sort-Object -Unique)
    $expandedExcludedUserLabels = @(Get-ConditionalAccessExpandedExcludedUsers -ExcludeUsers $excludeUsers -ExcludeGroups $excludeGroups -ExcludeRoles $excludeRoles -PolicyName $policyName | Sort-Object -Unique)

    if ($expandedExcludedUserLabels.Count -gt 0) {
        Add-Finding -Severity "Medium" -Area "Conditional Access" -ObjectName $policyName -Detail "$($expandedExcludedUserLabels.Count) excluded user(s), directly or through an excluded group/role."
    }

    $state = Get-ObjectProperty -InputObject $policy -Name "state"
    if ($state -eq "disabled") {
        Add-Finding -Severity "Low" -Area "Conditional Access" -ObjectName $policyName -Detail "Policy is disabled."
    }

    $rawJson = ConvertTo-HtmlEncodedText (ConvertTo-JsonSafe -Value $policy)

    $conditionalAccessRows.Add([pscustomobject]@{
        Name = ConvertTo-HtmlEncodedText $policyName
        State = switch ($state) {
            "enabled" { New-Badge -Text "Enabled" -Class "ok" }
            "enabledForReportingButNotEnforced" { New-Badge -Text "Report-only" -Class "warn" }
            "disabled" { New-Badge -Text "Disabled" -Class "neutral" }
            default { New-Badge -Text $state -Class "neutral" }
        }
        IncludeScope = (New-HtmlDetailsList -Items @(
            ($includeUsers | ForEach-Object { "User: $_" })
            (Resolve-GroupIdsToLabels -Ids $includeGroups | ForEach-Object { "Group: $_" })
            (Resolve-RoleIdsToLabels -Ids $includeRoles | ForEach-Object { "Role: $_" })
        ) -SummaryPrefix "scope items" -EmptyText "No include scope found")
        Applications = (New-HtmlDetailsList -Items @(
            ($includeApplicationIds | ForEach-Object { "Include app: $_" })
            ($excludeApplicationIds | ForEach-Object { "Exclude app: $_" })
        ) -SummaryPrefix "application rules" -EmptyText "No application rules found")
        DirectExcludedUsers = New-HtmlDetailsList -Items $directExcludedUserLabels -SummaryPrefix "direct excluded users" -EmptyText "None direct excluded users"
        ExcludedGroups = New-HtmlDetailsList -Items $excludedGroupLabels -SummaryPrefix "excluded groups" -EmptyText "No excluded groups"
        ExcludedRoles = New-HtmlDetailsList -Items $excludedRoleLabels -SummaryPrefix "excluded roles" -EmptyText "No excluded roles"
        ExpandedExcludedUsers = New-HtmlDetailsList -Items $expandedExcludedUserLabels -SummaryPrefix "total excluded users" -EmptyText "No excluded users found"
        Configuration = "<details><summary>Configuration JSON</summary><pre>$rawJson</pre></details>"
    }) | Out-Null
}

Write-ScanLog "Building report..."

$findingsRows = New-Object System.Collections.ArrayList
foreach ($finding in $script:Findings | Sort-Object @{ Expression = { $_.Severity }; Descending = $true }, Area, ObjectName) {
    $severityClass = switch ($finding.Severity) {
        "High" { "danger" }
        "Medium" { "warn" }
        "Low" { "neutral" }
        default { "ok" }
    }

    $findingsRows.Add([pscustomobject]@{
        Severity = New-Badge -Text $finding.Severity -Class $severityClass
        Area = ConvertTo-HtmlEncodedText $finding.Area
        ObjectName = ConvertTo-HtmlEncodedText $finding.ObjectName
        Detail = ConvertTo-HtmlEncodedText $finding.Detail
    }) | Out-Null
}


$roleAssignableGroupCount = @($allGroups | Where-Object { (Get-ObjectProperty -InputObject $_ -Name "isAssignableToRole") -eq $true }).Count
$enabledCaCount = @($allConditionalAccessPolicies | Where-Object { (Get-ObjectProperty -InputObject $_ -Name "state") -eq "enabled" }).Count
$spWithoutUserOwnerCount = @($script:Findings | Where-Object { $_.Area -eq "Service Principals" -and $_.Detail -like "No user owner*" }).Count
$highFindingCount = @($script:Findings | Where-Object { $_.Severity -eq "High" }).Count
$mediumFindingCount = @($script:Findings | Where-Object { $_.Severity -eq "Medium" }).Count

$generatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"
$tenantId = ConvertTo-HtmlEncodedText $contextTenantId
$account = ConvertTo-HtmlEncodedText $contextAccount

$overviewHtml = @"
<div class="hero">
    <div>
        <p class="eyebrow">JVEntraIDSecurityAssessment</p>
        <h1>Microsoft Entra ID Security Report</h1>
        <p class="subtitle">Tenant: <strong>$tenantId</strong> · Account: <strong>$account</strong> · Generated: <strong>$generatedAt</strong></p>
    </div>
    <div class="hero-chip">Read-only scan</div>
</div>

<div class="cards">
    <div class="card"><span>Users</span><strong>$($allUsers.Count)</strong></div>
    <div class="card"><span>Groups</span><strong>$($allGroups.Count)</strong></div>
    <div class="card"><span>Role-assignable groups</span><strong>$roleAssignableGroupCount</strong></div>
    <div class="card"><span>Service principals</span><strong>$($allServicePrincipals.Count)</strong></div>
    <div class="card"><span>CA policies</span><strong>$($allConditionalAccessPolicies.Count)</strong></div>
    <div class="card"><span>Enabled CA policies</span><strong>$enabledCaCount</strong></div>
    <div class="card"><span>SPs without user owner</span><strong>$spWithoutUserOwnerCount</strong></div>
    <div class="card"><span>Findings high / medium</span><strong>$highFindingCount / $mediumFindingCount</strong></div>
</div>

<div class="note">
    <strong>Scope of this first version:</strong> active role assignments, memberships at scan time, service principal API permissions, owners and Conditional Access configuration. PIM eligible assignments and audit/sign-in logging are intentionally not included yet.
</div>
"@

$findingsTable = New-DataTableHtml -Id "findingsTable" -Title "Findings" -Rows ($findingsRows.ToArray()) -Columns @("Severity", "Area", "ObjectName", "Detail") -ColumnLabels @{
    Severity = "Severity"
    Area = "Area"
    ObjectName = "Object"
    Detail = "Detail"
}

$userTable = New-DataTableHtml -Id "usersTable" -Title "Users" -Rows ($userRows.ToArray()) -Columns @("Name", "Enabled", "UserType", "DirectoryRoles", "OwnedObjects", "Groups") -ColumnLabels @{
    Name = "User"
    Enabled = "Status"
    UserType = "Type"
    DirectoryRoles = "Directory Roles"
    OwnedObjects = "Owned objects"
    Groups = "Groups"
}

$groupTable = New-DataTableHtml -Id "groupsTable" -Title "Groups" -Rows ($groupRows.ToArray()) -Columns @("Name", "RoleAssignable", "SecurityEnabled", "MailEnabled", "GroupTypes", "DirectoryRoles") -ColumnLabels @{
    Name = "Group"
    RoleAssignable = "Role assignable"
    SecurityEnabled = "Security enabled"
    MailEnabled = "Mail enabled"
    GroupTypes = "Group types"
    DirectoryRoles = "Directory roles"
}

$servicePrincipalTable = New-DataTableHtml -Id "servicePrincipalsTable" -Title "Service Principals" -Rows ($servicePrincipalRows.ToArray()) -Columns @("Name", "Type", "Enabled", "ApplicationPermissions", "DelegatedPermissions", "DirectoryRoles", "UserOwners", "OtherOwners") -ColumnLabels @{
    Name = "Service principal"
    Type = "Type"
    Enabled = "Status"
    ApplicationPermissions = "API application permissions"
    DelegatedPermissions = "API delegated permissions"
    DirectoryRoles = "Directory roles"
    UserOwners = "User owners"
    OtherOwners = "Other owners"
}

$conditionalAccessTable = New-DataTableHtml -Id "conditionalAccessTable" -Title "Conditional Access Policies" -Rows ($conditionalAccessRows.ToArray()) -Columns @("Name", "State", "IncludeScope", "Applications", "DirectExcludedUsers", "ExcludedGroups", "ExcludedRoles", "ExpandedExcludedUsers", "Configuration") -ColumnLabels @{
    Name = "Policy"
    State = "State"
    IncludeScope = "Include scope"
    Applications = "Applications"
    DirectExcludedUsers = "Direct excluded users"
    ExcludedGroups = "Excluded groups"
    ExcludedRoles = "Excluded roles"
    ExpandedExcludedUsers = "Total excluded users"
    Configuration = "Configuration"
}


$css = @"
:root {
    --accent: $AccentColor;
    --accent-strong: color-mix(in srgb, $AccentColor 78%, #0f172a);
    --bg: #f5f9fd;
    --surface: #ffffff;
    --surface-soft: #eef7ff;
    --text: #172033;
    --muted: #64748b;
    --border: #d8e7f4;
    --ok: #16865a;
    --warn: #b87504;
    --danger: #be123c;
    --shadow: 0 18px 50px rgba(15, 23, 42, 0.09);
}

* { box-sizing: border-box; }
body {
    margin: 0;
    font-family: "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
    background: radial-gradient(circle at top left, rgba(119, 176, 222, 0.28), transparent 28rem), var(--bg);
    color: var(--text);
}

.container {
    max-width: 1500px;
    margin: 0 auto;
    padding: 32px;
}

.hero {
    display: flex;
    justify-content: space-between;
    gap: 24px;
    align-items: flex-start;
    padding: 30px;
    border: 1px solid var(--border);
    border-radius: 28px;
    background: linear-gradient(135deg, rgba(255,255,255,0.96), rgba(238,247,255,0.96));
    box-shadow: var(--shadow);
}

.eyebrow {
    margin: 0 0 8px;
    text-transform: uppercase;
    letter-spacing: 0.13em;
    font-size: 12px;
    font-weight: 800;
    color: var(--accent-strong);
}

h1 {
    margin: 0;
    font-size: clamp(30px, 4vw, 48px);
    line-height: 1;
}

.subtitle {
    color: var(--muted);
    margin: 14px 0 0;
}

.hero-chip {
    background: var(--accent);
    color: #082033;
    font-weight: 800;
    border-radius: 999px;
    padding: 10px 16px;
    white-space: nowrap;
}

.cards {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 16px;
    margin: 22px 0;
}

.card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 22px;
    padding: 20px;
    box-shadow: 0 10px 24px rgba(15, 23, 42, 0.05);
}

.card span {
    display: block;
    color: var(--muted);
    font-size: 13px;
    margin-bottom: 8px;
}

.card strong {
    font-size: 30px;
}

.note {
    margin: 0 0 22px;
    padding: 16px 18px;
    background: var(--surface-soft);
    border: 1px solid var(--border);
    border-left: 6px solid var(--accent);
    border-radius: 18px;
    color: #243449;
}

.tabs {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    margin: 26px 0 18px;
    position: sticky;
    top: 0;
    z-index: 10;
    padding: 10px;
    background: rgba(245, 249, 253, 0.88);
    backdrop-filter: blur(12px);
}

.tab-button {
    border: 1px solid var(--border);
    background: var(--surface);
    color: var(--text);
    border-radius: 999px;
    padding: 10px 14px;
    cursor: pointer;
    font-weight: 750;
    transition: 0.18s ease;
}

.tab-button:hover, .tab-button.active {
    background: var(--accent);
    border-color: var(--accent);
    color: #071826;
    transform: translateY(-1px);
}

.tab-panel { display: none; }
.tab-panel.active { display: block; }

.table-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 24px;
    box-shadow: var(--shadow);
    overflow: hidden;
    margin-bottom: 24px;
}

.table-card-header {
    display: flex;
    justify-content: space-between;
    gap: 18px;
    align-items: center;
    padding: 22px;
    border-bottom: 1px solid var(--border);
    background: linear-gradient(90deg, rgba(119, 176, 222, 0.16), rgba(255,255,255,0));
}

.table-card-header h2 {
    margin: 0;
    font-size: 22px;
}

.table-card-header p {
    margin: 4px 0 0;
    color: var(--muted);
}

.table-search {
    width: min(360px, 100%);
    border: 1px solid var(--border);
    border-radius: 999px;
    padding: 11px 15px;
    font-size: 14px;
    outline: none;
}

.table-search:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 4px rgba(119, 176, 222, 0.25);
}

.table-wrap {
    overflow: auto;
    max-height: 76vh;
}

table {
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    font-size: 13px;
}

th {
    position: sticky;
    top: 0;
    z-index: 1;
    background: #edf6ff;
    color: #233044;
    text-align: left;
    padding: 13px 14px;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
}

td {
    vertical-align: top;
    padding: 13px 14px;
    border-bottom: 1px solid #edf2f7;
}

tr:hover td { background: #f8fbff; }

.muted { color: var(--muted); }

.badge {
    display: inline-flex;
    align-items: center;
    border-radius: 999px;
    padding: 4px 9px;
    font-size: 12px;
    font-weight: 800;
    background: #e2e8f0;
    color: #263445;
    white-space: nowrap;
}

.badge.ok { background: #dff7ed; color: var(--ok); }
.badge.warn { background: #fff2cc; color: var(--warn); }
.badge.danger { background: #ffe4eb; color: var(--danger); }
.badge.neutral { background: #e8eef5; color: #475569; }

.mini-list {
    margin: 8px 0 0;
    padding-left: 18px;
    min-width: 260px;
}

.mini-list li { margin: 2px 0; }

details summary {
    cursor: pointer;
    color: var(--accent-strong);
    font-weight: 800;
    white-space: nowrap;
}

pre {
    white-space: pre-wrap;
    word-break: break-word;
    background: #0f172a;
    color: #e2e8f0;
    border-radius: 14px;
    padding: 14px;
    max-width: 740px;
    max-height: 420px;
    overflow: auto;
}

.footer {
    color: var(--muted);
    margin-top: 28px;
    text-align: center;
    font-size: 12px;
}

.footer a {
    color: var(--accent-strong);
    font-weight: 800;
    text-decoration: none;
}

.footer a:hover { text-decoration: underline; }

@media (max-width: 1000px) {
    .cards { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .hero, .table-card-header { flex-direction: column; align-items: stretch; }
}

@media (max-width: 640px) {
    .container { padding: 18px; }
    .cards { grid-template-columns: 1fr; }
}
"@

$javascript = @"
function showTab(tabId) {
    document.querySelectorAll('.tab-button').forEach(function(button) {
        button.classList.toggle('active', button.dataset.tab === tabId);
    });
    document.querySelectorAll('.tab-panel').forEach(function(panel) {
        panel.classList.toggle('active', panel.id === tabId);
    });
}

function filterTable(tableId, query) {
    const table = document.getElementById(tableId);
    if (!table) return;
    const normalizedQuery = (query || '').toLowerCase();
    table.querySelectorAll('tbody tr').forEach(function(row) {
        const text = row.innerText.toLowerCase();
        row.style.display = text.includes(normalizedQuery) ? '' : 'none';
    });
}

window.addEventListener('DOMContentLoaded', function() {
    const firstButton = document.querySelector('.tab-button');
    if (firstButton) {
        showTab(firstButton.dataset.tab);
    }
});
"@

$html = @"
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>JVEntraIDSecurityAssessment</title>
    <style>$css</style>
</head>
<body>
    <main class="container">
        $overviewHtml

        <nav class="tabs" aria-label="Report tabs">
            <button class="tab-button" data-tab="tab-users" onclick="showTab('tab-users')">Users</button>
            <button class="tab-button" data-tab="tab-groups" onclick="showTab('tab-groups')">Groups</button>
            <button class="tab-button" data-tab="tab-service-principals" onclick="showTab('tab-service-principals')">Service Principals</button>
            <button class="tab-button" data-tab="tab-conditional-access" onclick="showTab('tab-conditional-access')">Conditional Access Policies</button>
            <button class="tab-button" data-tab="tab-findings" onclick="showTab('tab-findings')">Findings</button>
        </nav>

        <section id="tab-users" class="tab-panel">$userTable</section>
        <section id="tab-groups" class="tab-panel">$groupTable</section>
        <section id="tab-service-principals" class="tab-panel">$servicePrincipalTable</section>
        <section id="tab-conditional-access" class="tab-panel">$conditionalAccessTable</section>
        <section id="tab-findings" class="tab-panel">$findingsTable</section>

        <p class="footer">Generated by <a href="https://github.com/JustinVerstijnen/JV-EntraIDSecurityAssessment" target="_blank" rel="noopener noreferrer">JVEntraIDSecurityAssessment</a> · Accent $AccentColor</p>
    </main>
    <script>$javascript</script>
</body>
</html>
"@

$outputDirectory = Split-Path -Path $OutputPath -Parent
if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -Path $outputDirectory)) {
    New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
}

$html | Out-File -FilePath $OutputPath -Encoding UTF8 -Force
Write-ScanLog "Report written to: $OutputPath" "Done"

if ($OpenReport) {
    try {
        Invoke-Item -Path $OutputPath
    }
    catch {
        Write-ScanLog "Report could not be opened automatically: $($_.Exception.Message)" "Warn"
    }
}