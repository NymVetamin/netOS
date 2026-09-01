param(
    [string]$CredentialsPath = (Join-Path (Split-Path $PSScriptRoot -Parent) "dev_server_creds.txt"),
    [string]$UsernameOverride = "",
    [switch]$ResetDraft
)

$ErrorActionPreference = "Stop"

$credentials = @(Get-Content -LiteralPath $CredentialsPath | Where-Object { $_.Trim() })
if ($credentials -match 'https?://') {
    $addressLine = $credentials | Where-Object { $_ -match 'https?://' } | Select-Object -First 1
    $hostValue = [regex]::Match($addressLine, 'https?://\S+').Value
    $username = (($credentials[-2] -split '\s{2,}')[-1]).Trim()
    $password = (($credentials[-1] -split '\s{2,}')[-1]).Trim()
    if (-not $hostValue -or -not $username -or -not $password) {
        throw "Initial credentials file is incomplete"
    }
} else {
    if ($credentials.Count -ne 3) {
        throw "Expected host, username and password on three non-empty lines"
    }
    $hostValue = $credentials[0].Trim()
    $username = $credentials[1].Trim()
    $password = $credentials[2].Trim()
}
if ($UsernameOverride) {
    if ($UsernameOverride -notmatch '^[A-Za-z0-9_.@-]{1,64}$') {
        throw "UsernameOverride has an unsafe format"
    }
    $username = $UsernameOverride
}
if ($hostValue -match '^https?://') {
    $baseURL = $hostValue.TrimEnd('/')
} elseif ($hostValue -match ':\d+$') {
    $baseURL = "https://$hostValue"
} else {
    $baseURL = "https://${hostValue}:8443"
}

$qaTemp = Join-Path ([IO.Path]::GetTempPath()) ("netos-live-api-" + [Guid]::NewGuid().ToString("N"))
$null = New-Item -ItemType Directory -Path $qaTemp
$cookieJar = Join-Path $qaTemp "cookies.txt"
$script:csrf = ""
$results = New-Object System.Collections.Generic.List[object]

function Invoke-NetOSRequest {
    param(
        [string]$Method,
        [string]$Path,
        $Body = $null,
        [string]$RawJSON = "",
        [hashtable]$Headers = @{},
        [bool]$UseCookie = $true,
        [bool]$UseCSRF = $true
    )

    $bodyPath = Join-Path $qaTemp ([Guid]::NewGuid().ToString("N") + ".body")
    $arguments = @("-k", "-sS", "-o", $bodyPath, "-w", "%{http_code}", "-X", $Method)
    if ($UseCookie) {
        $arguments += @("-b", $cookieJar, "-c", $cookieJar)
    }
    foreach ($name in $Headers.Keys) {
        $arguments += @("-H", "${name}: $($Headers[$name])")
    }
    if ($UseCSRF -and $script:csrf -and $Method -notin @("GET", "HEAD")) {
        $arguments += @("-H", "X-NetOS-CSRF: $script:csrf")
    }
    if ($null -ne $Body -or $RawJSON) {
        $json = if ($RawJSON) { $RawJSON } else { $Body | ConvertTo-Json -Depth 100 -Compress }
        $requestPath = Join-Path $qaTemp ([Guid]::NewGuid().ToString("N") + ".json")
        [IO.File]::WriteAllText($requestPath, $json, (New-Object Text.UTF8Encoding($false)))
        $arguments += @("-H", "Content-Type: application/json", "--data-binary", ("@" + $requestPath))
    }
    $arguments += ($baseURL + $Path)

    $statusText = & curl.exe @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "curl failed for $Method $Path"
    }
    $content = if (Test-Path -LiteralPath $bodyPath) { [IO.File]::ReadAllText($bodyPath, [Text.Encoding]::UTF8) } else { "" }
    Remove-Item -LiteralPath $bodyPath -Force -ErrorAction SilentlyContinue
    if ($requestPath) { Remove-Item -LiteralPath $requestPath -Force -ErrorAction SilentlyContinue }
    [pscustomobject]@{ Status = [int]$statusText; Content = $content }
}

function Assert-NetOSStatus {
    param([string]$Name, $Response, [int[]]$Expected = @(200))
    if ($Response.Status -notin $Expected) {
        throw "$Name returned HTTP $($Response.Status), expected $($Expected -join ',')"
    }
    $results.Add([pscustomobject]@{ Check = $Name; HTTP = $Response.Status })
}

try {
    $response = Invoke-NetOSRequest GET "/api/ping" -UseCookie $false
    Assert-NetOSStatus "public ping" $response

    $response = Invoke-NetOSRequest GET "/api/config" -UseCookie $false
    Assert-NetOSStatus "unauthenticated config rejected" $response @(401)

    $badLogin = @{ username = "__qa_nonexistent__"; password = "invalid-qa-password" }
    $response = Invoke-NetOSRequest POST "/api/login" $badLogin -UseCookie $false -UseCSRF $false
    Assert-NetOSStatus "invalid login rejected" $response @(401)

    $response = Invoke-NetOSRequest POST "/api/login" @{ username = $username; password = $password } -UseCookie $true -UseCSRF $false
    Assert-NetOSStatus "valid login" $response
    $login = $response.Content | ConvertFrom-Json
    if (-not $login.csrf_token -or -not $login.role) { throw "login response lacks role or CSRF token" }
    $script:csrf = $login.csrf_token

    $response = Invoke-NetOSRequest GET "/api/session"
    Assert-NetOSStatus "session refresh" $response
    $session = $response.Content | ConvertFrom-Json
    $script:csrf = $session.csrf_token

    $response = Invoke-NetOSRequest POST "/api/config/plan" -Headers @{ "X-NetOS-CSRF" = "invalid" } -UseCSRF $false
    Assert-NetOSStatus "invalid CSRF rejected" $response @(403)

    $response = Invoke-NetOSRequest POST "/api/password" @{ current = "invalid"; new = "short" }
    Assert-NetOSStatus "short replacement password rejected" $response @(400)
    $response = Invoke-NetOSRequest POST "/api/password" @{ current = "invalid"; new = "valid-length-qa-password" }
    Assert-NetOSStatus "wrong current password rejected" $response @(403)

    $response = Invoke-NetOSRequest POST "/api/config/confirm" @{}
    Assert-NetOSStatus "confirm without pending apply rejected" $response @(409)
    $response = Invoke-NetOSRequest POST "/api/config/rollback" @{}
    Assert-NetOSStatus "rollback without pending apply rejected" $response @(409)

    $response = Invoke-NetOSRequest POST "/api/maintenance/restore" @{ name = "missing"; confirm = "WRONG" }
    Assert-NetOSStatus "restore without literal confirmation rejected" $response @(400)
    $response = Invoke-NetOSRequest POST "/api/maintenance/update" @{ version = "latest"; confirm = "WRONG" }
    Assert-NetOSStatus "update without literal confirmation rejected" $response @(400)
    $response = Invoke-NetOSRequest POST "/api/maintenance/panel" @{ panel = @{}; confirm = "WRONG" }
    Assert-NetOSStatus "panel restart without literal confirmation rejected" $response @(400)

    $response = Invoke-NetOSRequest GET "/api/revisions/not-a-number"
    Assert-NetOSStatus "invalid revision ID rejected" $response @(400)
    $response = Invoke-NetOSRequest GET "/api/revisions/9223372036854775807"
    Assert-NetOSStatus "missing revision rejected" $response @(404)
    $response = Invoke-NetOSRequest GET "/api/backups/netos-qa-definitely-missing.tar.gz"
    Assert-NetOSStatus "missing backup download rejected" $response @(404)
    $response = Invoke-NetOSRequest DELETE "/api/backups/netos-qa-definitely-missing.tar.gz"
    Assert-NetOSStatus "missing backup delete rejected" $response @(404)
    $response = Invoke-NetOSRequest GET "/api/vpn-servers/__qa_missing__/certificate"
    Assert-NetOSStatus "missing VPN certificate rejected" $response @(404)

    $getPaths = @(
        "/api/catalog", "/api/status", "/api/ddns/status", "/api/maintenance/status",
        "/api/backups", "/api/clients", "/api/interfaces", "/api/leases", "/api/arp",
        "/api/routes", "/api/audit?limit=1", "/api/audit?limit=100",
        "/api/revisions?limit=1", "/api/revisions?limit=50",
        "/api/statistics?hours=1", "/api/statistics?hours=24", "/api/statistics?hours=168"
    )
    foreach ($path in $getPaths) {
        $response = Invoke-NetOSRequest GET $path
        Assert-NetOSStatus "GET $path" $response
        if (-not $response.Content.Trim()) { throw "GET $path returned an empty body" }
    }

    $response = Invoke-NetOSRequest POST "/api/wireguard/keypair"
    Assert-NetOSStatus "WireGuard key generation" $response
    $wg = $response.Content | ConvertFrom-Json
    if ($wg.private_key.Length -ne 44 -or $wg.public_key.Length -ne 44) { throw "unexpected WireGuard key lengths" }
    $response = Invoke-NetOSRequest POST "/api/wireguard/keypair" @{ private_key = $wg.private_key }
    Assert-NetOSStatus "WireGuard public-key derivation" $response
    $wgDerived = $response.Content | ConvertFrom-Json
    if ($wgDerived.public_key -ne $wg.public_key -or $wgDerived.private_key) { throw "WireGuard derivation mismatch" }
    $response = Invoke-NetOSRequest POST "/api/wireguard/keypair" @{ private_key = "invalid" }
    Assert-NetOSStatus "invalid WireGuard key rejected" $response @(400)

    $response = Invoke-NetOSRequest POST "/api/xray/keypair"
    Assert-NetOSStatus "Reality key generation" $response
    $xray = $response.Content | ConvertFrom-Json
    if (-not $xray.private_key -or -not $xray.public_key) { throw "Reality keypair is incomplete" }
    $response = Invoke-NetOSRequest POST "/api/xray/keypair" @{ private_key = $xray.private_key }
    Assert-NetOSStatus "Reality public-key derivation" $response
    $xrayDerived = $response.Content | ConvertFrom-Json
    if ($xrayDerived.public_key -ne $xray.public_key -or $xrayDerived.private_key) { throw "Reality derivation mismatch" }
    $response = Invoke-NetOSRequest POST "/api/xray/keypair" @{ private_key = "invalid" }
    Assert-NetOSStatus "invalid Reality key rejected" $response @(400)

    $response = Invoke-NetOSRequest GET "/api/config"
    Assert-NetOSStatus "get configuration" $response
    $configEnvelopeJSON = $response.Content
    $configResponse = $response.Content | ConvertFrom-Json
    if ($configResponse.pending_confirmation) { throw "live configuration has a pending confirmation" }
    if ($configResponse.dirty -and $ResetDraft) {
        $response = Invoke-NetOSRequest POST "/api/config/discard" -Headers @{ "If-Match" = [string]$configResponse.draft_version }
        Assert-NetOSStatus "discard QA draft" $response
        $response = Invoke-NetOSRequest GET "/api/config"
        Assert-NetOSStatus "get clean configuration" $response
        $configEnvelopeJSON = $response.Content
        $configResponse = $response.Content | ConvertFrom-Json
    }
    if ($configResponse.dirty) { throw "live configuration is dirty before API test" }
    $draftVersion = [int]$configResponse.draft_version

    foreach ($server in @($configResponse.config.vpn_servers | Where-Object {
        $_.enabled -and $_.type -in @("ocserv", "ikev2")
    })) {
        $escapedServerID = [Uri]::EscapeDataString([string]$server.id)
        $response = Invoke-NetOSRequest GET ("/api/vpn-servers/" + $escapedServerID + "/certificate")
        Assert-NetOSStatus ("VPN certificate " + $server.id) $response
        if ($response.Content -notmatch "BEGIN CERTIFICATE") { throw "VPN certificate $($server.id) is not PEM" }
    }

    $response = Invoke-NetOSRequest GET "/api/revisions?limit=50"
    Assert-NetOSStatus "revision list for detail checks" $response
    $revisionEnvelope = $response.Content | ConvertFrom-Json
    foreach ($revision in @($revisionEnvelope.revisions)) {
        $response = Invoke-NetOSRequest GET ("/api/revisions/" + [string]$revision.id)
        Assert-NetOSStatus ("revision detail " + $revision.id) $response
        $detail = $response.Content | ConvertFrom-Json
        if ($detail.id -ne $revision.id -or -not $detail.config) { throw "revision detail mismatch for $($revision.id)" }
    }

    $response = Invoke-NetOSRequest GET "/api/backups"
    Assert-NetOSStatus "backup list for range checks" $response
    $backupEnvelope = $response.Content | ConvertFrom-Json
    foreach ($backup in @($backupEnvelope.backups | Select-Object -First 3)) {
        $escapedBackup = [Uri]::EscapeDataString([string]$backup.name)
        $response = Invoke-NetOSRequest GET ("/api/backups/" + $escapedBackup) -Headers @{ Range = "bytes=0-1023" }
        Assert-NetOSStatus ("backup range download " + $backup.name) $response @(206)
        if (-not $response.Content) { throw "backup range download $($backup.name) is empty" }
    }

    $envelopePath = Join-Path $qaTemp "config-envelope.json"
    [IO.File]::WriteAllText($envelopePath, $configEnvelopeJSON, (New-Object Text.UTF8Encoding($false)))
    $configJSON = & node -e "const fs=require('fs'); const value=JSON.parse(fs.readFileSync(process.argv[1],'utf8')); process.stdout.write(JSON.stringify(value.config));" $envelopePath
    if ($LASTEXITCODE -ne 0 -or -not $configJSON) { throw "failed to round-trip configuration through JavaScript" }

    $response = Invoke-NetOSRequest POST "/api/config/validate" $configResponse.config
    Assert-NetOSStatus "validate active configuration" $response
    $validation = $response.Content | ConvertFrom-Json
    if (@($validation.problems | Where-Object { $_.severity -eq "error" }).Count -ne 0) { throw "active configuration has validation errors" }

    $response = Invoke-NetOSRequest PUT "/api/config" -RawJSON $configJSON -Headers @{ "If-Match" = [string]$draftVersion }
    Assert-NetOSStatus "idempotent config save" $response
    $saved = $response.Content | ConvertFrom-Json
    if ($saved.dirty) {
        $diagnostic = Invoke-NetOSRequest POST "/api/config/plan"
        throw "saving the unchanged config created a dirty draft; plan=$($diagnostic.Content)"
    }

    $response = Invoke-NetOSRequest PUT "/api/config" -RawJSON $configJSON -Headers @{ "If-Match" = [string]$draftVersion }
    Assert-NetOSStatus "stale draft version rejected" $response @(409)

    $response = Invoke-NetOSRequest POST "/api/config/plan"
    Assert-NetOSStatus "plan clean configuration" $response
    $plan = $response.Content | ConvertFrom-Json
    if ($null -ne $plan.actions -and @($plan.actions).Count -ne 0) { throw "API plan reports unexpected actions: $($response.Content)" }

    $response = Invoke-NetOSRequest GET "/api/render"
    Assert-NetOSStatus "render artifact list" $response
    $renderList = $response.Content | ConvertFrom-Json
    foreach ($artifact in @($renderList.artifacts)) {
        $escapedID = [Uri]::EscapeDataString([string]$artifact.id)
        $response = Invoke-NetOSRequest GET ("/api/render/" + $escapedID)
        Assert-NetOSStatus ("render " + $artifact.id) $response
        if (-not $response.Content.Trim()) { throw "render $($artifact.id) is empty" }
    }

    $response = Invoke-NetOSRequest POST "/api/logout"
    Assert-NetOSStatus "logout" $response
    $script:csrf = ""
    $response = Invoke-NetOSRequest GET "/api/session"
    Assert-NetOSStatus "logged-out session rejected" $response @(401)

    $results | Format-Table -AutoSize
    "PASS: $($results.Count) live API checks"
} finally {
    if (Test-Path -LiteralPath $qaTemp) {
        Remove-Item -LiteralPath $qaTemp -Recurse -Force
    }
}
