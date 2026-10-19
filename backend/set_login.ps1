# Creates or rotates the single prototype login in Secret Manager. Prints the password once; only its hash is stored.
param(
    [string]$Project = "gujar-ai-builder-cup-2026",
    [Parameter(Mandatory)][string]$User,  # no default: keeps the live username out of the public repo
    [string]$Password = ""
)
Set-Location $PSScriptRoot
$env:Path += ";$env:USERPROFILE\sdk\go1.27.2\go\bin"

function New-RandomString([string]$alphabet, [int]$length) {
    $bytes = New-Object byte[] $length
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    -join ($bytes | ForEach-Object { $alphabet[$_ % $alphabet.Length] })
}

if (-not $Password) {
    $a = "abcdefghijklmnopqrstuvwxyz0123456789"
    $Password = (1..3 | ForEach-Object { New-RandomString $a 4 }) -join "-"
}
# Env var, not argv or a pipe: Windows PowerShell prefixes piped stdin with a BOM, which would corrupt the hash.
$env:SV_NEW_PASSWORD = $Password
$hash = go run . hash-password
Remove-Item Env:SV_NEW_PASSWORD
if (-not $hash -or $hash -notlike "pbkdf2_sha256$*") { throw "hashing failed" }

gcloud services enable secretmanager.googleapis.com --project $Project

function Set-Secret([string]$name, [string]$value) {
    $tmp = [IO.Path]::GetTempFileName()
    try {
        [IO.File]::WriteAllText($tmp, $value)  # no trailing newline
        gcloud secrets describe $name --project $Project *> $null
        if ($LASTEXITCODE -ne 0) { gcloud secrets create $name --project $Project --replication-policy=automatic *> $null }
        gcloud secrets versions add $name --project $Project --data-file=$tmp *> $null
    } finally { Remove-Item $tmp -Force }
}

Set-Secret "sv-app-user" $User
Set-Secret "sv-app-password-hash" $hash
gcloud secrets describe sv-session-secret --project $Project *> $null
if ($LASTEXITCODE -ne 0) { Set-Secret "sv-session-secret" (New-RandomString "0123456789abcdef" 64) }

$num = gcloud projects describe $Project --format="value(projectNumber)"
# Per secret, not project-wide: the runtime identity reads only these three.
foreach ($name in "sv-app-user", "sv-app-password-hash", "sv-session-secret") {
    gcloud secrets add-iam-policy-binding $name --project $Project --member="serviceAccount:$num-compute@developer.gserviceaccount.com" `
        --role="roles/secretmanager.secretAccessor" --condition=None *> $null
}

Write-Output "Login set. Username: $User  Password: $Password"
Write-Output "Run deploy.ps1 to apply."
