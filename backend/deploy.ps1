# Deploys the API + web app to Cloud Run. Gemini runs through Vertex AI with the service's own identity (no API key).
param(
    [string]$Project = "gujar-ai-builder-cup-2026",
    [string]$Region = "asia-south1",
    [string]$Service = "dhaal",
    [switch]$WithWebRisk
)
# Not "Stop": Windows PowerShell turns gcloud's normal stderr progress into terminating errors.
$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot

gcloud config set project $Project
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com aiplatform.googleapis.com

$num = gcloud projects describe $Project --format="value(projectNumber)"
$sa = "$num-compute@developer.gserviceaccount.com"
# New projects give the default compute identity no roles: it needs to build (source deploy) and call Vertex AI.
foreach ($role in "roles/run.builder", "roles/aiplatform.user") {
    gcloud projects add-iam-policy-binding $Project --member="serviceAccount:$sa" --role=$role --condition=None | Out-Null
}

$envVars = "GOOGLE_GENAI_USE_VERTEXAI=true,GOOGLE_CLOUD_PROJECT=$Project,GOOGLE_CLOUD_LOCATION=global"
if ($WithWebRisk) {
    gcloud services enable webrisk.googleapis.com apikeys.googleapis.com
    $key = gcloud services api-keys create --display-name="dhaal-webrisk" --api-target=service=webrisk.googleapis.com --format="value(response.keyString)"
    $envVars += ",WEBRISK_API_KEY=$key"
}

# Login secrets (created by set_login.ps1); without them the service runs open.
$secretArgs = @()
gcloud secrets describe sv-app-password-hash --project $Project *> $null
if ($LASTEXITCODE -eq 0) {
    $secretArgs = @("--set-secrets", "APP_USER=sv-app-user:latest,APP_PASSWORD_HASH=sv-app-password-hash:latest,SESSION_SECRET=sv-session-secret:latest")
}

gcloud run deploy $Service --source . --region $Region --allow-unauthenticated `
    --memory 1Gi --cpu 1 --timeout 120 --concurrency 20 --max-instances 5 `
    --set-env-vars $envVars @secretArgs

gcloud run services describe $Service --region $Region --format="value(status.url)"
