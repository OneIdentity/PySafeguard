[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$BuildId,
    [Parameter(Mandatory=$true)]
    [string]$TagName,
    [Parameter(Mandatory=$true)]
    [string]$IsTagBuild
)

# Read the semantic version from pyproject.toml (single source of truth)
$local:SemanticVersion = (poetry version --short).Trim()
$local:IsTagBuildBool = $IsTagBuild -eq "True" -or $IsTagBuild -eq "true" -or $IsTagBuild -eq "1"

Write-Host "SemanticVersion = $($local:SemanticVersion)"
Write-Host "BuildId = $BuildId"
Write-Host "TagName = $TagName"
Write-Host "IsTagBuild = $($local:IsTagBuildBool)"

if ($local:IsTagBuildBool) {
    # Validate tag format: must be v<major>.<minor>.<patch> with optional pre-release suffix
    if ($TagName -notmatch '^v\d+\.\d+\.\d+') {
        Write-Error "Tag '$TagName' does not match expected format 'v<major>.<minor>.<patch>'. Aborting release build."
        exit 1
    }
    # Tag builds use the tag name as the version, stripping the 'v' prefix
    # e.g. tag "v8.1.0" -> version "8.1.0"
    $local:PackageVersion = $TagName -replace '^v', ''
    Write-Host "Tag build detected, using tag name as version"
}
else {
    # Non-tag builds get a .devN suffix for unique artifact versioning
    $local:BuildNumber = $BuildId % 65534
    $local:PackageVersion = "${local:SemanticVersion}.dev${local:BuildNumber}"
    Write-Host "Dev build, BuildNumber = $($local:BuildNumber)"
}

Write-Host "PackageVersion = $($local:PackageVersion)"

poetry version $local:PackageVersion

# Compute release tag: tag builds reuse the trigger tag; dev builds use non-triggering prefix
if ($local:IsTagBuildBool) {
    $local:ReleaseTag = $TagName
} else {
    $local:ReleaseTag = "dev/v${local:PackageVersion}"
}

Write-Host "ReleaseTag = $($local:ReleaseTag)"

Write-Output "##vso[task.setvariable variable=PackageVersion;]$($local:PackageVersion)"
Write-Output "##vso[task.setvariable variable=ReleaseTag;]$($local:ReleaseTag)"
