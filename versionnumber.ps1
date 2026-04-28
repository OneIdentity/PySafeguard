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
    # Tag builds use the tag name as the version (e.g. tag "8.0.0" -> version "8.0.0")
    $local:PackageVersion = $TagName
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

Write-Output "##vso[task.setvariable variable=PackageVersion;]$($local:PackageVersion)"
