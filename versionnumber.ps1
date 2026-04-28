[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$BuildId,
    [Parameter(Mandatory=$true)]
    [bool]$IsPrerelease,
    [Parameter(Mandatory=$true)]
    [string]$TagName,
    [Parameter(Mandatory=$true)]
    [string]$IsTagBuild
)

# Read the semantic version from pyproject.toml (single source of truth)
$local:SemanticVersion = (poetry version --short).Trim()

Write-Host "SemanticVersion = $($local:SemanticVersion)"
Write-Host "BuildId = $BuildId"
Write-Host "IsPrerelease = $IsPrerelease"
Write-Host "TagName = $TagName"
Write-Host "IsTagBuild = $IsTagBuild"

if ($IsTagBuild -eq "true") {
    # Tag builds use the tag name as the version (e.g. tag "8.0.0" -> version "8.0.0")
    $local:PackageVersion = $TagName
    Write-Host "Tag build detected, using tag name as version"
}
elseif ($IsPrerelease) {
    # Prerelease builds get a .devN suffix
    $local:BuildNumber = $BuildId % 65534
    $local:PackageVersion = "${local:SemanticVersion}.dev${local:BuildNumber}"
    Write-Host "Prerelease build, BuildNumber = $($local:BuildNumber)"
}
else {
    $local:PackageVersion = $local:SemanticVersion
}

Write-Host "PackageVersion = $($local:PackageVersion)"

poetry version $local:PackageVersion

Write-Output "##vso[task.setvariable variable=PackageVersion;]$($local:PackageVersion)"
