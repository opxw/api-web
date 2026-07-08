# Copyright (c) 2026 - opx
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot "package"),
    [string]$ProjectPath = (Join-Path $PSScriptRoot "src\Opx.Api.Web.csproj"),
    [string]$VersionPrefix = "",
    [string]$DateReleaseFormat = "yyyyMMdd"
)

$ErrorActionPreference = "Stop"

function Get-NextVersionPrefix {
    param(
        [string]$CurrentVersion
    )

    if ([string]::IsNullOrWhiteSpace($CurrentVersion)) {
        return "1.0.1"
    }

    $match = [regex]::Match($CurrentVersion.Trim(), "^(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)(?:\.\d+)?$")

    if (-not $match.Success) {
        throw "Current project version '$CurrentVersion' must use major.minor.patch format."
    }

    $major = [int]$match.Groups["major"].Value
    $minor = [int]$match.Groups["minor"].Value
    $patch = [int]$match.Groups["patch"].Value + 1

    return "$major.$minor.$patch"
}

function Set-ProjectProperty {
    param(
        [xml]$Project,
        [System.Xml.XmlElement]$PropertyGroup,
        [string]$Name,
        [string]$Value
    )

    $property = $PropertyGroup.SelectSingleNode($Name)

    if ($null -eq $property) {
        $property = $Project.CreateElement($Name)
        [void]$PropertyGroup.AppendChild($property)
    }

    $property.InnerText = $Value
}

function Set-ProjectVersion {
    param(
        [string]$Path,
        [string]$Version,
        [string]$FileVersion
    )

    [xml]$project = Get-Content -Raw -LiteralPath $Path
    $propertyGroup = $project.Project.PropertyGroup | Where-Object { $_.Version } | Select-Object -First 1

    if ($null -eq $propertyGroup) {
        $propertyGroup = $project.Project.PropertyGroup | Select-Object -First 1

        if ($null -eq $propertyGroup) {
            throw "No PropertyGroup found in project file '$Path'."
        }
    }

    Set-ProjectProperty -Project $project -PropertyGroup $propertyGroup -Name "Version" -Value $Version
    Set-ProjectProperty -Project $project -PropertyGroup $propertyGroup -Name "AssemblyVersion" -Value $Version
    Set-ProjectProperty -Project $project -PropertyGroup $propertyGroup -Name "FileVersion" -Value $FileVersion
    Set-ProjectProperty -Project $project -PropertyGroup $propertyGroup -Name "GenerateAssemblyFileVersionAttribute" -Value "false"
    Set-ProjectProperty -Project $project -PropertyGroup $propertyGroup -Name "NoWarn" -Value '$(NoWarn);7035'

    $project.Save($Path)
}

function Set-AssemblyFileVersion {
    param(
        [string]$ProjectPath,
        [string]$FileVersion
    )

    $projectDirectory = Split-Path -Parent $ProjectPath
    $propertiesDirectory = Join-Path $projectDirectory "Properties"
    $assemblyInfoPath = Join-Path $propertiesDirectory "AssemblyInfo.cs"

    New-Item -ItemType Directory -Force -Path $propertiesDirectory | Out-Null
    @"
using System.Reflection;
using System.Runtime.CompilerServices;

[assembly: AssemblyFileVersion("$FileVersion")]
[assembly: InternalsVisibleTo("Opx.Api.Web.Tests")]
"@ | Set-Content -LiteralPath $assemblyInfoPath -Encoding UTF8
}

$resolvedProjectPath = (Resolve-Path -LiteralPath $ProjectPath).Path
[xml]$project = Get-Content -Raw -LiteralPath $resolvedProjectPath
$currentVersion = ($project.Project.PropertyGroup | Where-Object { $_.Version } | Select-Object -First 1).Version

if ([string]::IsNullOrWhiteSpace($VersionPrefix)) {
    $VersionPrefix = Get-NextVersionPrefix -CurrentVersion $currentVersion
}

$dateRelease = Get-Date -Format $DateReleaseFormat
$version = $VersionPrefix
$fileVersion = "$VersionPrefix.$dateRelease"

Set-ProjectVersion -Path $resolvedProjectPath -Version $version -FileVersion $fileVersion
Set-AssemblyFileVersion -ProjectPath $resolvedProjectPath -FileVersion $fileVersion

New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null

dotnet pack $resolvedProjectPath `
    -c Release `
    -p:PackageVersion=$version `
    -p:AssemblyVersion=$version `
    -p:FileVersion=$fileVersion `
    -p:InformationalVersion=$fileVersion `
    -o $OutputPath `
    --nologo

if ($LASTEXITCODE -ne 0) {
    throw "dotnet pack failed with exit code $LASTEXITCODE"
}

Write-Host "Updated project version from '$currentVersion' to '$version'"
Write-Host "Updated file version to '$fileVersion'"
Write-Host "Packed Opx.Api.Web $version to $OutputPath"
