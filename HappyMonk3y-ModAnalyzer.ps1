# happymonk3y Mod Analyzer 1.0
# Static Minecraft JAR inspection. Never loads or executes mod code.
[CmdletBinding()]
param([string]$Path, [string]$ReportDirectory)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression.FileSystem

Write-Host "`nhappymonk3y | Minecraft Mod Analyzer" -ForegroundColor Magenta
Write-Host 'Static indicators only: a renamed, obfuscated, or unknown cheat may be missed.'
if (-not $Path) { $Path = Read-Host 'Paste your mods folder path' }
$Path = $Path.Trim().Trim('"')
$resolvedFolder = Get-Item -LiteralPath $Path -ErrorAction Stop
if (-not $resolvedFolder.PSIsContainer) { throw 'Enter a folder, not a file.' }
if (-not $ReportDirectory) {
    $ReportDirectory = Join-Path $env:TEMP ('happymonk3y-mod-report-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$null = New-Item -ItemType Directory -Path $ReportDirectory -Force

# These identify client families, not whether cheating occurred in-game.
$rules = @(
    @{ Name='Meteor Client'; Pattern='(^|/)(meteordevelopment/meteorclient|meteorclient)(/|$)'; Id='meteor-client' },
    @{ Name='Wurst Client'; Pattern='(^|/)net/wurstclient(/|$)'; Id='wurst' },
    @{ Name='LiquidBounce'; Pattern='(^|/)net/ccbluex/liquidbounce(/|$)'; Id='liquidbounce' },
    @{ Name='Aristois'; Pattern='(^|/)(me/deftware/client|com/aristois)(/|$)'; Id='aristois' },
    @{ Name='Inertia'; Pattern='(^|/)inertia/client(/|$)'; Id='inertia' }
)
$results = [System.Collections.Generic.List[object]]::new()
$files = @(Get-ChildItem -LiteralPath $resolvedFolder.FullName -File -Filter '*.jar' -Recurse)
Write-Host ("Found {0} JAR files. Reports: {1}" -f $files.Count, $ReportDirectory)
foreach ($file in $files) {
    $evidence = [System.Collections.Generic.List[string]]::new()
    $notes = [System.Collections.Generic.List[string]]::new()
    $modIds = [System.Collections.Generic.List[string]]::new()
    $status = 'No listed indicators'
    $archive = $null
    $hash = $null
    try {
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
        if ($file.Length -gt 512MB) { throw 'JAR exceeds the 512 MB inspection limit.' }
        $archive = [IO.Compression.ZipFile]::OpenRead($file.FullName)
        if ($archive.Entries.Count -gt 100000) { throw 'Archive exceeds the 100,000-entry limit.' }
        $names = @($archive.Entries | ForEach-Object { $_.FullName.Replace('\','/') })
        foreach ($rule in $rules) {
            $match = $names | Where-Object { $_ -match $rule.Pattern } | Select-Object -First 1
            if ($match) { $evidence.Add(($rule.Name + ' package: ' + $match)); $status = 'Known-client indicator' }
        }
        foreach ($metadataName in @('fabric.mod.json','quilt.mod.json','META-INF/mods.toml','META-INF/neoforge.mods.toml','mcmod.info')) {
            $entry = $archive.GetEntry($metadataName)
            if (-not $entry) { continue }
            if ($entry.Length -gt 1MB) { $notes.Add("Metadata too large: $metadataName"); continue }
            $stream = $entry.Open()
            $reader = [IO.StreamReader]::new($stream)
            try {
                $buffer = New-Object char[] (1048577)
                $count = $reader.ReadBlock($buffer,0,$buffer.Length)
                if ($count -gt 1048576) { $notes.Add("Metadata read limit: $metadataName"); continue }
                $metadata = -join $buffer[0..([Math]::Max(0,$count-1))]
                if ($metadataName -eq 'fabric.mod.json') {
                    $parsed = $metadata | ConvertFrom-Json
                    if ($parsed.id) { $modIds.Add([string]$parsed.id) }
                } elseif ($metadataName -eq 'quilt.mod.json') {
                    $parsed = $metadata | ConvertFrom-Json
                    if ($parsed.quilt_loader.id) { $modIds.Add([string]$parsed.quilt_loader.id) }
                } elseif ($metadataName -match '\.toml$') {
                    foreach ($idMatch in [regex]::Matches($metadata, '(?m)^\s*modId\s*=\s*["'']([^"'']+)["'']')) {
                        $modIds.Add($idMatch.Groups[1].Value)
                    }
                }
            } catch { $notes.Add("Metadata parse failed: $metadataName") }
            finally { $reader.Dispose(); $stream.Dispose() }
        }
        foreach ($rule in $rules) {
            if ($modIds -contains $rule.Id) { $evidence.Add(($rule.Name + ' mod ID: ' + $rule.Id)); $status = 'Known-client indicator' }
        }
        # Feature names and filenames are weak evidence and need human review.
        $featureMatches = @($names | Where-Object {
            $_ -match '(?i)(^|/)(KillAura|CrystalAura|AimBot|AutoTotem|XRay|Reach|TriggerBot)(Module)?\.class$'
        } | Select-Object -First 8)
        foreach ($feature in $featureMatches) { $evidence.Add('Feature-name indicator (review): ' + $feature) }
        if ($file.BaseName -match '(?i)(^|[-_. ])(meteor|wurst|liquidbounce|aristois|inertia|xray|killaura)([-_. ]|$)') {
            $evidence.Add('Filename indicator only: ' + $file.Name)
        }
        if ($names | Where-Object { $_ -match '(^|/)baritone/' } | Select-Object -First 1) {
            $evidence.Add('Baritone automation component: server rules determine whether allowed')
        }
        if ($status -eq 'No listed indicators' -and $evidence.Count -gt 0) { $status = 'Review needed' }
        $nested = @($names | Where-Object { $_ -match '(?i)\.jar$' })
        if ($nested.Count) { $notes.Add("$($nested.Count) nested JAR(s) not scanned: " + (($nested | Select-Object -First 5) -join ', ')) }
        if ($notes.Count -gt 0 -and $status -eq 'No listed indicators') { $status = 'Incomplete inspection' }
    } catch {
        $notes.Add($_.Exception.Message)
        if ($status -ne 'Known-client indicator') { $status = 'Incomplete inspection' }
    } finally { if ($archive) { $archive.Dispose() } }
    $row = [pscustomobject]@{
        File=$file.Name; FullPath=$file.FullName; Result=$status;
        ModIds=($modIds -join '; '); SHA256=$hash;
        Evidence=($evidence -join ' | '); Notes=($notes -join ' | ')
    }
    $results.Add($row)
    $color = switch ($status) { 'Known-client indicator' {'Red'} 'Review needed' {'Yellow'} 'Incomplete inspection' {'Yellow'} default {'Gray'} }
    # Suppress control characters in filenames before displaying them.
    $displayName = $file.Name -replace '[\x00-\x1F\x7F]', '?'
    Write-Host ("[{0}] {1}" -f $status,$displayName) -ForegroundColor $color
}
$jsonPath = Join-Path $ReportDirectory 'report.json'
$csvPath = Join-Path $ReportDirectory 'report.csv'
ConvertTo-Json -InputObject @($results.ToArray()) -Depth 4 | Set-Content -LiteralPath $jsonPath -Encoding UTF8
# Neutralize spreadsheet formula prefixes in exported text.
$results | Select-Object * | ForEach-Object {
    foreach ($property in $_.PSObject.Properties) {
        if ($property.Value -is [string] -and $property.Value -match '^[=+@\-\t\r]') { $property.Value = "'" + $property.Value }
    }
    $_
} | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
Write-Host "`nFinished. Scanned $($files.Count) JAR(s)." -ForegroundColor Magenta
$results | Group-Object Result | ForEach-Object { Write-Host ("{0}: {1}" -f $_.Name,$_.Count) }
Write-Host "Reports saved to $ReportDirectory"
Write-Host 'No listed indicators does NOT mean cheat-free. No malware analysis or online lookups were performed.'
Write-Host 'Nested JARs, obfuscation, renamed classes, external injectors and unknown clients require further review.'
