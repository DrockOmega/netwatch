# Daily ET Open rule refresh for the sensor's Suricata (SYSTEM task SuricataRulesUpdate).
# Downloads the ruleset, tests it against the live suricata.yaml with `suricata -T`, keeps the
# previous rules in rules.prev, swaps the files in and restarts the service (Suricata for Windows
# has no live reload). Rollback: Copy-Item rules.prev\* rules\ -Force; Restart-Service Suricata
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$base = 'C:\ProgramData\NetWatch\suricata'
$exe = 'C:\Program Files\Suricata\suricata.exe'
$url = 'https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz'
$work = Join-Path $base 'rules-update'
$log = Join-Path $base 'rules-update.log'
function Say($m) { "$(Get-Date -Format s) $m" | Add-Content $log }
try {
    if (Test-Path $work) { Remove-Item $work -Recurse -Force }
    New-Item -ItemType Directory $work | Out-Null
    Invoke-WebRequest -UseBasicParsing $url -OutFile "$work\et.tgz"
    tar -xzf "$work\et.tgz" -C $work
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path "$work\rules\emerging-malware.rules")) { throw 'archive did not unpack' }
    # This Suricata for Windows build has no libmagic: rules using file.magic fail to parse (disabled by hand 2026-10-09).
    foreach ($f in Get-ChildItem "$work\rules\*.rules") {
        $lines = [IO.File]::ReadAllLines($f.FullName)
        $hit = $false
        for ($i = 0; $i -lt $lines.Length; $i++) {
            if ($lines[$i] -match '^alert .*\bfile\.magic;') { $lines[$i] = '#' + $lines[$i]; $hit = $true }
        }
        if ($hit) { [IO.File]::WriteAllLines($f.FullName, $lines) }
    }
    $ErrorActionPreference = 'Continue'  # PowerShell 5.1 turns a native program's stderr into a terminating error
    & $exe -T -v -c "$base\suricata.yaml" --set "default-rule-path=$work\rules" -l $work *> "$work\test.txt"
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    $loaded = Select-String -Path "$work\test.txt" -Pattern 'rules successfully loaded, (\d+) rules failed' | Select -Last 1
    if ($code -ne 0 -or -not $loaded -or $loaded.Matches[0].Groups[1].Value -ne '0') {
        throw "suricata -T failed (exit $code, $($loaded.Line)); see $work\test.txt"
    }
    if (Test-Path "$base\rules.prev") { Remove-Item "$base\rules.prev" -Recurse -Force }
    Copy-Item "$base\rules" "$base\rules.prev" -Recurse
    Copy-Item "$work\rules\*" "$base\rules\" -Force
    Restart-Service Suricata
    Say "rules updated ($($loaded.Line.Trim())); Suricata restarted"
} catch {
    Say "FAILED: $_"
    exit 1
}
