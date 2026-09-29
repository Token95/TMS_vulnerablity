#Requires -Version 5.1
<#
.SYNOPSIS
    TMS Internal - Monthly Vulnerability Remediation Report (CVE / CVSS / CWE / CISA KEV).

.DESCRIPTION
    Reads vulnerability exports (CSV) from Nessus, CrowdStrike Falcon Spotlight,
    Blumira and GitHub CodeQL (Security overview export). Each file's source is
    detected automatically from its file name and
    columns, so any mix of files and folders can be passed in one run.

    Every finding is normalized and enriched from four public sources:
        NIST NVD 2.0 API    CVSS base score / vector and the CVE -> CWE mapping
        CIRCL CVE API       Description, vendor solution text, CISA SSVC data
        MITRE CWE REST API  Weakness name, description and potential mitigations
        CISA KEV catalog    Known-exploited status, required action, due date

    The script then decides whether each finding affects the current network
    (status open, host in scope, seen recently), applies the TMS remediation SLA
    (Critical 30 / High 60 / Medium 90 / Low 180 days, CISA KEV held to the
    Critical window), merges hosts and users that share the same vulnerability
    and the same fix, and writes a meeting-ready PDF report plus CSV exports.

.PARAMETER Path
    CSV files, folders, or wildcard paths. Accepts several values and pipeline
    input. When omitted, a file picker (Windows) or a prompt is shown.

.PARAMETER Recurse
    Search sub-folders when a folder is passed to -Path.

.PARAMETER OutputFolder
    Where reports, CSV exports and operator.log are written. Default: .\Reports

.PARAMETER ReportDate
    The "as of" date for SLA math. Default: today.

.PARAMETER Offline
    Make no network calls; use cached API data and the scanner's own data only.

.PARAMETER SkipDns
    Do not look up host names for IP addresses on the domain controllers.

.PARAMETER DnsServer
    Domain controller(s) / DNS server(s) to query, e.g. -DnsServer DC01,DC02.
    Overrides DnsServers in settings.psd1. Default: the domain's DCs, found automatically.

.PARAMETER KeepHtml
    Also keep the HTML version of the report next to the PDF.

.PARAMETER BrowserPath
    Full path to msedge.exe or chrome.exe, if Edge is not in its default location.
    The PDF is rendered by Edge/Chrome running headless (nothing is shown on screen).

.EXAMPLE
    .\TMS-VulnReport.ps1 -Path .\exports\nessus.csv, .\exports\spotlight.csv

.EXAMPLE
    .\TMS-VulnReport.ps1 -Path \\fileserver\SecOps\September -Recurse

.EXAMPLE
    Get-ChildItem .\exports -Filter *.csv | .\TMS-VulnReport.ps1

.EXAMPLE
    .\TMS-VulnReport.ps1 -Path .\Reports\TMS_Vulnerability_Report_2026-09_20260929-1148_ActionPlan.xlsx

    A filled-in Action Plan workbook (file name contains "ActionPlan") gets its own
    Remediation Status report: owners, status, target dates against the SLA dates.

.NOTES
    Author  : Devon Brown, Network Security Engineer
    Owner   : TMS (Times Microwave Systems) Internal
    Version : 3.5.0
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('FullName', 'File', 'Folder')]
    [string[]]$Path,

    [switch]$Recurse,
    [string]$OutputFolder,
    [string]$SettingsPath,
    [datetime]$ReportDate = (Get-Date),
    [switch]$Offline,
    [switch]$SkipNvd,
    [switch]$SkipCircl,
    [switch]$SkipCwe,
    [switch]$SkipDns,
    [string[]]$DnsServer,
    [switch]$IncludeInformational,
    [switch]$KeepHtml,
    [string]$BrowserPath,
    [switch]$NoOpen
)

begin {
    $ErrorActionPreference = 'Stop'
    $ScriptVersion = '3.6.0'
    $ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    if (-not $OutputFolder) { $OutputFolder = Join-Path $ScriptRoot 'Reports' }
    if (-not $SettingsPath) { $SettingsPath = Join-Path $ScriptRoot 'settings.psd1' }
    $CollectedPaths = New-Object System.Collections.Generic.List[string]

    # Windows PowerShell 5.1 defaults to TLS 1.0 - the APIs require TLS 1.2+
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }

    # ==================================================================
    #  LOGGING + CONSOLE STATUS
    # ==================================================================
    $script:LogFile = $null

    function Write-Log {
        param([string]$Level, [string]$Message)
        if (-not $script:LogFile) { return }
        $line = '{0} - {1} - {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch { }
    }
    function Write-Info { param([string]$m) Write-Host '[*] ' -ForegroundColor Cyan -NoNewline; Write-Host $m; Write-Log 'INFO' $m }
    function Write-Good { param([string]$m) Write-Host '[+] ' -ForegroundColor Green -NoNewline; Write-Host $m; Write-Log 'INFO' $m }
    function Write-Bad { param([string]$m) Write-Host '[-] ' -ForegroundColor Red -NoNewline; Write-Host $m; Write-Log 'WARN' $m }
    function Write-Rule { param([int]$Width = 64) Write-Host ('-' * $Width) -ForegroundColor DarkGray }

    function Show-Banner {
        param($Cfg)
        try { Clear-Host } catch { }
        $bar = '=' * 64
        Write-Host ''
        Write-Host $bar -ForegroundColor Cyan
        Write-Host '   TTTTTTT  M     M   SSSSS' -ForegroundColor Cyan
        Write-Host '      T     MM   MM  S     ' -ForegroundColor Cyan
        Write-Host '      T     M M M M   SSSS ' -ForegroundColor Cyan
        Write-Host '      T     M  M  M       S' -ForegroundColor Cyan
        Write-Host '      T     M     M  SSSSS ' -ForegroundColor Cyan
        Write-Host ''
        Write-Host ('   {0}' -f $Cfg.Organization) -ForegroundColor White
        Write-Host ('   {0}  |  v{1}' -f $Cfg.ReportTitle, $ScriptVersion) -ForegroundColor Gray
        Write-Host ('   {0}, {1}' -f $Cfg.PreparedBy, $Cfg.PreparedByTitle) -ForegroundColor Gray
        Write-Host $bar -ForegroundColor Cyan
        Write-Host ''
    }

    # ==================================================================
    #  SETTINGS
    # ==================================================================
    function Merge-Hashtable {
        param([hashtable]$Base, [hashtable]$Override)
        $out = @{}
        foreach ($k in $Base.Keys) { $out[$k] = $Base[$k] }
        foreach ($k in $Override.Keys) {
            if ($out[$k] -is [hashtable] -and $Override[$k] -is [hashtable]) {
                $out[$k] = Merge-Hashtable $out[$k] $Override[$k]
            } else { $out[$k] = $Override[$k] }
        }
        return $out
    }

    function Import-TmsSettings {
        param([string]$File)
        $defaults = @{
            Organization = 'TMS (Times Microwave Systems) Internal'
            ReportTitle = 'Monthly Vulnerability Remediation Report'
            PreparedBy = 'Devon Brown'
            PreparedByTitle = 'Network Security Engineer'
            LogoFile = 'TMS_Logo.png'
            Api = @{
                NvdUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='
                NvdApiKey = ''
                CirclUrl = 'https://cve.circl.lu/api/cve/'
                KevUrl = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
                CweUrl = 'https://cwe-api.mitre.org/api/v1/cwe/weakness/'
            }
            RemediationSlaDays = @{ Critical = 30; High = 60; Medium = 90; Low = 180 }
            KevEscalatesToCritical = $true
            CisaImmediateDays = 3
            Thresholds = @{ Critical = 9.0; High = 7.0; Medium = 4.0; Low = 0.1 }
            InScopeNetworks = @(); InScopeHostPatterns = @()
            InternetFacingNetworks = @(); InternetFacingHostPatterns = @()
            StaleAfterDays = 30
            CodeQLRepositoryName = ''
            CacheHours = @{ Kev = 24; Nvd = 168; Circl = 168; Cwe = 720 }
            NvdDelaySeconds = @{ WithKey = 0.7; WithoutKey = 6.5 }
            MaxHostsShownPerRow = 40
            RemediationFilePatterns = @('*ActionPlan*', '*Action_Plan*', '*Action Plan*', '*Action-Plan*')
            ResolveIpsWithDns = $true
            DnsServers = @()
            DnsShortNames = $true
        }
        if (Test-Path -LiteralPath $File) {
            try {
                $user = Import-PowerShellDataFile -LiteralPath $File
                return (Merge-Hashtable $defaults $user)
            } catch {
                Write-Host "[-] Could not read settings file '$File': $($_.Exception.Message). Using defaults." -ForegroundColor Red
            }
        }
        return $defaults
    }

    # ==================================================================
    #  INPUT FILE RESOLUTION
    # ==================================================================
    function Select-CsvInteractively {
        $onWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ($IsWindows -eq $true)
        $isSta = [System.Threading.Thread]::CurrentThread.GetApartmentState() -eq 'STA'
        if ($onWindows -and $isSta) {
            try {
                Add-Type -AssemblyName System.Windows.Forms
                $dlg = New-Object System.Windows.Forms.OpenFileDialog
                $dlg.Title = 'Select vulnerability exports (Nessus, CrowdStrike, Blumira, CodeQL) and Action Plan workbooks'
                $dlg.Filter = 'Exports and workbooks (*.csv;*.xlsx;*.xlsm)|*.csv;*.xlsx;*.xlsm|CSV files (*.csv)|*.csv|Excel workbooks (*.xlsx;*.xlsm)|*.xlsx;*.xlsm|All files (*.*)|*.*'
                $dlg.Multiselect = $true
                if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $dlg.FileNames }
                return @()
            } catch { }
        }
        Write-Host ''
        Write-Host 'Enter one or more CSV files or folders. Separate multiple paths with ";".' -ForegroundColor Yellow
        $answer = Read-Host 'Path(s)'
        return @($answer -split ';' | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ })
    }

    function Resolve-InputCsv {
        param([string[]]$Paths, [switch]$Recurse)
        $files = New-Object System.Collections.Generic.List[string]
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        # "a.csv,b.csv" arrives as one string from cmd.exe / Task Scheduler - split it
        $expanded = foreach ($p in $Paths) {
            if (-not $p) { continue }
            $t = $p.Trim().Trim('"')
            if (-not (Test-Path -LiteralPath $t) -and $t -match '[,;]') { $t -split '[,;]' | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ } }
            else { $t }
        }
        foreach ($p in @($expanded)) {
            if (-not $p) { continue }
            $items = @()
            try {
                if (Test-Path -LiteralPath $p) { $items = @(Get-Item -LiteralPath $p) }
                else { $items = @(Get-Item -Path $p -ErrorAction Stop) }   # wildcard support
                if (-not $items.Count) { Write-Bad "No files match: $p"; continue }
            } catch {
                Write-Bad "Path not found: $p"
                continue
            }
            foreach ($it in $items) {
                if ($it.PSIsContainer) {
                    $found = if ($Recurse) { Get-ChildItem -LiteralPath $it.FullName -File -Recurse }
                             else { Get-ChildItem -LiteralPath $it.FullName -File }
                    $found = @($found | Where-Object { $_.Extension -in '.csv', '.xlsx', '.xlsm' -and $_.Name -notlike '~$*' })
                    foreach ($f in $found) { if ($seen.Add($f.FullName)) { $files.Add($f.FullName) } }
                } elseif ($it.Extension -in '.csv', '.txt', '.xlsx', '.xlsm') {
                    if ($seen.Add($it.FullName)) { $files.Add($it.FullName) }
                } else {
                    Write-Bad "Skipping unsupported file type: $($it.FullName)"
                }
            }
        }
        return $files.ToArray()
    }

    # ==================================================================
    #  GENERIC HELPERS
    # ==================================================================
    function New-ColumnMap {
        param([string[]]$Headers)
        $map = @{}
        foreach ($h in $Headers) {
            if ($null -eq $h) { continue }
            $k = ($h -replace '^\uFEFF', '').Trim().ToLowerInvariant()
            if (-not $map.ContainsKey($k)) { $map[$k] = $h }
            $squash = $k -replace '[^a-z0-9]', ''            # "created_at" and "Created At" both -> "createdat"
            if ($squash -and -not $map.ContainsKey("~$squash")) { $map["~$squash"] = $h }
        }
        return $map
    }

    function Get-Col {
        param($Row, [hashtable]$Map, [string[]]$Names)
        foreach ($n in $Names) {
            $actual = $Map[$n]
            if (-not $actual) { $actual = $Map['~' + ($n.ToLowerInvariant() -replace '[^a-z0-9]', '')] }
            if ($actual) {
                $v = $Row.$actual
                if ($null -ne $v) {
                    $s = "$v".Trim()
                    if ($s -ne '' -and $s -ne '-' -and $s -ine 'n/a' -and $s -ine 'null') { return $s }
                }
            }
        }
        return ''
    }

    function ConvertTo-DateOrNull {
        param([string]$Text)
        if (-not $Text) { return $null }
        $t = ($Text -replace '\s+\(?[A-Z]{2,5}\)?$', '').Trim()      # strip "EDT", "UTC" etc.
        $d = [datetime]::MinValue
        $styles = [Globalization.DateTimeStyles]::AllowWhiteSpaces
        if ([datetime]::TryParse($t, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
        if ([datetime]::TryParse($t, [Globalization.CultureInfo]::CurrentCulture, $styles, [ref]$d)) { return $d }
        $epoch = 0L
        if ([long]::TryParse($t, [ref]$epoch) -and $epoch -gt 946684800) {
            if ($epoch -gt 100000000000) { $epoch = [long]($epoch / 1000) }
            return [DateTimeOffset]::FromUnixTimeSeconds($epoch).LocalDateTime
        }
        return $null
    }

    function ConvertTo-ScoreOrNull {
        param([string]$Text)
        if (-not $Text) { return $null }
        $m = [regex]::Match($Text, '\d+(\.\d+)?')
        if (-not $m.Success) { return $null }
        $v = [double]::Parse($m.Value, [Globalization.CultureInfo]::InvariantCulture)
        if ($v -lt 0 -or $v -gt 10) { return $null }
        return $v
    }

    function Get-CveList {
        param([string]$Text)
        if (-not $Text) { return @() }
        $list = New-Object System.Collections.Generic.List[string]
        foreach ($m in [regex]::Matches($Text, '(?i)CVE-\d{4}-\d{4,}')) {
            $id = $m.Value.ToUpperInvariant()
            if (-not $list.Contains($id)) { $list.Add($id) }
        }
        return $list.ToArray()
    }

    function Get-CweList {
        param([string]$Text)
        if (-not $Text) { return @() }
        $list = New-Object System.Collections.Generic.List[string]
        foreach ($m in [regex]::Matches($Text, '(?i)CWE[-_ ]?(\d{1,5})')) {
            $id = 'CWE-' + [int]$m.Groups[1].Value
            if (-not $list.Contains($id)) { $list.Add($id) }
        }
        return $list.ToArray()
    }

    function Get-SeverityRank {
        param([string]$Severity)
        switch ($Severity) { 'Critical' { 4 } 'High' { 3 } 'Medium' { 2 } 'Low' { 1 } default { 0 } }
    }

    function Get-SeverityFromScore {
        param($Score, $Thresholds)
        if ($null -eq $Score) { return $null }
        if ($Score -ge $Thresholds.Critical) { return 'Critical' }
        if ($Score -ge $Thresholds.High) { return 'High' }
        if ($Score -ge $Thresholds.Medium) { return 'Medium' }
        $lowMin = if ($null -ne $Thresholds.Low) { [double]$Thresholds.Low } else { 0.1 }
        if ($Score -ge $lowMin) { return 'Low' }
        return 'Info'
    }

    function ConvertTo-SeverityWord {
        param([string]$Text)
        switch -Regex ($Text) {
            '(?i)^\s*(critical|crit|urgent|emergency)' { return 'Critical' }
            '(?i)^\s*(high|important|severe)' { return 'High' }
            '(?i)^\s*(medium|moderate|med)' { return 'Medium' }
            '(?i)^\s*(low|minor)' { return 'Low' }
            default { return '' }
        }
    }

    function Test-IsIPv4 {
        param([string]$Text)
        $ip = $null
        return ([Net.IPAddress]::TryParse($Text, [ref]$ip) -and $ip.AddressFamily -eq 'InterNetwork' -and $Text -match '^\d{1,3}(\.\d{1,3}){3}$')
    }

    function New-Finding {
        param([hashtable]$P)
        $f = [ordered]@{
            Source = ''; SourceFile = ''; VulnId = ''; Cve = ''; Cwes = @(); Title = ''
            Host = ''; IP = ''; User = ''; Port = ''; Protocol = ''; Location = ''; Product = ''
            SourceSeverity = ''; SourceScore = $null; SourceSolution = ''; Description = ''
            Status = ''; FirstSeen = $null; LastSeen = $null; PluginId = ''; Exploit = ''
            # enrichment
            Cvss = $null; CvssVersion = ''; CvssVector = ''; Severity = ''; SeverityRank = 0
            CweNames = ''; IsKev = $false; KevDueDate = ''; KevAction = ''; KevRansomware = ''
            SsvcExploitation = ''; SsvcAutomatable = ''; SsvcTechnicalImpact = ''
            InternetFacing = $false
            Remediation = ''; RemediationSource = ''; RemediationKey = ''
            AffectsNetwork = $true; AffectsReason = ''
            SlaTier = ''; SlaDays = $null; BaseDate = $null; DueDate = $null; DaysRemaining = $null
            SlaStatus = ''; IsNew = $false; HostLabel = ''; DisplayName = ''
        }
        foreach ($k in $P.Keys) { $f[$k] = $P[$k] }
        return [pscustomobject]$f
    }

    # ==================================================================
    #  SOURCE DETECTION
    # ==================================================================
    $script:CodeQLHeader = 'Name', 'Description', 'Severity', 'Message', 'Path', 'StartLine', 'StartColumn', 'EndLine', 'EndColumn'

    function Get-CsvSourceType {
        param([string]$File)
        $firstLine = Get-Content -LiteralPath $File -TotalCount 1 -ErrorAction Stop
        if (-not $firstLine) { return 'Empty' }
        $cells = @(($firstLine | ConvertFrom-Csv -Header (1..60 | ForEach-Object { "c$_" })).PSObject.Properties |
                   Where-Object { $null -ne $_.Value } | ForEach-Object { "$($_.Value)".Trim() })
        $h = @($cells | ForEach-Object { ($_ -replace '^\uFEFF', '').ToLowerInvariant() })
        $name = [IO.Path]::GetFileName($File).ToLowerInvariant()
        $sq = @($h | ForEach-Object { $_ -replace '[^a-z0-9]', '' })

        # GitHub organization Security overview export:
        #   organization_security_overview_alerts_<ORG>_<yyyy-MM-ddTHHhMMmSS...>.csv
        if ($name -match '^(organization|enterprise)_security_overview' -or $name -match 'security_overview_alerts') { return 'GitHub' }
        if (($sq -match '^repo(sitory)?(name|fullname)?$') -and
            ($sq -match '^(tool|toolname|alerttype|alertnumber|alerturl|htmlurl|securityseverity|securityseveritylevel|secrettype|ghsaid)$')) { return 'GitHub' }

        # CodeQL CLI "--format=csv" has no header row: rule, description, severity, message, path, lines...
        if ($cells.Count -ge 9 -and $cells[2] -match '^(error|warning|recommendation|note)$' -and $cells[5] -match '^\d+$') { return 'CodeQL' }
        if (($h -contains 'rule' -or $h -contains 'rule id' -or $h -contains 'query') -and ($h -contains 'path' -or $h -contains 'file') -and ($h -contains 'start line' -or $h -contains 'line')) { return 'CodeQL' }

        if ($h -contains 'plugin id' -or ($h -contains 'plugin' -and $h -contains 'plugin name')) { return 'Nessus' }

        if (($h | Where-Object { $_ -match 'exprt|exploit status|spotlight|falcon|sensor|\baid\b' }) -or
            (($h -contains 'hostname') -and ($h -contains 'cve id') -and ($h | Where-Object { $_ -match 'remediation|vulnerable product|product|local ip' }))) { return 'CrowdStrike' }

        if (($h -contains 'priority') -and ($h | Where-Object { $_ -match 'finding|analysis|workflow|blumira|detector|evidence' })) { return 'Blumira' }

        if ($name -match 'nessus|tenable') { return 'Nessus' }
        if ($name -match 'crowdstrike|falcon|spotlight') { return 'CrowdStrike' }
        if ($name -match 'blumira') { return 'Blumira' }
        if ($name -match 'codeql|code-scanning|sarif') { return 'CodeQL' }

        if ($h | Where-Object { $_ -match 'cve' }) { return 'Generic' }
        return 'Unknown'
    }

    # ==================================================================
    #  PARSERS  (one per source - all return normalized findings)
    # ==================================================================
    function Read-NessusCsv {
        param([string]$File)
        $rows = @(Import-Csv -LiteralPath $File)
        if (-not $rows.Count) { return @() }
        $map = New-ColumnMap $rows[0].PSObject.Properties.Name
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($r in $rows) {
            $risk = Get-Col $r $map 'risk', 'risk factor', 'severity'
            $sev = switch -Regex ($risk) {
                '(?i)^(critical|4)$' { 'Critical' } '(?i)^(high|3)$' { 'High' }
                '(?i)^(medium|2)$' { 'Medium' } '(?i)^(low|1)$' { 'Low' } default { 'Info' }
            }
            $hostCol = Get-Col $r $map 'host', 'asset'
            $ip = Get-Col $r $map 'ip address', 'ip', 'host ip', 'ipv4'
            $name = Get-Col $r $map 'dns name', 'fqdn', 'netbios name', 'host name', 'hostname'
            if ($hostCol) { if (-not $ip -and (Test-IsIPv4 $hostCol)) { $ip = $hostCol } elseif (-not $name) { $name = $hostCol } }
            $plugin = Get-Col $r $map 'plugin id', 'plugin'
            $title = Get-Col $r $map 'name', 'plugin name', 'vulnerability name'
            $score = ConvertTo-ScoreOrNull (Get-Col $r $map 'cvss v3.1 base score', 'cvss v3.0 base score', 'cvss v3 base score', 'cvssv3 base score', 'cvss v4.0 base score', 'cvss v2.0 base score', 'cvss v2 base score', 'cvss')
            $synopsis = Get-Col $r $map 'synopsis'
            $desc = Get-Col $r $map 'description'
            if ($synopsis -and $desc) { $desc = "$synopsis $desc" } elseif ($synopsis) { $desc = $synopsis }
            $common = @{
                Source = 'Nessus'; SourceFile = $File; Title = $title; Host = $name; IP = $ip
                Port = Get-Col $r $map 'port'; Protocol = Get-Col $r $map 'protocol'
                SourceSeverity = $sev; SourceScore = $score
                SourceSolution = Get-Col $r $map 'solution', 'steps to remediate', 'recommended solution'
                Description = $desc; PluginId = $plugin
                Status = Get-Col $r $map 'state', 'status', 'vulnerability state', 'mitigation status'
                FirstSeen = ConvertTo-DateOrNull (Get-Col $r $map 'first discovered', 'first seen', 'first found')
                LastSeen = ConvertTo-DateOrNull (Get-Col $r $map 'last observed', 'last seen', 'last found')
                Exploit = Get-Col $r $map 'exploit?', 'exploit available', 'exploitability ease'
                Cwes = @(Get-CweList (Get-Col $r $map 'cwe', 'cwes'))
            }
            $cves = @(Get-CveList (Get-Col $r $map 'cve', 'cves', 'cve id'))
            if ($cves.Count) {
                foreach ($c in $cves) { $p = $common.Clone(); $p.Cve = $c; $p.VulnId = $c; $out.Add((New-Finding $p)) }
            } else {
                $p = $common.Clone(); $p.VulnId = if ($plugin) { "Nessus $plugin" } else { "Nessus: $title" }
                $out.Add((New-Finding $p))
            }
        }
        return $out.ToArray()
    }

    function Read-CrowdStrikeCsv {
        param([string]$File)
        $rows = @(Import-Csv -LiteralPath $File)
        if (-not $rows.Count) { return @() }
        $map = New-ColumnMap $rows[0].PSObject.Properties.Name
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($r in $rows) {
            $sevText = Get-Col $r $map 'severity', 'cve severity', 'vulnerability severity', 'cvss severity'
            $sev = ConvertTo-SeverityWord $sevText
            if (-not $sev) { $sev = 'Info' }
            $product = Get-Col $r $map 'vulnerable product', 'product', 'product name', 'application', 'vulnerable app', 'app name'
            $prodVer = Get-Col $r $map 'product version', 'version', 'app version'
            if ($prodVer -and $product -and $product -notmatch [regex]::Escape($prodVer)) { $product = "$product $prodVer" }
            $common = @{
                Source = 'CrowdStrike'; SourceFile = $File
                Host = Get-Col $r $map 'hostname', 'host name', 'host', 'device name', 'computer name'
                IP = Get-Col $r $map 'local ip', 'local ip address', 'ip address', 'ip', 'external ip'
                User = Get-Col $r $map 'last logged in user', 'last user', 'user', 'username', 'user name'
                Product = $product
                Title = Get-Col $r $map 'vulnerability name', 'name', 'title'
                SourceSeverity = $sev
                SourceScore = ConvertTo-ScoreOrNull (Get-Col $r $map 'base score', 'cvss base score', 'cvss score', 'cvss v3 base score', 'score')
                SourceSolution = Get-Col $r $map 'remediation', 'recommended remediations', 'recommended remediation', 'remediation details', 'remediation action', 'remediations', 'fix'
                Description = Get-Col $r $map 'cve description', 'description', 'vulnerability description'
                Status = Get-Col $r $map 'status', 'state', 'remediation status'
                FirstSeen = ConvertTo-DateOrNull (Get-Col $r $map 'created date', 'created', 'opened', 'first seen', 'created on', 'open date', 'date opened')
                LastSeen = ConvertTo-DateOrNull (Get-Col $r $map 'last seen', 'last seen date', 'updated date', 'last updated', 'updated', 'last observed')
                Exploit = Get-Col $r $map 'exploit status', 'exprt rating', 'exprt', 'exploitability'
                Cwes = @(Get-CweList (Get-Col $r $map 'cwe', 'cwes', 'cwe id'))
            }
            $cves = @(Get-CveList (Get-Col $r $map 'cve id', 'cve', 'cves', 'vulnerability id'))
            if ($cves.Count) {
                foreach ($c in $cves) {
                    $p = $common.Clone(); $p.Cve = $c; $p.VulnId = $c
                    if (-not $p.Title) { $p.Title = if ($product) { "$c in $product" } else { $c } }
                    $out.Add((New-Finding $p))
                }
            } else {
                $p = $common.Clone()
                $p.VulnId = if ($common.Title) { "CrowdStrike: $($common.Title)" } else { "CrowdStrike: $product" }
                $out.Add((New-Finding $p))
            }
        }
        return $out.ToArray()
    }

    function Read-BlumiraCsv {
        param([string]$File)
        $rows = @(Import-Csv -LiteralPath $File)
        if (-not $rows.Count) { return @() }
        $map = New-ColumnMap $rows[0].PSObject.Properties.Name
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($r in $rows) {
            $prio = Get-Col $r $map 'priority', 'severity', 'risk'
            $sev = switch -Regex ($prio) {
                '(?i)^\s*(p\s*)?(priority\s*)?1\b' { 'Critical' }
                '(?i)^\s*(p\s*)?(priority\s*)?2\b' { 'High' }
                '(?i)^\s*(p\s*)?(priority\s*)?3\b' { 'Medium' }
                '(?i)^\s*(p\s*)?(priority\s*)?[45]\b' { 'Low' }
                default { ConvertTo-SeverityWord $prio }
            }
            if (-not $sev) { $sev = 'Medium' }
            $title = Get-Col $r $map 'name', 'finding name', 'finding', 'title', 'detection', 'rule name'
            $analysis = Get-Col $r $map 'analysis', 'description', 'summary', 'details', 'evidence'
            $common = @{
                Source = 'Blumira'; SourceFile = $File; Title = $title
                Host = Get-Col $r $map 'hostname', 'host', 'device', 'device name', 'source hostname', 'src host', 'endpoint', 'computer', 'destination hostname'
                IP = Get-Col $r $map 'source ip', 'src ip', 'ip', 'ip address', 'src_ip', 'destination ip', 'dst ip'
                User = Get-Col $r $map 'username', 'user', 'user name', 'account', 'src user', 'target user', 'user_name'
                SourceSeverity = $sev
                SourceSolution = Get-Col $r $map 'workflow', 'recommendation', 'recommended action', 'remediation', 'next steps', 'response'
                Description = $analysis
                Status = Get-Col $r $map 'status', 'state', 'resolution'
                FirstSeen = ConvertTo-DateOrNull (Get-Col $r $map 'created', 'created at', 'created date', 'first seen', 'date', 'timestamp')
                LastSeen = ConvertTo-DateOrNull (Get-Col $r $map 'last seen', 'last activity', 'last observed')
                PluginId = Get-Col $r $map 'finding id', 'id', 'short id'
                Cwes = @(Get-CweList "$title $analysis")
            }
            $cves = @(Get-CveList "$title $analysis $(Get-Col $r $map 'cve', 'cves')")
            if ($cves.Count) {
                foreach ($c in $cves) { $p = $common.Clone(); $p.Cve = $c; $p.VulnId = $c; $out.Add((New-Finding $p)) }
            } else {
                $p = $common.Clone(); $p.VulnId = "Blumira: $title"
                $out.Add((New-Finding $p))
            }
        }
        return $out.ToArray()
    }

    # CodeQL's CSV does not carry the query's CWE tags, so the most common
    # security queries are mapped here. Anything with "CWE-nnn" in its text
    # is picked up automatically as well.
    $script:CodeQLCweMap = [ordered]@{
        'sql query built from'                    = 'CWE-89'
        'database query built from'               = 'CWE-89'
        'nosql'                                   = 'CWE-943'
        'uncontrolled command line'               = 'CWE-78'
        'command injection'                       = 'CWE-78'
        'shell command built from'                = 'CWE-78'
        'cross-site scripting'                    = 'CWE-79'
        'dom text reinterpreted as html'          = 'CWE-79'
        'path expression'                         = 'CWE-22'
        'path injection'                          = 'CWE-22'
        'zip slip'                                = 'CWE-22'
        'code injection'                          = 'CWE-94'
        'deserialization'                         = 'CWE-502'
        'server-side request forgery'             = 'CWE-918'
        'clear-text logging'                      = 'CWE-312'
        'clear-text storage'                      = 'CWE-312'
        'cleartext'                               = 'CWE-319'
        'hard-coded credential'                   = 'CWE-798'
        'hardcoded credential'                    = 'CWE-798'
        'broken or weak cryptographic'            = 'CWE-327'
        'insecure ssl/tls'                        = 'CWE-327'
        'weak cryptographic key'                  = 'CWE-326'
        'insecure randomness'                     = 'CWE-338'
        'regular expression injection'            = 'CWE-730'
        'inefficient regular expression'          = 'CWE-1333'
        'polynomial regular expression'           = 'CWE-1333'
        'missing rate limiting'                   = 'CWE-770'
        'incomplete url substring sanitization'   = 'CWE-20'
        'stack trace'                             = 'CWE-209'
        'debug mode'                              = 'CWE-489'
        'xml external entity'                     = 'CWE-611'
        'xpath injection'                         = 'CWE-643'
        'ldap query built from'                   = 'CWE-90'
        'log injection'                           = 'CWE-117'
        'url redirect'                            = 'CWE-601'
        'prototype-polluting'                     = 'CWE-1321'
        'prototype pollution'                     = 'CWE-1321'
        'csrf'                                    = 'CWE-352'
        'incomplete string escaping'              = 'CWE-116'
        'certificate validation'                  = 'CWE-295'
        'uncontrolled format string'              = 'CWE-134'
        'workflow does not contain permissions'   = 'CWE-275'
        'unvalidated dynamic method call'         = 'CWE-754'
    }

    function Get-CodeQLCwe {
        param([string]$AllText, [string]$RuleText)
        $c = @(Get-CweList $AllText)
        if ($c.Count) { return $c }
        $lower = "$RuleText".ToLowerInvariant()
        foreach ($k in $script:CodeQLCweMap.Keys) { if ($lower.Contains($k)) { return @($script:CodeQLCweMap[$k]) } }
        return @()
    }

    function Read-CodeQLCsv {
        param([string]$File, [string]$RepoName)
        $firstLine = Get-Content -LiteralPath $File -TotalCount 1
        $hasHeader = $firstLine -match '(?i)^"?(name|rule|rule id|query)"?\s*,'
        $rows = if ($hasHeader) { @(Import-Csv -LiteralPath $File) } else { @(Import-Csv -LiteralPath $File -Header $script:CodeQLHeader) }
        if (-not $rows.Count) { return @() }
        $map = New-ColumnMap $rows[0].PSObject.Properties.Name
        $repo = if ($RepoName) { $RepoName } else { [IO.Path]::GetFileNameWithoutExtension($File) }
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($r in $rows) {
            $rule = Get-Col $r $map 'name', 'rule', 'rule id', 'query'
            $sevRaw = Get-Col $r $map 'severity', 'level'
            $secSev = ConvertTo-ScoreOrNull (Get-Col $r $map 'security severity', 'security-severity')
            $sev = switch -Regex ($sevRaw) {
                '(?i)^error$' { 'High' } '(?i)^warning$' { 'Medium' } '(?i)^(recommendation|note)$' { 'Low' }
                default { $w = ConvertTo-SeverityWord $sevRaw; if ($w) { $w } else { 'Low' } }
            }
            $desc = Get-Col $r $map 'description'
            $msg = Get-Col $r $map 'message'
            $filePath = Get-Col $r $map 'path', 'file'
            $line = Get-Col $r $map 'startline', 'start line', 'line'
            $cwes = @(Get-CodeQLCwe "$rule $desc $msg $(Get-Col $r $map 'cwe', 'tags')" "$rule $desc")
            $clean = ($msg -replace '\[\[\"([^"]*)\"\|\"[^"]*\"\]\]', '$1')   # strip CodeQL link markup
            $out.Add((New-Finding @{
                Source = 'CodeQL'; SourceFile = $File; VulnId = "CodeQL: $rule"; Title = $rule
                Host = $repo; Location = if ($line) { "$filePath`:$line" } else { $filePath }
                SourceSeverity = $sev; SourceScore = $secSev
                Description = (@($desc, $clean) | Where-Object { $_ }) -join ' '
                Cwes = $cwes; Status = 'Open'
            }))
        }
        return $out.ToArray()
    }

    # GitHub "Security and quality > Overview > Export CSV" for the organization.
    # One file can mix code scanning (CodeQL), Dependabot and secret scanning alerts;
    # the row's tool / alert type decides how it is read. Column names vary between
    # GitHub releases, so every field accepts several spellings (spaces, snake_case).
    function Read-GitHubOverviewCsv {
        param([string]$File)
        $rows = @(Import-Csv -LiteralPath $File)
        if (-not $rows.Count) { return @() }
        $map = New-ColumnMap $rows[0].PSObject.Properties.Name
        $orgName = ''
        if ([IO.Path]::GetFileName($File) -match '(?i)security_overview_alerts_(.+?)_\d{4}-\d{2}-\d{2}') { $orgName = $Matches[1] }
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($r in $rows) {
            $repo = Get-Col $r $map 'repository', 'repository name', 'repository full name', 'repo', 'repo name', 'repository_nwo'
            if ($repo -and $orgName -and $repo -notmatch '/') { $repo = "$orgName/$repo" }
            if (-not $repo) { $repo = if ($orgName) { "$orgName (repository not listed)" } else { '(repository not listed)' } }
            $tool = Get-Col $r $map 'tool', 'tool name', 'alert type', 'type', 'scanner', 'feature', 'source'
            $rule = Get-Col $r $map 'rule', 'rule name', 'rule description', 'rule id', 'alert title', 'title', 'name', 'query', 'summary', 'advisory summary', 'secret type display name', 'secret type'
            $secretType = Get-Col $r $map 'secret type display name', 'secret type', 'secret'
            $pkg = Get-Col $r $map 'package', 'package name', 'dependency', 'dependency name'
            $eco = Get-Col $r $map 'ecosystem', 'package ecosystem'
            $manifest = Get-Col $r $map 'manifest', 'manifest path', 'dependency manifest'
            $path = Get-Col $r $map 'path', 'file', 'file path', 'location', 'most recent instance path'
            $line = Get-Col $r $map 'start line', 'line', 'start_line'
            $sevText = Get-Col $r $map 'security severity', 'security severity level', 'severity', 'rule severity', 'advisory severity'
            $score = ConvertTo-ScoreOrNull (Get-Col $r $map 'cvss score', 'cvss', 'security severity score')
            $state = Get-Col $r $map 'state', 'status', 'alert state', 'resolution'
            $created = ConvertTo-DateOrNull (Get-Col $r $map 'created at', 'created', 'opened at', 'first detected', 'introduced at', 'date created')
            $url = Get-Col $r $map 'alert url', 'html url', 'url', 'link'
            $alertNo = Get-Col $r $map 'alert number', 'number', 'alert id', 'id'
            $identifiers = Get-Col $r $map 'cve', 'cve id', 'cves', 'identifiers', 'advisory identifiers', 'ghsa id', 'ghsa', 'advisory id'
            $patched = Get-Col $r $map 'first patched version', 'patched version', 'fixed version', 'fixed in', 'patched versions'

            $kind = if ($tool -match '(?i)dependabot|dependency') { 'Dependabot' }
                    elseif ($tool -match '(?i)secret') { 'Secret' }
                    elseif ($tool) { 'Code' }
                    elseif ($secretType) { 'Secret' }
                    elseif ($pkg -or $eco) { 'Dependabot' }
                    else { 'Code' }

            $sev = ConvertTo-SeverityWord $sevText
            if (-not $sev) {
                $sev = switch -Regex ($sevText) { '(?i)^error$' { 'High' } '(?i)^warning$' { 'Medium' } '(?i)^(note|recommendation)$' { 'Low' } default { '' } }
            }
            $common = @{
                SourceFile = $File; Host = $repo; Status = $state; FirstSeen = $created
                PluginId = $alertNo; SourceScore = $score
            }

            switch ($kind) {
                'Dependabot' {
                    $cves = @(Get-CveList $identifiers)
                    if (-not $cves.Count) { $cves = @(Get-CveList "$rule $(Get-Col $r $map 'description')") }
                    $ghsa = ([regex]::Match("$identifiers $(Get-Col $r $map 'ghsa id', 'ghsa', 'advisory id', 'identifiers') $rule $url", '(?i)GHSA(-[23456789cfghjmpqrvwx]{4}){3}')).Value
                    if ($ghsa) { $ghsa = 'GHSA-' + $ghsa.Substring(5).ToLowerInvariant() }
                    $product = @($pkg, $(if ($eco) { "($eco)" })) -join ' '
                    $where = if ($manifest) { $manifest } else { $path }
                    $fix = if ($pkg -and $patched) { "Upgrade $pkg to $patched or later$(if ($where) { " in $where" })." }
                           elseif ($pkg) { "Upgrade $pkg to a patched version$(if ($ghsa) { " (see $ghsa)" })$(if ($where) { " in $where" })." }
                           else { '' }
                    $base = $common.Clone()
                    $base.Source = 'GitHub Dependabot'; $base.Product = $product.Trim(); $base.Location = $where
                    $base.Title = if ($rule) { $rule } elseif ($pkg) { "Vulnerable dependency: $pkg" } else { 'Vulnerable dependency' }
                    $base.SourceSeverity = if ($sev) { $sev } else { 'Medium' }
                    $base.SourceSolution = $fix
                    $base.Description = Get-Col $r $map 'description', 'advisory description', 'summary'
                    $base.Cwes = @(Get-CweList "$(Get-Col $r $map 'cwe', 'cwes', 'cwe ids')")
                    if ($cves.Count) {
                        foreach ($c in $cves) { $p = $base.Clone(); $p.Cve = $c; $p.VulnId = $c; $out.Add((New-Finding $p)) }
                    } else {
                        $p = $base.Clone(); $p.VulnId = if ($ghsa) { $ghsa } else { "Dependabot: $($base.Title)" }
                        $out.Add((New-Finding $p))
                    }
                }
                'Secret' {
                    $st = if ($secretType) { $secretType } elseif ($rule) { $rule } else { 'credential' }
                    $p = $common.Clone()
                    $p.Source = 'GitHub Secret Scanning'; $p.VulnId = "Exposed secret: $st"; $p.Title = "Exposed secret: $st"
                    $p.Location = if ($path -and $line) { "$path`:$line" } else { $path }
                    $p.SourceSeverity = if ($sev) { $sev } else { 'High' }
                    $p.SourceSolution = "Revoke and rotate the exposed $st now, then remove it from the repository and its history, and review the provider's access logs for use of the leaked value."
                    $p.Description = "A $st was committed to $repo."
                    $p.Cwes = @('CWE-798')
                    $out.Add((New-Finding $p))
                }
                default {
                    $isCodeQL = (-not $tool) -or $tool -match '(?i)codeql|^code.?scanning$'
                    $label = if ($isCodeQL) { 'CodeQL' } else { $tool }
                    $desc = Get-Col $r $map 'description', 'rule description', 'message', 'most recent instance message'
                    $p = $common.Clone()
                    $p.Source = if ($isCodeQL) { 'CodeQL' } else { "GitHub Code Scanning ($tool)" }
                    $p.VulnId = "$label`: $rule"; $p.Title = $rule
                    $p.Location = if ($path -and $line) { "$path`:$line" } else { $path }
                    $p.SourceSeverity = if ($sev) { $sev } else { 'Medium' }
                    $p.Description = $desc
                    $p.Cwes = @(Get-CodeQLCwe "$rule $desc $(Get-Col $r $map 'cwe', 'cwes', 'tags', 'rule tags')" "$rule $desc")
                    $cves = @(Get-CveList "$rule $desc")
                    if ($cves.Count) { $p.Cve = $cves[0] }
                    $out.Add((New-Finding $p))
                }
            }
        }
        return $out.ToArray()
    }

    function Read-GenericCsv {
        param([string]$File)
        $rows = @(Import-Csv -LiteralPath $File)
        if (-not $rows.Count) { return @() }
        $map = New-ColumnMap $rows[0].PSObject.Properties.Name
        $cveCols = @($map.Keys | Where-Object { $_ -match 'cve' })
        $out = New-Object System.Collections.Generic.List[object]
        foreach ($r in $rows) {
            $cves = @(Get-CveList (($cveCols | ForEach-Object { Get-Col $r $map $_ }) -join ' '))
            if (-not $cves.Count) { continue }
            $sev = ConvertTo-SeverityWord (Get-Col $r $map 'severity', 'risk', 'priority', 'criticality')
            foreach ($c in $cves) {
                $out.Add((New-Finding @{
                    Source = 'Generic CSV'; SourceFile = $File; VulnId = $c; Cve = $c
                    Title = Get-Col $r $map 'name', 'title', 'vulnerability', 'plugin name'
                    Host = Get-Col $r $map 'hostname', 'host', 'asset', 'device', 'computer', 'dns name'
                    IP = Get-Col $r $map 'ip', 'ip address', 'local ip'
                    User = Get-Col $r $map 'user', 'username', 'user name', 'owner'
                    Port = Get-Col $r $map 'port'
                    SourceSeverity = if ($sev) { $sev } else { 'Info' }
                    SourceScore = ConvertTo-ScoreOrNull (Get-Col $r $map 'cvss', 'cvss score', 'base score', 'score')
                    SourceSolution = Get-Col $r $map 'solution', 'remediation', 'fix', 'recommendation'
                    Description = Get-Col $r $map 'description', 'synopsis', 'summary'
                    Status = Get-Col $r $map 'status', 'state'
                    FirstSeen = ConvertTo-DateOrNull (Get-Col $r $map 'first seen', 'first discovered', 'created')
                    LastSeen = ConvertTo-DateOrNull (Get-Col $r $map 'last seen', 'last observed', 'updated')
                }))
            }
        }
        return $out.ToArray()
    }
    # ==================================================================
    #  JSON CACHE HELPERS (hashtable keyed by CVE / CWE)
    # ==================================================================
    function Read-JsonCache {
        param([string]$File)
        $h = @{}
        if (Test-Path -LiteralPath $File) {
            try {
                $obj = Get-Content -LiteralPath $File -Raw -Encoding UTF8 | ConvertFrom-Json
                foreach ($p in $obj.PSObject.Properties) { $h[$p.Name] = $p.Value }
            } catch { Write-Bad "Cache file '$File' is unreadable and will be rebuilt." }
        }
        return $h
    }

    function Save-JsonCache {
        param([hashtable]$Cache, [string]$File)
        try {
            $ordered = [ordered]@{}
            foreach ($k in ($Cache.Keys | Sort-Object)) { $ordered[$k] = $Cache[$k] }
            ($ordered | ConvertTo-Json -Depth 6 -Compress) | Set-Content -LiteralPath $File -Encoding UTF8
        } catch { Write-Bad "Could not write cache '$File': $($_.Exception.Message)" }
    }

    function Test-CacheFresh {
        param($Entry, [double]$Hours)
        if (-not $Entry -or -not $Entry.Fetched) { return $false }
        $d = ConvertTo-DateOrNull "$($Entry.Fetched)"
        if (-not $d) { return $false }
        return ((Get-Date) - $d).TotalHours -lt $Hours
    }

    function Invoke-Api {
        param([string]$Uri, [hashtable]$Headers = @{}, [int]$TimeoutSec = 25, [int]$Retries = 1)
        # Windows PowerShell 5.1 rejects User-Agent inside -Headers, so use -UserAgent
        $ua = "TMS-VulnReport/$ScriptVersion (PowerShell)"
        for ($i = 0; $i -le $Retries; $i++) {
            try {
                return Invoke-RestMethod -Uri $Uri -Headers $Headers -UserAgent $ua -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop
            } catch {
                $code = $null
                try { $code = [int]$_.Exception.Response.StatusCode } catch { }
                if ($code -eq 404) { return $null }
                if (-not $code -and $i -ge 1) { throw }          # network unreachable: one retry only
                if (($code -in 403, 429, 500, 502, 503, 504 -or -not $code) -and $i -lt $Retries) {
                    $wait = if ($code) { 6 * ($i + 1) } else { 2 }
                    Write-Log 'WARN' "HTTP $code from $Uri - retrying in $wait s"
                    Start-Sleep -Seconds $wait
                    continue
                }
                throw
            }
        }
    }

    # ==================================================================
    #  CISA KEV
    # ==================================================================
    function Get-KevCatalog {
        param($Cfg, [string]$CacheDir, [switch]$Offline)
        $file = Join-Path $CacheDir 'kev_catalog.json'
        $legacy = Join-Path $ScriptRoot 'kev_cache.json'       # cache left by the old Python tool
        $load = {
            param([string]$f)
            $obj = Get-Content -LiteralPath $f -Raw -Encoding UTF8 | ConvertFrom-Json
            $map = @{}
            if ($obj.vulnerabilities) {
                foreach ($v in $obj.vulnerabilities) { if ($v.cveID) { $map[$v.cveID] = $v } }
            } else {
                foreach ($p in $obj.PSObject.Properties) { if ($p.Value.cveID) { $map[$p.Name] = $p.Value } }
            }
            return $map
        }
        $cacheFile = if (Test-Path -LiteralPath $file) { $file } elseif (Test-Path -LiteralPath $legacy) { $legacy } else { $null }
        if ($cacheFile) {
            $age = ((Get-Date) - (Get-Item -LiteralPath $cacheFile).LastWriteTime).TotalHours
            if ($Offline -or $age -lt $Cfg.CacheHours.Kev) {
                try {
                    $m = & $load $cacheFile
                    Write-Good ("CISA KEV catalog loaded from cache ({0:N1} h old, {1} entries)." -f $age, $m.Count)
                    return $m
                } catch { }
            }
        }
        if ($Offline) { Write-Bad 'Offline mode and no KEV cache found - KEV matching is disabled for this run.'; return @{} }
        Write-Info 'Downloading CISA Known Exploited Vulnerabilities catalog...'
        try {
            $resp = Invoke-WebRequest -Uri $Cfg.Api.KevUrl -UseBasicParsing -TimeoutSec 60 -UserAgent "TMS-VulnReport/$ScriptVersion (PowerShell)"
            $text = if ($resp.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($resp.Content) } else { [string]$resp.Content }
            Set-Content -LiteralPath $file -Value $text -Encoding UTF8
            $m = & $load $file
            Write-Good "CISA KEV catalog downloaded: $($m.Count) known-exploited CVEs."
            return $m
        } catch {
            Write-Bad "CISA KEV download failed: $($_.Exception.Message)"
            if ($cacheFile) {
                try { $m = & $load $cacheFile; Write-Bad 'Using the older cached KEV catalog instead.'; return $m } catch { }
            }
        }
        return @{}
    }

    # ==================================================================
    #  NIST NVD  (CVSS + CWE)
    # ==================================================================
    function Get-NvdRecord {
        param([string]$CveId, $Cfg, [string]$ApiKey)
        $headers = @{}
        if ($ApiKey) { $headers['apiKey'] = $ApiKey }
        $resp = Invoke-Api -Uri ($Cfg.Api.NvdUrl + $CveId) -Headers $headers
        $rec = [ordered]@{ Fetched = (Get-Date).ToString('o'); Found = $false; Score = $null; Version = ''; Vector = ''; Description = ''; Cwes = @(); Published = '' }
        if (-not $resp -or -not $resp.vulnerabilities) { return [pscustomobject]$rec }
        $cve = $resp.vulnerabilities[0].cve
        $rec.Found = $true
        $rec.Published = "$($cve.published)"
        $en = @($cve.descriptions | Where-Object { $_.lang -like 'en*' } | Select-Object -First 1)
        if ($en.Count) { $rec.Description = $en[0].value }
        foreach ($key in 'cvssMetricV31', 'cvssMetricV40', 'cvssMetricV30', 'cvssMetricV2') {
            $list = @($cve.metrics.$key)
            if ($list.Count -and $list[0]) {
                $m = @($list | Where-Object { $_.type -eq 'Primary' } | Select-Object -First 1)
                if (-not $m.Count) { $m = @($list[0]) }
                $rec.Score = [double]$m[0].cvssData.baseScore
                $rec.Version = "$($m[0].cvssData.version)"
                $rec.Vector = "$($m[0].cvssData.vectorString)"
                break
            }
        }
        $cwes = New-Object System.Collections.Generic.List[string]
        foreach ($w in @($cve.weaknesses)) {
            foreach ($d in @($w.description)) {
                if ($d.value -match '^CWE-\d+$' -and -not $cwes.Contains($d.value)) { $cwes.Add($d.value) }
            }
        }
        $rec.Cwes = $cwes.ToArray()
        return [pscustomobject]$rec
    }

    # ==================================================================
    #  CIRCL  (description, vendor solution, CISA SSVC via Vulnrichment)
    # ==================================================================
    function Get-CirclRecord {
        param([string]$CveId, $Cfg)
        $data = Invoke-Api -Uri ($Cfg.Api.CirclUrl + $CveId)
        $rec = [ordered]@{ Fetched = (Get-Date).ToString('o'); Description = ''; Solution = ''; Exploitation = ''; Automatable = ''; TechnicalImpact = ''; Cwes = @() }
        if (-not $data) { return [pscustomobject]$rec }
        $cna = $data.containers.cna
        if ($cna) {
            $d = @($cna.descriptions | Where-Object { $_.lang -like 'en*' -and $_.value } | Select-Object -First 1)
            if ($d.Count) { $rec.Description = $d[0].value }
            foreach ($block in 'solutions', 'workarounds') {
                $s = @($cna.$block | Where-Object { $_.lang -like 'en*' -and $_.value } | Select-Object -First 1)
                if ($s.Count) { $rec.Solution = $s[0].value; break }
            }
            $cw = New-Object System.Collections.Generic.List[string]
            foreach ($pt in @($cna.problemTypes)) { foreach ($d2 in @($pt.descriptions)) { if ($d2.cweId -and -not $cw.Contains($d2.cweId)) { $cw.Add($d2.cweId) } } }
            $rec.Cwes = $cw.ToArray()
        } elseif ($data.summary) {
            $rec.Description = "$($data.summary)"          # legacy CIRCL format
        }
        # CISA-ADP container carries SSVC decision points (used by BOD 26-04)
        foreach ($adp in @($data.containers.adp)) {
            foreach ($metric in @($adp.metrics)) {
                if ($metric.other.type -eq 'ssvc') {
                    foreach ($opt in @($metric.other.content.options)) {
                        foreach ($p in $opt.PSObject.Properties) {
                            switch ($p.Name) {
                                'Exploitation' { $rec.Exploitation = "$($p.Value)" }
                                'Automatable' { $rec.Automatable = "$($p.Value)" }
                                'Technical Impact' { $rec.TechnicalImpact = "$($p.Value)" }
                            }
                        }
                    }
                }
            }
            if (-not $rec.Cwes.Count) {
                $cw2 = New-Object System.Collections.Generic.List[string]
                foreach ($pt in @($adp.problemTypes)) { foreach ($d3 in @($pt.descriptions)) { if ($d3.cweId -and -not $cw2.Contains($d3.cweId)) { $cw2.Add($d3.cweId) } } }
                $rec.Cwes = $cw2.ToArray()
            }
        }
        return [pscustomobject]$rec
    }

    # ==================================================================
    #  MITRE CWE REST API  (batched, comma-separated IDs)
    # ==================================================================
    function ConvertTo-CweRecord {
        param($W)
        $mit = ''
        $mits = @($W.PotentialMitigations)
        $pick = @($mits | Where-Object { $_.Phase -and (@($_.Phase) -match 'Implementation|Architecture and Design|Operation|Patching') } | Select-Object -First 1)
        if (-not $pick.Count -and $mits.Count) { $pick = @($mits[0]) }
        if ($pick.Count -and $pick[0].Description) { $mit = ("$($pick[0].Description)" -replace '\s+', ' ').Trim() }
        if ($mit.Length -gt 420) {
            $cut = $mit.Substring(0, 420)
            $dot = $cut.LastIndexOf('. ')
            $mit = if ($dot -gt 120) { $cut.Substring(0, $dot + 1) } else { $cut + '...' }
        }
        return [pscustomobject][ordered]@{
            Fetched = (Get-Date).ToString('o'); Found = $true
            Id = "CWE-$($W.ID)"; Name = "$($W.Name)"
            Description = ("$($W.Description)" -replace '\s+', ' ').Trim()
            Likelihood = "$($W.LikelihoodOfExploit)"; Mitigation = $mit
        }
    }

    function Get-CweRecords {
        param([string[]]$Ids, $Cfg, [hashtable]$Cache)
        $nums = @($Ids | ForEach-Object { ($_ -replace '^CWE-', '') } | Where-Object { $_ -match '^\d+$' } | Select-Object -Unique)
        for ($i = 0; $i -lt $nums.Count; $i += 20) {
            $chunk = @($nums[$i..([Math]::Min($i + 19, $nums.Count - 1))])
            $got = @()
            try {
                $resp = Invoke-Api -Uri ($Cfg.Api.CweUrl + ($chunk -join ','))
                $got = if ($resp -and $resp.Weaknesses) { @($resp.Weaknesses) } elseif ($resp -is [array]) { @($resp) } else { @() }
            } catch {
                Write-Log 'WARN' "CWE batch lookup failed ($($chunk -join ',')): $($_.Exception.Message)"
                Write-Bad "MITRE CWE API is not responding ($($_.Exception.Message)) - CWE names come from cache only."
                return
            }
            foreach ($w in $got) { if ($w.ID) { $Cache["CWE-$($w.ID)"] = ConvertTo-CweRecord $w } }
            $fails = 0
            foreach ($n in $chunk) {
                if ($Cache.ContainsKey("CWE-$n") -and (Test-CacheFresh $Cache["CWE-$n"] 1)) { continue }
                if ($fails -ge 2) { break }
                try {   # one-by-one fallback (the batch 404s if any ID is a category or view)
                    $one = Invoke-Api -Uri ($Cfg.Api.CweUrl + $n)
                    $w1 = if ($one -and $one.Weaknesses) { @($one.Weaknesses)[0] } elseif ($one -is [array]) { $one[0] } else { $null }
                    if ($w1) { $Cache["CWE-$n"] = ConvertTo-CweRecord $w1 }
                    else { $Cache["CWE-$n"] = [pscustomobject]@{ Fetched = (Get-Date).ToString('o'); Found = $false; Id = "CWE-$n"; Name = ''; Description = ''; Likelihood = ''; Mitigation = '' } }
                } catch { $fails++; Write-Log 'WARN' "CWE-$n lookup failed: $($_.Exception.Message)" }
            }
        }
    }

    # ==================================================================
    #  SCOPE / NETWORK HELPERS
    # ==================================================================
    function ConvertTo-UInt64Ip {
        param([string]$Ip)
        $addr = $null
        if (-not [Net.IPAddress]::TryParse($Ip, [ref]$addr)) { return $null }
        $b = $addr.GetAddressBytes()
        if ($b.Length -ne 4) { return $null }
        return ([uint64]$b[0] -shl 24) + ([uint64]$b[1] -shl 16) + ([uint64]$b[2] -shl 8) + [uint64]$b[3]
    }

    function Test-IpInCidr {
        param([string]$Ip, [string]$Cidr)
        $ipNum = ConvertTo-UInt64Ip $Ip
        if ($null -eq $ipNum) { return $false }
        $parts = $Cidr.Split('/')
        $net = ConvertTo-UInt64Ip $parts[0]
        if ($null -eq $net) { return $false }
        $bits = if ($parts.Count -gt 1) { [int]$parts[1] } else { 32 }
        $all = [uint64][uint32]::MaxValue
        $mask = if ($bits -le 0) { [uint64]0 } else { ($all -shl (32 - $bits)) -band $all }
        return (($ipNum -band $mask) -eq ($net -band $mask))
    }

    function Test-AssetMatch {
        param($Finding, [string[]]$Networks, [string[]]$Patterns)
        foreach ($c in @($Networks)) { if ($c -and $Finding.IP -and (Test-IpInCidr $Finding.IP $c)) { return $true } }
        foreach ($p in @($Patterns)) {
            if (-not $p) { continue }
            if ($Finding.Host -and $Finding.Host -like $p) { return $true }
            if ($Finding.IP -and $Finding.IP -like $p) { return $true }
        }
        return $false
    }

    # ==================================================================
    #  REMEDIATION TEXT  (scanner fix > CISA KEV > CIRCL vendor > CWE > policy)
    # ==================================================================
    function Get-FallbackRemediation {
        param($F, $Cfg)
        $days = $F.SlaDays
        $what = if ($F.Product) { $F.Product } elseif ($F.Title) { $F.Title } else { 'the affected software' }
        if ($F.Source -match '^(CodeQL|GitHub Code Scanning)') {
            return "Fix the '$($F.Title)' finding at the listed code locations within $days days, then confirm the alert closes on the next code scan."
        }
        switch -Regex ($F.SlaTier) {
            '^(Critical|CISA)' { "Apply the vendor security update for $($F.VulnId) ($what) on every listed asset within $days days. If no fix exists yet, isolate the service or apply the vendor's documented mitigation and restrict network access until patched." }
            '^High' { "Update $what to a fixed release that resolves $($F.VulnId) within $days days; confirm with a rescan." }
            '^Medium' { "Schedule the vendor fix for $($F.VulnId) ($what) in a maintenance window within $days days." }
            '^Low' { "Address $($F.VulnId) ($what) during routine patching within $days days, or document a risk acceptance." }
            default { "Review $($F.VulnId) for relevance; no SLA applies to informational findings." }
        }
    }

    function Set-Remediation {
        param($F, $Cfg, $Circl, $CweCache)
        $text = ''; $src = ''
        if ($F.SourceSolution -and $F.SourceSolution -notmatch '^(n/?a|none|no solution|-)$') {
            $text = $F.SourceSolution; $src = $F.Source
        } elseif ($F.IsKev -and $F.KevAction) {
            $text = $F.KevAction; $src = 'CISA KEV'
        } elseif ($Circl -and $Circl.Solution) {
            $text = $Circl.Solution; $src = 'Vendor (CIRCL)'
        } elseif ($F.Cwes.Count) {
            foreach ($c in $F.Cwes) {
                $cw = $CweCache[$c]
                if ($cw -and $cw.Mitigation) { $text = "Fix the $c weakness ($($cw.Name)) in the listed locations. $($cw.Mitigation)"; $src = 'MITRE CWE'; break }
            }
        }
        if (-not $text) { $text = Get-FallbackRemediation $F $Cfg; $src = 'TMS policy' }
        $text = ($text -replace '\s+', ' ').Trim()
        $F.Remediation = $text
        $F.RemediationSource = $src
        # Generic texts (KEV boilerplate, CWE advice, policy) must never merge different vulnerabilities
        $norm = ($text.ToLowerInvariant() -replace '[^a-z0-9]+', ' ').Trim()
        $F.RemediationKey = if ($src -in 'CISA KEV', 'MITRE CWE', 'TMS policy') { "$($F.VulnId)|$norm" } else { $norm }
    }

    # ==================================================================
    #  IP -> HOST NAME  (nslookup against the TMS domain controllers)
    #  An IP that arrives without a name (Nessus, Blumira) is looked up
    #  as a PTR record on the DCs. The scanner's own name is kept when it
    #  has one. Order of DNS servers:
    #    -DnsServer parameter > DnsServers in settings > DCs found from AD
    # ==================================================================
    function Test-InternalIp {
        param([string]$Ip, $Cfg)
        foreach ($c in @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16') + @($Cfg.InScopeNetworks)) {
            if ($c -and (Test-IpInCidr $Ip $c)) { return $true }
        }
        return $false
    }

    function Get-TmsDomainControllers {
        # Finds the domain's DCs the same way Windows does: the _ldap SRV record
        $domain = "$env:USERDNSDOMAIN"
        if (-not $domain) {
            try { $domain = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).Domain } catch { }
        }
        if (-not $domain -or $domain -eq 'WORKGROUP') { $domain = '' }
        $dcs = New-Object System.Collections.Generic.List[string]
        if ($domain) {
            $srv = "_ldap._tcp.dc._msdcs.$domain"
            if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
                try {
                    Resolve-DnsName -Name $srv -Type SRV -DnsOnly -ErrorAction Stop |
                        Where-Object { $_.Type -eq 'SRV' } | Sort-Object Priority, Weight |
                        ForEach-Object { if ($_.NameTarget -and -not $dcs.Contains($_.NameTarget)) { $dcs.Add($_.NameTarget.TrimEnd('.')) } }
                } catch { }
            }
            if (-not $dcs.Count -and (Get-Command nslookup -ErrorAction SilentlyContinue)) {
                $out = & nslookup -type=SRV $srv 2>$null
                foreach ($line in @($out)) {
                    if ($line -match 'svr hostname\s*=\s*(\S+)' -or $line -match 'service = \d+ \d+ \d+ (\S+)') {
                        $n = $Matches[1].TrimEnd('.'); if (-not $dcs.Contains($n)) { $dcs.Add($n) }
                    }
                }
            }
        }
        if (-not $dcs.Count -and $env:LOGONSERVER) {
            $n = $env:LOGONSERVER.TrimStart('\')
            if ($n -and $n -ne $env:COMPUTERNAME) { $dcs.Add($n) }
        }
        return @($dcs | Select-Object -First 3)
    }

    function Invoke-PtrLookup {
        # One IP against one DNS server. Returns @{ Name; Result } where Result is
        # Found, NotFound (the server answered: no PTR record) or Failed (no answer).
        param([string]$Ip, [string]$Server)
        if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
            $args2 = @{ Name = $Ip; Type = 'PTR'; DnsOnly = $true; QuickTimeout = $true; ErrorAction = 'Stop' }
            if ($Server) { $args2['Server'] = $Server }
            try {
                $rec = @(Resolve-DnsName @args2 | Where-Object { $_.Type -eq 'PTR' -and $_.NameHost } | Select-Object -First 1)
                if ($rec.Count) { return @{ Name = $rec[0].NameHost.TrimEnd('.'); Result = 'Found' } }
                return @{ Name = ''; Result = 'NotFound' }
            } catch {
                $id = "$($_.FullyQualifiedErrorId) $($_.Exception.Message)"
                if ($id -match 'RCODE_NAME_ERROR|does not exist|9003|NO_RECORDS|9501') { return @{ Name = ''; Result = 'NotFound' } }
                return @{ Name = ''; Result = 'Failed' }
            }
        }
        # Same lookup with nslookup.exe (older Windows, or no DnsClient module)
        if (Get-Command nslookup -ErrorAction SilentlyContinue) {
            $nsArgs = @('-timeout=2', '-retry=1', $Ip)
            if ($Server) { $nsArgs += $Server }
            $text = (& nslookup @nsArgs 2>&1 | Out-String)
            return (ConvertFrom-NslookupOutput $text $Ip)
        }
        try {
            $n = [System.Net.Dns]::GetHostEntry($Ip).HostName
            if ($n -and $n -ne $Ip) { return @{ Name = $n.TrimEnd('.'); Result = 'Found' } }
        } catch { return @{ Name = ''; Result = 'NotFound' } }
        return @{ Name = ''; Result = 'NotFound' }
    }

    function ConvertFrom-NslookupOutput {
        param([string]$Text, [string]$Ip)
        # Windows:  "Name:    tms-dc01.tms.local"  (after the server's own Name: line)
        # Linux:    "15.1.20.10.in-addr.arpa  name = tms-dc01.tms.local."
        $m = [regex]::Match($Text, '(?im)in-addr\.arpa\s+name\s*=\s*(\S+)')
        if ($m.Success) { return @{ Name = $m.Groups[1].Value.TrimEnd('.'); Result = 'Found' } }
        $names = [regex]::Matches($Text, '(?im)^\s*Name:\s*(\S+)')
        $addrs = [regex]::Matches($Text, '(?im)^\s*Address(?:es)?:\s*(\S+)')
        if ($names.Count -ge 2) { return @{ Name = $names[$names.Count - 1].Groups[1].Value.TrimEnd('.'); Result = 'Found' } }
        if ($names.Count -eq 1 -and $addrs.Count -ge 2 -and $addrs[$addrs.Count - 1].Groups[1].Value -eq $Ip) {
            return @{ Name = $names[0].Groups[1].Value.TrimEnd('.'); Result = 'Found' }
        }
        if ($Text -match "(?i)Non-existent domain|NXDOMAIN|can't find|can not find") { return @{ Name = ''; Result = 'NotFound' } }
        return @{ Name = ''; Result = 'Failed' }
    }

    function Resolve-IpNamesOnDcs {
        param([string[]]$Ips, [string[]]$Servers)
        $result = @{}
        $live = New-Object System.Collections.Generic.List[string]
        foreach ($sv in @($Servers)) { if ($sv) { $live.Add($sv) } }
        if (-not $live.Count) { $live.Add('') }          # '' = this computer's own DNS servers
        $strikes = @{}
        $i = 0
        foreach ($ip in $Ips) {
            $i++
            Write-Progress -Activity 'nslookup on domain controllers' -Status "$ip ($i of $($Ips.Count))" -PercentComplete ($i * 100 / [Math]::Max(1, $Ips.Count))
            foreach ($sv in @($live)) {
                $r = Invoke-PtrLookup $ip $sv
                if ($r.Result -eq 'Found') { $result[$ip] = $r.Name; break }
                if ($r.Result -eq 'NotFound') { break }       # DCs share the AD zone - no point asking the next one
                $strikes[$sv] = 1 + [int]$strikes[$sv]        # no answer: try the next DC
                if ($strikes[$sv] -ge 3 -and $live.Count -gt 1) {
                    [void]$live.Remove($sv)
                    Write-Bad "DNS server '$sv' is not answering - using $($live -join ', ') for the rest."
                }
            }
        }
        Write-Progress -Activity 'nslookup on domain controllers' -Completed
        return $result
    }

    # ==================================================================
    #  GROUPING
    # ==================================================================
    function Join-Unique {
        param([object[]]$Values, [string]$Separator = '; ')
        $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $list = New-Object System.Collections.Generic.List[string]
        foreach ($v in $Values) { $s = "$v".Trim(); if ($s -and $set.Add($s)) { $list.Add($s) } }
        return $list.ToArray()
    }

    function New-GroupRow {
        param([object[]]$Items, [string]$Kind)
        $top = $Items | Sort-Object @{ e = { $_.SeverityRank }; Descending = $true }, @{ e = { if ($null -ne $_.Cvss) { $_.Cvss } else { -1 } }; Descending = $true } | Select-Object -First 1
        $due = $Items | Where-Object { $_.DueDate } | Sort-Object DueDate | Select-Object -First 1
        $hosts = @(Join-Unique ($Items | ForEach-Object { $_.HostLabel }))
        $users = @(Join-Unique ($Items | ForEach-Object { $_.User }))
        $locs = @(Join-Unique ($Items | ForEach-Object { $_.Location }))
        $vulns = @(Join-Unique ($Items | Sort-Object @{ e = { $_.SeverityRank }; Descending = $true } | ForEach-Object { $_.VulnId }))
        $cwes = @(Join-Unique ($Items | ForEach-Object { $_.Cwes }))
        $maxCvss = ($Items | Where-Object { $null -ne $_.Cvss } | Measure-Object -Property Cvss -Maximum).Maximum
        [pscustomobject][ordered]@{
            Kind = $Kind
            VulnIds = $vulns
            Cves = @(Join-Unique ($Items | ForEach-Object { $_.Cve }))
            Titles = @(Join-Unique ($Items | ForEach-Object { if ($_.Title) { $_.Title } else { $_.VulnId } }))
            Title = $top.Title
            Severity = $top.Severity
            SeverityRank = $top.SeverityRank
            Cvss = $maxCvss
            CvssVector = $top.CvssVector
            Cwes = $cwes
            CweNames = (Join-Unique ($Items | ForEach-Object { $_.CweNames })) -join '; '
            IsKev = [bool]($Items | Where-Object { $_.IsKev })
            KevDueDate = (Join-Unique ($Items | Where-Object { $_.IsKev } | ForEach-Object { $_.KevDueDate })) -join ', '
            KevAction = ($Items | Where-Object { $_.KevAction } | Select-Object -First 1).KevAction
            KevRansomware = [bool]($Items | Where-Object { $_.KevRansomware -eq 'Known' })
            Ssvc = (Join-Unique ($Items | Where-Object { $_.SsvcExploitation } | ForEach-Object { "Exploitation: $($_.SsvcExploitation), Automatable: $($_.SsvcAutomatable), Impact: $($_.SsvcTechnicalImpact)" })) -join ' | '
            Hosts = $hosts
            Users = $users
            Locations = $locs
            Instances = @($Items).Count
            Sources = (Join-Unique ($Items | ForEach-Object { $_.Source })) -join ', '
            SlaTier = $top.SlaTier
            DueDate = if ($due) { $due.DueDate } else { $null }
            DaysRemaining = if ($due) { $due.DaysRemaining } else { $null }
            SlaStatus = if ($due) { $due.SlaStatus } else { 'No SLA' }
            NewCount = @($Items | Where-Object { $_.IsNew }).Count
            Remediation = $top.Remediation
            RemediationSource = $top.RemediationSource
            Description = ($Items | Where-Object { $_.Description } | Select-Object -First 1).Description
            Reason = (Join-Unique ($Items | ForEach-Object { $_.AffectsReason })) -join '; '
        }
    }

    # ==================================================================
    #  HTML REPORT
    # ==================================================================
    function ConvertTo-Html5Text { param($s) return [System.Net.WebUtility]::HtmlEncode("$s") }

    function Get-VulnLink {
        param([string]$Id)
        $e = ConvertTo-Html5Text $Id
        if ($Id -match '^CVE-\d{4}-\d+$') { return "<a href=""https://nvd.nist.gov/vuln/detail/$Id"">$e</a>" }
        if ($Id -match '^GHSA(-[a-z0-9]{4}){3}$') { return "<a href=""https://github.com/advisories/$Id"">$e</a>" }
        if ($Id -match '^Nessus (\d+)$') { return "<a href=""https://www.tenable.com/plugins/nessus/$($Matches[1])"">$e</a>" }
        return $e
    }

    function Get-CweLinks {
        param([string[]]$Cwes)
        return (@($Cwes) | Where-Object { $_ } | ForEach-Object {
            $n = $_ -replace '^CWE-', ''
            "<a href=""https://cwe.mitre.org/data/definitions/$n.html"">$(ConvertTo-Html5Text $_)</a>"
        }) -join ', '
    }

    function Get-CveCell {
        param($Row)
        $cves = @($Row.Cves)
        if ($cves.Count) {
            $h = ($cves | Select-Object -First 8 | ForEach-Object { "<span class=""vid"">$(Get-VulnLink $_)</span>" }) -join '<br>'
            if ($cves.Count -gt 8) { $h += "<br><span class=""muted"">and $($cves.Count - 8) more</span>" }
            return $h
        }
        return '<span class="muted">No CVE</span>'
    }

    function Get-CweCell {
        param($Row)
        $cwes = @(@($Row.Cwes) | Where-Object { $_ })
        if (-not $cwes.Count) { return '<span class="muted">None listed</span>' }
        $names = @("$($Row.CweNames)" -split '; ' | Where-Object { $_ })
        $h = New-Object System.Collections.Generic.List[string]
        for ($k = 0; $k -lt [Math]::Min(2, $cwes.Count); $k++) {
            $line = "<span class=""vid"">$(Get-CweLinks @($cwes[$k]))</span>"
            if ($k -lt $names.Count) {
                $nm = $names[$k]; $nm = $nm -replace "\s*\('[^']*'\)", ''          # drop the ('SQL Injection') style suffix
                if ($nm.Length -gt 42) { $nm = $nm.Substring(0, 40).TrimEnd() + '...' }
                $line += "<span class=""cwe"">$(ConvertTo-Html5Text $nm)</span>"
            }
            $h.Add($line)
        }
        $out = $h -join ''
        if ($cwes.Count -gt 2) { $out += "<span class=""cwe"">+ $($cwes.Count - 2) more: $(($cwes | Select-Object -Skip 2) -join ', ')</span>" }
        return $out
    }

    function Get-AssetCell {
        param($Row, [int]$Max)
        $parts = New-Object System.Collections.Generic.List[string]
        $render = {
            param([string[]]$Items, [string]$Label)
            $Items = @($Items | Where-Object { "$_".Trim() })
            if (-not $Items.Count) { return '' }
            $shown = @($Items | Select-Object -First $Max | ForEach-Object { ConvertTo-Html5Text $_ })
            $html = "<div class=""assets""><span class=""asset-label"">$Label ($($Items.Count))</span> " + ($shown -join ', ')
            if ($Items.Count -gt $Max) {
                $html += " <span class=""muted"">and $($Items.Count - $Max) more (full list in the CSV exports)</span>"
            }
            return $html + '</div>'
        }
        $label = if ($Row.Sources -and ($Row.Sources -split ', ' | Where-Object { $_ -notmatch '^(CodeQL|GitHub)' }).Count -eq 0) { 'Repositories' } else { 'Hosts' }
        $parts.Add((& $render $Row.Hosts $label))
        $parts.Add((& $render $Row.Users 'Users'))
        $parts.Add((& $render $Row.Locations 'Code locations'))
        return ($parts | Where-Object { $_ }) -join ''
    }

    function Get-DueCell {
        param($Row)
        if (-not $Row.DueDate) { return '<span class="due none">No SLA</span>' }
        $cls = switch ($Row.SlaStatus) { 'Overdue' { 'overdue' } 'Due soon' { 'soon' } default { 'ok' } }
        $d = $Row.DaysRemaining
        $when = if ($d -lt 0) { "$([Math]::Abs($d)) days overdue" } elseif ($d -eq 0) { 'due today' } else { "$d days left" }
        return "<span class=""due $cls""><strong>$($Row.DueDate.ToString('MMM d, yyyy'))</strong><br>$when</span>"
    }

    function Get-SevPill {
        param([string]$Sev, $Cvss)
        $score = if ($null -ne $Cvss) { ' ' + ('{0:N1}' -f $Cvss) } else { '' }
        return "<span class=""pill sev-$($Sev.ToLower())"">$Sev$score</span>"
    }

    function Get-LogoTag {
        param([string]$LogoPath)
        $logoTag = ''
        if ($LogoPath -and (Test-Path -LiteralPath $LogoPath)) {
            $ext = [IO.Path]::GetExtension($LogoPath).TrimStart('.').ToLower()
            if ($ext -eq 'jpg') { $ext = 'jpeg' }
            if ($ext -eq 'svg') { $ext = 'svg+xml' }
            $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($LogoPath))
            $logoTag = "<img class=""logo"" src=""data:image/$ext;base64,$b64"" alt=""Times Microwave Systems"">"
        }

        return $logoTag
    }

    function Get-ReportCss {
        param([string]$FooterTitle = 'Monthly Vulnerability Remediation Report')
        return (@'
:root{--blue:#1473BC;--ink:#1C2430;--steel:#56616F;--line:#D6DDE5;--wash:#F2F5F8;
--crit:#A4161A;--high:#CC4E15;--med:#A87B00;--low:#2E7A4C;--info:#7A8591}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:#fff;color:var(--ink);font:15px/1.5 "Segoe UI","Helvetica Neue",Arial,sans-serif;font-variant-numeric:tabular-nums}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
a:focus-visible,summary:focus-visible{outline:2px solid var(--blue);outline-offset:2px}
.marking{background:var(--blue);color:#fff;text-align:center;font:600 12px/1 "Segoe UI",Arial,sans-serif;letter-spacing:.14em;padding:7px 0}
.page{max-width:1180px;margin:0 auto;padding:0 28px 48px}
header.top{display:flex;align-items:center;gap:28px;padding:26px 0 20px;border-bottom:3px solid var(--ink)}
.logo{height:64px;width:auto;flex:none}
.titles h1{font-family:Bahnschrift,"DIN Alternate","Segoe UI",Arial,sans-serif;font-weight:600;font-stretch:condensed;font-size:30px;line-height:1.1;margin:0}
.titles .period{font-family:Bahnschrift,"DIN Alternate","Segoe UI",Arial,sans-serif;font-size:20px;color:var(--blue);margin-top:2px}
.titles .by{color:var(--steel);font-size:13px;margin-top:6px}
h2{font-family:Bahnschrift,"DIN Alternate","Segoe UI",Arial,sans-serif;font-weight:600;font-size:22px;margin:40px 0 6px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-family:Bahnschrift,"DIN Alternate","Segoe UI",Arial,sans-serif;font-weight:600;font-size:18px;margin:26px 0 8px;display:flex;align-items:center;gap:10px}
.intro{color:var(--steel);max-width:78ch;margin:4px 0 14px}
.status{font-size:21px;line-height:1.4;max-width:62ch;margin:26px 0 18px}
.status b{font-weight:600}
.bar{display:flex;height:46px;border-radius:3px;overflow:hidden;border:1px solid var(--ink)}
.bar div{display:flex;align-items:center;justify-content:center;color:#fff;font-weight:600;font-size:15px;min-width:34px;white-space:nowrap}
.bar .sev-critical{background:var(--crit)}.bar .sev-high{background:var(--high)}.bar .sev-medium{background:var(--med)}.bar .sev-low{background:var(--low)}
.legend{display:grid;grid-template-columns:repeat(4,1fr);gap:0;margin-top:8px}
.legend div{padding:4px 10px 0 0;font-size:13px;color:var(--steel)}
.legend b{display:block;color:var(--ink);font-size:14px}
.legend i{display:inline-block;width:10px;height:10px;margin-right:6px;border-radius:2px;vertical-align:0}
.facts{display:grid;grid-template-columns:repeat(6,1fr);border-top:1px solid var(--line);border-bottom:1px solid var(--line);margin:22px 0 0}
.facts div{padding:12px 12px 12px 0}
.facts dt{font-size:12.5px;color:var(--steel)}
.facts dd{margin:0;font-family:Bahnschrift,"DIN Alternate","Segoe UI",Arial,sans-serif;font-size:26px;font-weight:600}
.facts .alert dd{color:var(--crit)}
table{width:100%;border-collapse:collapse;font-size:13.5px}
.tablewrap{overflow-x:auto}
th{text-align:left;font-weight:600;font-size:12.5px;color:var(--steel);border-bottom:2px solid var(--ink);padding:8px 10px 6px;vertical-align:bottom}
td{border-bottom:1px solid var(--line);padding:10px;vertical-align:top}
tbody tr:nth-child(even) td{background:var(--wash)}
tr{break-inside:avoid;page-break-inside:avoid}
td.num{white-space:nowrap;font-family:Bahnschrift,"Segoe UI",Arial,sans-serif;font-size:18px;font-weight:600;color:var(--blue)}
.fix{min-width:26ch}
.vector{display:block;color:var(--steel);font-size:11px;margin-top:4px;word-break:break-all;max-width:16ch}
.src{display:block;color:var(--steel);font-size:12px;margin-top:4px}
.pill{display:inline-block;padding:2px 8px;border-radius:3px;color:#fff;font-weight:600;font-size:12.5px;white-space:nowrap}
.sev-critical{background:var(--crit)}.sev-high{background:var(--high)}.sev-medium{background:var(--med)}.sev-low{background:var(--low)}.sev-info{background:var(--info)}
.kev{display:inline-block;margin-top:5px;padding:1px 6px;border:1.5px solid var(--crit);color:var(--crit);border-radius:3px;font-weight:700;font-size:11.5px;white-space:nowrap}
.newtag{display:inline-block;margin-top:5px;padding:1px 6px;border:1px solid var(--blue);color:var(--blue);border-radius:3px;font-size:11.5px}
.vid{font-weight:600}.finding{font-weight:600;font-size:12.5px}.vid a{white-space:nowrap}
table.fixed{table-layout:fixed}table.fixed td{overflow-wrap:break-word}
.vtitle{display:block;color:var(--steel);font-size:12.5px;margin-top:2px}
.cwe{display:block;font-size:12px;margin-top:3px;color:var(--steel)}
.assets{margin-bottom:4px}
.asset-label{color:var(--steel);font-size:12px}
details{display:inline}summary{cursor:pointer;color:var(--blue);display:inline}
.due{font-size:12.5px}.due strong{white-space:nowrap}
.due.overdue strong,.due.overdue{color:var(--crit)}
.due.soon strong{color:var(--high)}
.due.none{color:var(--steel)}
.cisa{margin-top:6px;padding:6px 8px;border-left:3px solid var(--crit);background:#fff;font-size:12.5px}
.policy td,.policy th{padding:6px 10px}
.policy{max-width:760px}
.muted{color:var(--steel)}
.empty{padding:18px;border:1px dashed var(--line);color:var(--steel)}
footer{margin-top:44px;padding-top:12px;border-top:3px solid var(--ink);font-size:12.5px;color:var(--steel);display:flex;justify-content:space-between;gap:20px;flex-wrap:wrap}
@media screen and (max-width:760px){.facts{grid-template-columns:repeat(2,1fr)}.legend{grid-template-columns:repeat(2,1fr)}header.top{flex-direction:column;align-items:flex-start}}
@page{size:letter landscape;margin:16mm 11mm 14mm 11mm;
@top-center{content:"TMS INTERNAL USE ONLY";font:600 8.5pt "Segoe UI",Arial,sans-serif;letter-spacing:.14em;color:#1473BC}
@bottom-left{content:"@@FOOTER@@";font:8pt "Segoe UI",Arial,sans-serif;color:#56616F}
@bottom-right{content:"Page " counter(page) " of " counter(pages);font:8pt "Segoe UI",Arial,sans-serif;color:#56616F}}
@media print{
body{font-size:13px}
.marking{display:none}
.page{max-width:none;padding:0}.tablewrap{overflow:visible}
header.top{padding-top:0}
h2{break-after:avoid;page-break-after:avoid}
h3{break-after:avoid;page-break-after:avoid}
thead{display:table-header-group}
.newpage{break-before:page;page-break-before:always}
.newpage h2:first-child{margin-top:0}
.vector{display:none}
.marking,.bar div,.pill,tbody tr:nth-child(even) td{-webkit-print-color-adjust:exact;print-color-adjust:exact}
a{color:var(--ink)}}
.st-done{color:var(--low);font-weight:600}.st-accepted{color:var(--steel);font-weight:600}
.st-open{font-weight:600}.st-progress{color:var(--blue);font-weight:600}
.issue{display:block;color:var(--crit);font-size:12px;font-weight:600;margin-top:3px}
.notes{display:block;color:var(--steel);font-size:12px;margin-top:4px;font-style:italic}
.owner{font-weight:600}
'@).Replace('@@FOOTER@@', $FooterTitle)
    }

    function New-HtmlReport {
        param($Cfg, $Stats, $ActionPlan, $Groups, $NotAffecting, $SourceStats, [string]$LogoPath, [datetime]$AsOf)

        $logoTag = Get-LogoTag $LogoPath
        $css = Get-ReportCss

        $sb = New-Object System.Text.StringBuilder
        $w = { param([string]$t) [void]$sb.Append($t) }

        $month = $AsOf.ToString('MMMM yyyy')
        & $w "<!DOCTYPE html><html lang=""en""><head><meta charset=""utf-8""><meta name=""viewport"" content=""width=device-width, initial-scale=1"">"
        & $w "<title>$(ConvertTo-Html5Text $Cfg.ReportTitle) - $month</title><style>$css</style></head><body>"
        & $w "<div class=""marking"">TMS INTERNAL USE ONLY</div><div class=""page"">"
        & $w "<header class=""top"">$logoTag<div class=""titles""><h1>$(ConvertTo-Html5Text $Cfg.ReportTitle)</h1><div class=""period"">$month</div>"
        & $w "<div class=""by"">Prepared by $(ConvertTo-Html5Text $Cfg.PreparedBy), $(ConvertTo-Html5Text $Cfg.PreparedByTitle). Data as of $($AsOf.ToString('MMMM d, yyyy')).</div></div></header>"

        # ---- Lead: status sentence + severity bar -------------------------
        $s = $Stats
        $sentence = if ($s.OpenVulns -eq 0) {
            'No open vulnerabilities affect the current network in the files reviewed this month.'
        } else {
            $t = "<b>$($s.OpenVulns)</b> open vulnerabilit$(if ($s.OpenVulns -eq 1) {'y'} else {'ies'}) across <b>$($s.Hosts)</b> host$(if ($s.Hosts -ne 1) {'s'})"
            if ($s.Users) { $t += " and <b>$($s.Users)</b> user$(if ($s.Users -ne 1) {'s'})" }
            $t += ', fixed by '
            $t += "<b>$($s.Actions)</b> remediation action$(if ($s.Actions -ne 1) {'s'}). "
            $extra = @()
            if ($s.Kev) { $extra += "<b>$($s.Kev)</b> $(if ($s.Kev -eq 1) {'is'} else {'are'}) on CISA's Known Exploited Vulnerabilities list" }
            if ($s.Overdue) { $extra += "<b>$($s.Overdue)</b> $(if ($s.Overdue -eq 1) {'is'} else {'are'}) past due" }
            if ($extra.Count) { $t += ($extra -join ' and ') + '.' } else { $t += 'Nothing is past due.' }
            $t
        }
        & $w "<p class=""status"">$sentence</p>"

        $sevs = 'Critical', 'High', 'Medium', 'Low'
        $totalSev = ($sevs | ForEach-Object { $s.BySeverity[$_] } | Measure-Object -Sum).Sum
        if ($totalSev -gt 0) {
            & $w '<div class="bar" role="img" aria-label="Open vulnerabilities by severity">'
            foreach ($sv in $sevs) {
                $n = $s.BySeverity[$sv]
                if ($n -gt 0) { & $w ("<div class=""sev-{0}"" style=""flex:{1}"" title=""{2}: {1}"">{1}</div>" -f $sv.ToLower(), $n, $sv) }
            }
            & $w '</div>'
        }
        & $w '<div class="legend">'
        $colors = @{ Critical = 'var(--crit)'; High = 'var(--high)'; Medium = 'var(--med)'; Low = 'var(--low)' }
        $t0 = $Cfg.Thresholds
        $g1 = { param($v) ([double]$v).ToString('0.0', [Globalization.CultureInfo]::InvariantCulture) }
        $lowMin = if ($null -ne $t0.Low) { $t0.Low } else { 0.1 }
        $ranges = @{
            Critical = "CVSS $(& $g1 $t0.Critical)-10.0"
            High     = "CVSS $(& $g1 $t0.High)-$(& $g1 ([double]$t0.Critical - 0.1))"
            Medium   = "CVSS $(& $g1 $t0.Medium)-$(& $g1 ([double]$t0.High - 0.1))"
            Low      = "CVSS $(& $g1 $lowMin)-$(& $g1 ([double]$t0.Medium - 0.1))"
        }
        foreach ($sv in $sevs) {
            & $w ("<div><b><i style=""background:{0}""></i>{1} {2}</b>{4} &middot; fix within {3} days</div>" -f $colors[$sv], $s.BySeverity[$sv], $sv, $Cfg.RemediationSlaDays[$sv], $ranges[$sv])
        }
        & $w '</div>'

        & $w '<dl class="facts">'
        $facts = @(
            @('Hosts affected', $s.Hosts, $false), @('Users affected', $s.Users, $false),
            @('CISA KEV', $s.Kev, ($s.Kev -gt 0)), @('Past due', $s.Overdue, ($s.Overdue -gt 0)),
            @('Due in 14 days', $s.DueSoon, $false), @('New this month', $s.New, $false))
        foreach ($f in $facts) { & $w ("<div{0}><dt>{1}</dt><dd>{2}</dd></div>" -f $(if ($f[2]) { ' class="alert"' } else { '' }), $f[0], $f[1]) }
        & $w '</dl>'

        # ---- Action plan ---------------------------------------------------
        & $w '<section class="newpage"><h2>Remediation action plan</h2>'
        & $w '<p class="intro">Each row is one fix. Hosts and users that need the same fix for the same vulnerabilities are listed together, in priority order: CISA KEV first, then severity, then due date.</p>'
        if (-not @($ActionPlan).Count) {
            & $w '<div class="empty">No remediation actions are open this month.</div>'
        } else {
            & $w '<div class="tablewrap"><table class="fixed"><colgroup><col style="width:12.5%"><col style="width:12%"><col style="width:3%"><col style="width:20.5%"><col style="width:10%"><col style="width:11%"><col style="width:20%"><col style="width:11%"></colgroup><thead><tr><th>CVE ID</th><th>CWE</th><th>#</th><th>Fix</th><th>Severity</th><th>Finding</th><th>Affected</th><th>Due</th></tr></thead><tbody>'
            $i = 0
            foreach ($a in $ActionPlan) {
                $i++
                $titles = @($a.Titles)
                $findHtml = ($titles | Select-Object -First 3 | ForEach-Object { ConvertTo-Html5Text $_ }) -join '<br>'
                if ($titles.Count -gt 3) { $findHtml += "<br><span class=""muted"">and $($titles.Count - 3) more</span>" }
                $tags = ''
                if ($a.IsKev) { $tags += '<br><span class="kev">CISA KEV</span>' }
                if ($a.NewCount) { $tags += '<br><span class="newtag">New</span>' }
                & $w "<tr><td>$(Get-CveCell $a)</td><td>$(Get-CweCell $a)</td><td class=""num"">$i</td><td class=""fix"">$(ConvertTo-Html5Text $a.Remediation)<span class=""src"">Source: $(ConvertTo-Html5Text $a.RemediationSource)</span></td>"
                & $w "<td>$(Get-SevPill $a.Severity $a.Cvss)$tags</td><td class=""finding"">$findHtml</td><td>$(Get-AssetCell $a $Cfg.MaxHostsShownPerRow)</td><td>$(Get-DueCell $a)</td></tr>"
            }
            & $w '</tbody></table></div>'
        }

        & $w '</section>'

        # ---- SLA policy ---------------------------------------------------
        & $w '<h2>Remediation timelines</h2>'
        & $w '<p class="intro">The clock starts when a finding is first detected (from the scanner, or the first report it appeared in). CVEs on the CISA Known Exploited Vulnerabilities catalog are held to the Critical timeline whatever their CVSS score.</p>'
        & $w '<table class="policy"><thead><tr><th>Severity</th><th>CVSS base score</th><th>Fix within</th></tr></thead><tbody>'
        $t = $Cfg.Thresholds
        $f1 = { param($v) ([double]$v).ToString('0.0', [Globalization.CultureInfo]::InvariantCulture) }
        & $w "<tr><td>$(Get-SevPill 'Critical' $null)</td><td>$(& $f1 $t.Critical) to 10.0, or on the CISA KEV catalog</td><td>$($Cfg.RemediationSlaDays.Critical) days</td></tr>"
        & $w "<tr><td>$(Get-SevPill 'High' $null)</td><td>$(& $f1 $t.High) to $(& $f1 ([double]$t.Critical - 0.1))</td><td>$($Cfg.RemediationSlaDays.High) days</td></tr>"
        & $w "<tr><td>$(Get-SevPill 'Medium' $null)</td><td>$(& $f1 $t.Medium) to $(& $f1 ([double]$t.High - 0.1))</td><td>$($Cfg.RemediationSlaDays.Medium) days</td></tr>"
        & $w "<tr><td>$(Get-SevPill 'Low' $null)</td><td>$(& $f1 $(if ($null -ne $t.Low) { $t.Low } else { 0.1 })) to $(& $f1 ([double]$t.Medium - 0.1))</td><td>$($Cfg.RemediationSlaDays.Low) days</td></tr>"
        if (@($Cfg.InternetFacingNetworks).Count -or @($Cfg.InternetFacingHostPatterns).Count) {
            & $w "<tr><td><span class=""pill sev-critical"">CISA immediate</span></td><td>KEV, internet-facing, automatable, total technical impact (CISA BOD 26-04)</td><td>$($Cfg.CisaImmediateDays) days</td></tr>"
        }
        & $w '</tbody></table>'

        # ---- Findings by severity -------------------------------------------
        & $w '<section class="newpage"><h2>Findings by severity</h2>'
        & $w '<p class="intro">One row per vulnerability and fix. CVSS scores come from NIST NVD, weakness names from MITRE CWE, and exploitation data from CISA.</p>'
        foreach ($sv in $sevs + 'Info') {
            $rows = @($Groups | Where-Object { $_.Severity -eq $sv })
            if (-not $rows.Count) { continue }
            & $w "<h3>$(Get-SevPill $sv $null) $($rows.Count) vulnerabilit$(if ($rows.Count -eq 1) {'y'} else {'ies'})</h3>"
            & $w '<div class="tablewrap"><table class="fixed"><colgroup><col style="width:25%"><col style="width:9%"><col style="width:23%"><col style="width:32%"><col style="width:11%"></colgroup><thead><tr><th>CVE ID / Finding</th><th>CVSS</th><th>Affected</th><th>Remediation</th><th>Due</th></tr></thead><tbody>'
            foreach ($g in $rows) {
                $id = @($g.VulnIds)[0]
                $cell = if (@($g.Cves).Count) { "<span class=""vid"">$(Get-VulnLink $id)</span>" }
                        else { "<span class=""muted"">No CVE</span><br><span class=""vid"">$(Get-VulnLink $id)</span>" }
                if ($g.Title -and $g.Title -ne $id -and -not $id.EndsWith($g.Title)) { $cell += "<span class=""vtitle"">$(ConvertTo-Html5Text $g.Title)</span>" }
                if (@($g.Cwes).Count) {
                    $cn = if ($g.CweNames) { ' ' + (ConvertTo-Html5Text $g.CweNames) } else { '' }
                    $cell += "<span class=""cwe"">$(Get-CweLinks $g.Cwes)$cn</span>"
                }
                if ($g.IsKev) { $cell += "<span class=""kev"">CISA KEV$(if ($g.KevRansomware) {', ransomware use'})</span>" }
                if ($g.NewCount) { $cell += ' <span class="newtag">New</span>' }
                $cvss = if ($null -ne $g.Cvss) { '{0:N1}' -f $g.Cvss } else { '<span class="muted">n/a</span>' }
                if ($g.CvssVector) { $cvss += "<span class=""vector"">$(ConvertTo-Html5Text ($g.CvssVector -replace '^CVSS:[\d.]+/', ''))</span>" }
                $rem = "$(ConvertTo-Html5Text $g.Remediation)<span class=""src"">Source: $(ConvertTo-Html5Text $g.RemediationSource) &middot; Found by $(ConvertTo-Html5Text $g.Sources)</span>"
                if ($g.IsKev -and $g.KevAction -and $g.RemediationSource -ne 'CISA KEV') {
                    $rem += "<div class=""cisa""><b>CISA required action</b> (federal due date $(ConvertTo-Html5Text $g.KevDueDate)): $(ConvertTo-Html5Text $g.KevAction)</div>"
                }
                if ($g.Ssvc) { $rem += "<span class=""src"">CISA SSVC: $(ConvertTo-Html5Text $g.Ssvc)</span>" }
                & $w "<tr><td>$cell</td><td>$cvss</td><td>$(Get-AssetCell $g $Cfg.MaxHostsShownPerRow)</td><td class=""fix"">$rem</td><td>$(Get-DueCell $g)</td></tr>"
            }
            & $w '</tbody></table></div>'
        }
        if (-not @($Groups).Count) { & $w '<div class="empty">No open findings affect the current network.</div>' }
        & $w '</section>'

        # ---- Not affecting ---------------------------------------------------
        & $w '<section class="newpage"><h2>Not affecting the current network</h2>'
        & $w '<p class="intro">Findings in the exports that are closed, outside the configured TMS networks, or not seen recently. They are excluded from the counts above.</p>'
        if (@($NotAffecting).Count) {
            & $w '<div class="tablewrap"><table><thead><tr><th>Vulnerability</th><th>Severity</th><th>Assets</th><th>Why excluded</th></tr></thead><tbody>'
            foreach ($n in $NotAffecting) {
                $nid = @($n.VulnIds)[0]
                $ntitle = if ($n.Title -and -not $nid.EndsWith($n.Title)) { '<span class="vtitle">' + (ConvertTo-Html5Text $n.Title) + '</span>' } else { '' }
                & $w "<tr><td><span class=""vid"">$(Get-VulnLink $nid)</span>$ntitle</td><td>$(Get-SevPill $n.Severity $n.Cvss)</td><td>$(Get-AssetCell $n $Cfg.MaxHostsShownPerRow)</td><td>$(ConvertTo-Html5Text $n.Reason)</td></tr>"
            }
            & $w '</tbody></table></div>'
        } else { & $w '<div class="empty">Every finding in the exports affects the current network.</div>' }

        # ---- Sources -----------------------------------------------------------
        & $w '<h2>Files reviewed</h2><div class="tablewrap"><table><thead><tr><th>File</th><th>Detected as</th><th>Rows</th><th>Findings</th><th>Affecting network</th></tr></thead><tbody>'
        foreach ($ss in $SourceStats) {
            & $w "<tr><td>$(ConvertTo-Html5Text $ss.File)</td><td>$(ConvertTo-Html5Text $ss.Type)</td><td>$($ss.Rows)</td><td>$($ss.Findings)</td><td>$($ss.Affecting)</td></tr>"
        }
        & $w '</tbody></table></div></section>'

        & $w "<footer><span>$(ConvertTo-Html5Text $Cfg.Organization). $(ConvertTo-Html5Text $Cfg.PreparedBy), $(ConvertTo-Html5Text $Cfg.PreparedByTitle).</span>"
        & $w "<span>Enrichment: NIST NVD, CIRCL, MITRE CWE, CISA KEV. Generated $((Get-Date).ToString('yyyy-MM-dd HH:mm')) by TMS-VulnReport v$ScriptVersion.</span></footer>"
        & $w '</div></body></html>'
        return $sb.ToString()
    }

    function Publish-Report {
        # Renders $Html to "$OutBase.pdf" with Edge/Chrome; falls back to "$OutBase.html"
        param([string]$Html, [string]$OutBase)
        $outBase = $OutBase
        # The HTML is only the layout source for the PDF; it lives in %TEMP% unless -KeepHtml
        $htmlPath = if ($KeepHtml) { "$outBase.html" } else { Join-Path ([IO.Path]::GetTempPath()) ("TMS_Report_" + [guid]::NewGuid().ToString('N') + '.html') }
        [IO.File]::WriteAllText($htmlPath, $html, (New-Object System.Text.UTF8Encoding($true)))

        $pdfPath = "$outBase.pdf"
        $browser = Find-PdfBrowser $BrowserPath
        $pdfOk = $false
        if ($browser) {
            Write-Info "Rendering PDF with $(Split-Path $browser -Leaf)..."
            try { $pdfOk = Export-HtmlToPdf $htmlPath $pdfPath $browser }
            catch { Write-Bad "PDF rendering failed: $($_.Exception.Message)" }
        } else {
            Write-Bad 'Microsoft Edge or Google Chrome was not found, so the PDF could not be rendered. Use -BrowserPath to point at msedge.exe.'
        }
        if ($pdfOk) {
            Write-Good "PDF report written: $pdfPath"
            if (-not $KeepHtml) { Remove-Item -LiteralPath $htmlPath -Force -ErrorAction SilentlyContinue; $htmlPath = $null }
        } else {
            $pdfPath = $null
            if (-not $KeepHtml) {   # keep the layout so nothing is lost; it can be printed to PDF by hand
                $fallback = "$outBase.html"
                Move-Item -LiteralPath $htmlPath -Destination $fallback -Force
                $htmlPath = $fallback
            }
            Write-Bad "Saved the report as HTML instead: $htmlPath (open it and choose Print > Save as PDF)."
        }
        return [pscustomobject]@{ Pdf = $pdfPath; Html = $htmlPath }
    }

    function Find-PdfBrowser {
        param([string]$Preferred)
        if ($Preferred) {
            if (Test-Path -LiteralPath $Preferred) { return (Resolve-Path -LiteralPath $Preferred).ProviderPath }
            Write-Bad "BrowserPath not found: $Preferred"
        }
        $candidates = @(
            "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
            "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
            "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe",
            "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
            "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
            "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
        ) | Where-Object { $_ -and -not $_.StartsWith('\') -and (Test-Path -LiteralPath $_) }
        if (@($candidates).Count) { return @($candidates)[0] }
        foreach ($n in 'msedge', 'microsoft-edge', 'google-chrome', 'chrome', 'chromium', 'chromium-browser') {
            $cmd = Get-Command $n -ErrorAction SilentlyContinue
            if ($cmd) { return $cmd.Source }
        }
        return $null
    }

    function Export-HtmlToPdf {
        param([string]$HtmlPath, [string]$PdfPath, [string]$Browser)
        if (Test-Path -LiteralPath $PdfPath) { Remove-Item -LiteralPath $PdfPath -Force }
        # A private, throw-away browser profile keeps this from attaching to an Edge
        # window the user already has open (which would return before printing).
        $profileDir = Join-Path ([IO.Path]::GetTempPath()) ("tms-pdf-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
        $uri = (New-Object System.Uri($HtmlPath)).AbsoluteUri
        $browserArgs = @('--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
            '--disable-extensions', '--run-all-compositor-stages-before-draw',
            '--no-pdf-header-footer', '--print-to-pdf-no-header',
            "--user-data-dir=`"$profileDir`"", "--print-to-pdf=`"$PdfPath`"", $uri)
        $onWindows = ($PSVersionTable.PSEdition -eq 'Desktop') -or ($IsWindows -eq $true)
        if (-not $onWindows) { $browserArgs = @('--no-sandbox') + $browserArgs }
        try {
            $errLog = Join-Path $profileDir 'browser-stderr.txt'; $outLog = Join-Path $profileDir 'browser-stdout.txt'
            $sp = @{ FilePath = $Browser; ArgumentList = $browserArgs; PassThru = $true; RedirectStandardError = $errLog; RedirectStandardOutput = $outLog }
            if ($onWindows) { $sp['WindowStyle'] = 'Hidden' }
            $proc = Start-Process @sp
            # Watch for the PDF while the browser runs. As soon as it exists and its
            # size stops changing, it is finished - close the browser if it lingers.
            $deadline = (Get-Date).AddSeconds(90); $lastSize = -1; $stable = 0
            while ((Get-Date) -lt $deadline) {
                Start-Sleep -Milliseconds 500
                if (Test-Path -LiteralPath $PdfPath) {
                    $size = (Get-Item -LiteralPath $PdfPath).Length
                    if ($size -gt 0 -and $size -eq $lastSize) { $stable++ } else { $stable = 0 }
                    $lastSize = $size
                    if ($stable -ge 2) { break }
                } elseif ($proc.HasExited) {
                    Start-Sleep -Seconds 2                    # some builds hand off to a child process
                    if (-not (Test-Path -LiteralPath $PdfPath)) { break }
                }
            }
            if (-not $proc.HasExited) { try { $proc.Kill() } catch { } }
        } finally {
            Start-Sleep -Milliseconds 300
            Remove-Item -LiteralPath $profileDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        return ((Test-Path -LiteralPath $PdfPath) -and (Get-Item -LiteralPath $PdfPath).Length -gt 0)
    }
    # ==================================================================
    #  EXCEL (.xlsx / .xlsm) READER
    #  An .xlsx is a zip of XML parts. Read it directly so no Excel,
    #  ImportExcel module or Office install is needed. The file is opened
    #  with shared access, so it can be read while it is open in Excel.
    # ==================================================================
    function ConvertFrom-XlsxColumn {
        param([string]$Ref)
        $letters = ($Ref -replace '[^A-Za-z]', '').ToUpperInvariant()
        $n = 0
        foreach ($ch in $letters.ToCharArray()) { $n = ($n * 26) + ([int][char]$ch - 64) }
        return ($n - 1)
    }

    function Read-XlsxWorkbook {
        param([string]$File)
        try { Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop } catch { }
        $fs = [IO.File]::Open($File, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $zip = New-Object System.IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Read)
            $readXml = {
                param([string]$Name)
                $entry = $zip.GetEntry($Name)
                if (-not $entry) { return $null }
                $sr = New-Object IO.StreamReader($entry.Open())
                try { $doc = New-Object Xml.XmlDocument; $doc.LoadXml($sr.ReadToEnd()); return $doc } finally { $sr.Dispose() }
            }
            # Shared strings (most text cells point into this list)
            $shared = New-Object System.Collections.Generic.List[string]
            $sst = & $readXml 'xl/sharedStrings.xml'
            if ($sst) {
                foreach ($si in $sst.SelectNodes("//*[local-name()='si']")) {
                    $parts = $si.SelectNodes(".//*[local-name()='t'][not(ancestor::*[local-name()='rPh'])]")
                    $shared.Add((@($parts | ForEach-Object { $_.InnerText }) -join ''))
                }
            }
            # Sheet name -> XML part
            $wb = & $readXml 'xl/workbook.xml'
            $rels = & $readXml 'xl/_rels/workbook.xml.rels'
            $targets = @{}
            foreach ($r in $rels.SelectNodes("//*[local-name()='Relationship']")) { $targets[$r.GetAttribute('Id')] = $r.GetAttribute('Target') }
            $sheets = New-Object System.Collections.Generic.List[object]
            foreach ($sh in $wb.SelectNodes("//*[local-name()='sheet']")) {
                $rid = @($sh.Attributes | Where-Object { $_.LocalName -eq 'id' } | ForEach-Object { $_.Value })[0]
                $target = "$($targets[$rid])"
                if (-not $target) { continue }
                $part = if ($target.StartsWith('/')) { $target.TrimStart('/') } else { 'xl/' + $target }
                $xml = & $readXml $part
                $rows = New-Object System.Collections.Generic.List[object]
                if ($xml) {
                    foreach ($row in $xml.SelectNodes("//*[local-name()='sheetData']/*[local-name()='row']")) {
                        $cells = @{}; $max = -1; $col = -1
                        foreach ($c in $row.SelectNodes("*[local-name()='c']")) {
                            $ref = $c.GetAttribute('r')
                            $col = if ($ref) { ConvertFrom-XlsxColumn $ref } else { $col + 1 }
                            $t = $c.GetAttribute('t')
                            $vNode = $c.SelectSingleNode("*[local-name()='v']")
                            $v = if ($vNode) { $vNode.InnerText } else { '' }
                            $val = switch ($t) {
                                's' { if ($v -match '^\d+$' -and [int]$v -lt $shared.Count) { $shared[[int]$v] } else { '' } }
                                'inlineStr' { (@($c.SelectNodes(".//*[local-name()='t']") | ForEach-Object { $_.InnerText }) -join '') }
                                'b' { if ($v -eq '1') { 'TRUE' } else { 'FALSE' } }
                                default { $v }
                            }
                            $cells[$col] = "$val"
                            if ($col -gt $max) { $max = $col }
                        }
                        $arr = New-Object string[] ($max + 1)
                        foreach ($k in $cells.Keys) { $arr[$k] = $cells[$k] }
                        $rows.Add($arr)
                    }
                }
                $sheets.Add([pscustomobject]@{ Name = $sh.GetAttribute('name'); Rows = $rows })
            }
            return $sheets.ToArray()
        } finally {
            $fs.Dispose()
        }
    }

    function ConvertFrom-ExcelDate {
        # Excel stores dates as a day count (e.g. 46319); text dates are parsed normally
        param([string]$Text)
        if (-not $Text) { return $null }
        $d = 0.0
        if ([double]::TryParse($Text, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d) -and $d -gt 20000 -and $d -lt 80000) {
            return [DateTime]::FromOADate($d).Date
        }
        return (ConvertTo-DateOrNull $Text)
    }

    # ==================================================================
    #  REMEDIATION WORKBOOKS (the Action Plan, filled in and brought back)
    # ==================================================================
    function Test-RemediationFileName {
        param([string]$File, $Cfg)
        $leaf = [IO.Path]::GetFileName($File)
        foreach ($pat in @($Cfg.RemediationFilePatterns)) { if ($pat -and $leaf -like $pat) { return $true } }
        return $false
    }

    function Test-IsReportOutput {
        # Findings / All Findings CSVs this script wrote - reading them back would double-count
        param([string]$File)
        $leaf = [IO.Path]::GetFileName($File)
        return ($leaf -match '(?i)^TMS_Vulnerability_Report_.*_(Findings|AllFindings)\.csv$' -or $leaf -match '(?i)^TMS_Remediation_Status_')
    }

    function Read-RemediationRows {
        # Returns @{ Sheet; Rows } where Rows are objects keyed by the header row
        param([string]$File)
        $ext = [IO.Path]::GetExtension($File).ToLowerInvariant()
        if ($ext -eq '.csv') {
            return [pscustomobject]@{ Sheet = ''; Rows = @(Import-Csv -LiteralPath $File) }
        }
        $sheets = @(Read-XlsxWorkbook $File)
        $isCveHeader = { param($v) ("$v" -replace '[^A-Za-z]', '').ToLowerInvariant() -in 'cveid', 'cve', 'cveids' }
        foreach ($sh in $sheets) {
            $rows = $sh.Rows
            $headerAt = -1
            for ($r = 0; $r -lt [Math]::Min(25, $rows.Count); $r++) {
                if (@($rows[$r] | Where-Object { & $isCveHeader $_ }).Count) { $headerAt = $r; break }
            }
            if ($headerAt -lt 0) {
                # No "CVE ID" header - accept the sheet if CVE numbers appear in it anyway
                $hasCve = $false
                for ($r = 0; $r -lt [Math]::Min(200, $rows.Count); $r++) { if ((@($rows[$r]) -join ' ') -match '(?i)CVE-\d{4}-\d{4,}') { $hasCve = $true; break } }
                if (-not $hasCve) { continue }
                for ($r = 0; $r -lt $rows.Count; $r++) { if (@($rows[$r] | Where-Object { $_ }).Count -ge 2) { $headerAt = $r; break } }
            }
            $header = @($rows[$headerAt])
            $names = New-Object System.Collections.Generic.List[string]
            for ($c = 0; $c -lt $header.Count; $c++) {
                $n = "$($header[$c])".Trim(); if (-not $n) { $n = "Column$($c + 1)" }
                while ($names.Contains($n)) { $n = "$n~" }
                $names.Add($n)
            }
            $objs = New-Object System.Collections.Generic.List[object]
            for ($r = $headerAt + 1; $r -lt $rows.Count; $r++) {
                $cells = @($rows[$r])
                if (-not @($cells | Where-Object { "$_".Trim() }).Count) { continue }
                $o = [ordered]@{}
                for ($c = 0; $c -lt $names.Count; $c++) { $o[$names[$c]] = if ($c -lt $cells.Count) { "$($cells[$c])" } else { '' } }
                $objs.Add([pscustomobject]$o)
            }
            return [pscustomobject]@{ Sheet = $sh.Name; Rows = $objs.ToArray() }
        }
        return [pscustomobject]@{ Sheet = ''; Rows = @() }
    }

    function Test-ActionPlanHasEntries {
        # A fresh Action Plan CSV (nothing filled in) is report output, not a tracker
        param([object[]]$Rows)
        if (-not $Rows.Count) { return $false }
        $map = New-ColumnMap $Rows[0].PSObject.Properties.Name
        foreach ($r in $Rows) { if (Get-Col $r $map 'owner', 'status', 'target date', 'notes') { return $true } }
        return $false
    }

    function Get-RemediationItems {
        param([object[]]$Rows, $Kev, [datetime]$Today)
        if (-not $Rows.Count) { return @() }
        $map = New-ColumnMap $Rows[0].PSObject.Properties.Name
        $items = New-Object System.Collections.Generic.List[object]
        $split = { param($t) @("$t" -split '\s*[;\r\n]+\s*' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
        foreach ($r in $Rows) {
            $cveText = Get-Col $r $map 'cve id', 'cve', 'cve ids', 'vulnerabilities'
            $cves = @(Get-CveList "$cveText $(Get-Col $r $map 'vulnerabilities', 'finding ids')")
            $fix = Get-Col $r $map 'fix', 'remediation', 'remediation guidance'
            $finding = Get-Col $r $map 'finding', 'title', 'vulnerability'
            if (-not $cves.Count -and -not $fix -and -not $finding) { continue }
            $sev = ConvertTo-SeverityWord (Get-Col $r $map 'severity', 'sla tier')
            if (-not $sev) { $sev = 'Info' }
            $due = ConvertFrom-ExcelDate (Get-Col $r $map 'due date', 'sla due date', 'due')
            $target = ConvertFrom-ExcelDate (Get-Col $r $map 'target date', 'target', 'planned date')
            $owner = Get-Col $r $map 'owner', 'assigned to', 'assignee'
            $statusRaw = Get-Col $r $map 'status', 'remediation status', 'state'
            $status = switch -Regex ($statusRaw) {
                '(?i)^(done|complete|completed|closed|fixed|remediated|resolved|patched|mitigated)' { 'Completed'; break }
                '(?i)(accept|exception|waiv|defer)' { 'Risk accepted'; break }
                '(?i)(progress|working|started|scheduled|pending|assigned)' { 'In progress'; break }
                default { if ($statusRaw) { $statusRaw } else { 'Open' } }
            }
            $isOpen = $status -notin 'Completed', 'Risk accepted'
            $sheetKev = (Get-Col $r $map 'cisa kev') -match '(?i)^(yes|true|y|1)$'
            $kevNow = @($cves | Where-Object { $Kev -and $Kev.ContainsKey($_) })
            $days = if ($due) { [int][Math]::Floor(($due - $Today).TotalDays) } else { $null }
            $issues = New-Object System.Collections.Generic.List[string]
            if ($isOpen) {
                if ($due -and $days -lt 0) { $issues.Add("Past SLA due date by $([Math]::Abs($days)) days") }
                if (-not $owner) { $issues.Add('No owner') }
                if ($target -and $due -and $target -gt $due) { $issues.Add("Target date is $([int]($target - $due).TotalDays) days after the SLA due date") }
                if ($target -and $target -lt $Today) { $issues.Add('Target date has passed') }
                if ($kevNow.Count -and -not $sheetKev) { $issues.Add("Added to CISA KEV since this plan was made ($($kevNow -join ', ')) - hold to the Critical timeline") }
            }
            $cwes = @(Get-CweList (Get-Col $r $map 'cwe', 'cwes', 'cwe id'))
            $items.Add([pscustomobject][ordered]@{
                Priority = Get-Col $r $map 'priority', '#'
                Cves = $cves
                Cwes = $cwes
                CweNames = Get-Col $r $map 'cwe name', 'cwe names'
                Fix = $fix
                Finding = $finding
                Severity = $sev
                SeverityRank = Get-SeverityRank $sev
                Cvss = ConvertTo-ScoreOrNull (Get-Col $r $map 'max cvss', 'cvss', 'cvss score')
                IsKev = ($sheetKev -or $kevNow.Count -gt 0)
                Hosts = & $split (Get-Col $r $map 'affected hosts', 'hosts', 'host')
                Users = & $split (Get-Col $r $map 'affected users', 'users', 'user')
                Locations = & $split (Get-Col $r $map 'code locations', 'locations')
                Sources = Get-Col $r $map 'found by', 'source'
                Owner = $owner
                Status = $status
                IsOpen = $isOpen
                DueDate = $due
                DaysRemaining = $days
                SlaStatus = if (-not $isOpen) { $status } elseif (-not $due) { 'No SLA' } elseif ($days -lt 0) { 'Overdue' } elseif ($days -le 14) { 'Due soon' } else { 'On track' }
                TargetDate = $target
                Notes = Get-Col $r $map 'notes', 'comments', 'comment'
                Issues = $issues.ToArray()
            })
        }
        return $items.ToArray()
    }

    function New-RemediationHtml {
        param($Cfg, [object[]]$Items, [string]$SourceLabel, [string]$LogoPath, [datetime]$AsOf)
        $sb = New-Object System.Text.StringBuilder
        $w = { param([string]$t) [void]$sb.Append($t) }
        $e = { param($t) ConvertTo-Html5Text $t }
        $fmt = { param($d) if ($d) { ([datetime]$d).ToString('MMM d, yyyy') } else { '' } }
        $month = $AsOf.ToString('MMMM yyyy')
        $title = 'Remediation Status Report'

        $open = @($Items | Where-Object { $_.IsOpen })
        $done = @($Items | Where-Object { $_.Status -eq 'Completed' })
        $accepted = @($Items | Where-Object { $_.Status -eq 'Risk accepted' })
        $overdue = @($open | Where-Object { $_.SlaStatus -eq 'Overdue' })
        $soon = @($open | Where-Object { $_.SlaStatus -eq 'Due soon' })
        $noOwner = @($open | Where-Object { -not $_.Owner })
        $late = @($open | Where-Object { $_.TargetDate -and $_.DueDate -and $_.TargetDate -gt $_.DueDate })
        $attention = @($open | Where-Object { $_.Issues.Count })

        & $w "<!DOCTYPE html><html lang=""en""><head><meta charset=""utf-8""><meta name=""viewport"" content=""width=device-width, initial-scale=1"">"
        & $w "<title>$title - $month</title><style>$(Get-ReportCss -FooterTitle 'Remediation Status Report')</style></head><body>"
        & $w "<div class=""marking"">TMS INTERNAL USE ONLY</div><div class=""page"">"
        & $w "<header class=""top"">$(Get-LogoTag $LogoPath)<div class=""titles""><h1>$title</h1><div class=""period"">$month</div>"
        & $w "<div class=""by"">Prepared by $(& $e $Cfg.PreparedBy), $(& $e $Cfg.PreparedByTitle). Data as of $($AsOf.ToString('MMMM d, yyyy')). Source: $(& $e $SourceLabel).</div></div></header>"

        $n = $Items.Count
        $sentence = "<b>$($open.Count)</b> of $n remediation item$(if ($n -ne 1) {'s'}) $(if ($open.Count -eq 1) {'is'} else {'are'}) still open"
        if ($done.Count) { $sentence += " and <b>$($done.Count)</b> $(if ($done.Count -eq 1) {'is'} else {'are'}) complete" }
        $sentence += '. '
        $extra = @()
        if ($overdue.Count) { $extra += "<b>$($overdue.Count)</b> $(if ($overdue.Count -eq 1) {'is'} else {'are'}) past the SLA due date" }
        if ($noOwner.Count) { $extra += "<b>$($noOwner.Count)</b> $(if ($noOwner.Count -eq 1) {'has'} else {'have'}) no owner" }
        if ($late.Count) { $extra += "<b>$($late.Count)</b> $(if ($late.Count -eq 1) {'has a target date'} else {'have target dates'}) later than the SLA allows" }
        if ($extra.Count) { $sentence += ($extra -join ', ') + '.' } elseif ($open.Count) { $sentence += 'Every open item has an owner and is within its SLA.' }
        & $w "<p class=""status"">$sentence</p>"

        & $w '<dl class="facts">'
        foreach ($f in @(@('Open', $open.Count, $false), @('Completed', $done.Count, $false), @('Past due', $overdue.Count, ($overdue.Count -gt 0)),
                         @('Due in 14 days', $soon.Count, $false), @('No owner', $noOwner.Count, ($noOwner.Count -gt 0)), @('Target after SLA', $late.Count, ($late.Count -gt 0)))) {
            & $w ("<div{0}><dt>{1}</dt><dd>{2}</dd></div>" -f $(if ($f[2]) { ' class="alert"' } else { '' }), $f[0], $f[1])
        }
        & $w '</dl>'

        # ---- By owner
        & $w '<h2>By owner</h2>'
        & $w '<table class="policy"><thead><tr><th>Owner</th><th>Open</th><th>Past due</th><th>Due in 14 days</th><th>Completed</th><th>Risk accepted</th></tr></thead><tbody>'
        $byOwner = $Items | Group-Object { if ($_.Owner) { $_.Owner } else { '(no owner)' } } |
                   Sort-Object @{ e = { @($_.Group | Where-Object { $_.SlaStatus -eq 'Overdue' }).Count }; Descending = $true }, @{ e = { @($_.Group | Where-Object { $_.IsOpen }).Count }; Descending = $true }, Name
        foreach ($g in $byOwner) {
            $gi = @($g.Group)
            $od = @($gi | Where-Object { $_.SlaStatus -eq 'Overdue' }).Count
            $ownerCell = if ($g.Name -eq '(no owner)') { '<span class="issue" style="margin:0">(no owner)</span>' } else { "<span class=""owner"">$(& $e $g.Name)</span>" }
            & $w ("<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td><td>{5}</td></tr>" -f $ownerCell,
                  @($gi | Where-Object { $_.IsOpen }).Count, $(if ($od) { "<b style=""color:var(--crit)"">$od</b>" } else { '0' }),
                  @($gi | Where-Object { $_.SlaStatus -eq 'Due soon' }).Count, @($gi | Where-Object { $_.Status -eq 'Completed' }).Count,
                  @($gi | Where-Object { $_.Status -eq 'Risk accepted' }).Count)
        }
        & $w '</tbody></table>'

        $cveCell = {
            param($it)
            if (@($it.Cves).Count) { return (@($it.Cves) | Select-Object -First 6 | ForEach-Object { "<span class=""vid"">$(Get-VulnLink $_)</span>" }) -join '<br>' }
            return '<span class="muted">No CVE</span>'
        }
        $statusCell = {
            param($it)
            $cls = switch ($it.Status) { 'Completed' { 'st-done' } 'Risk accepted' { 'st-accepted' } 'In progress' { 'st-progress' } default { 'st-open' } }
            $h = if ($it.Owner) { "<span class=""owner"">$(& $e $it.Owner)</span><br>" } else { '<span class="issue" style="margin:0">No owner</span>' }
            $h += "<span class=""$cls"">$(& $e $it.Status)</span>"
            if ($it.Notes) { $h += "<span class=""notes"">$(& $e $it.Notes)</span>" }
            return $h
        }
        $dueCell = {
            param($it)
            if (-not $it.DueDate) { return '<span class="due none">No SLA date</span>' }
            if (-not $it.IsOpen) { return "<span class=""due none""><strong>$(& $fmt $it.DueDate)</strong></span>" }
            return (Get-DueCell ([pscustomobject]@{ DueDate = $it.DueDate; DaysRemaining = $it.DaysRemaining; SlaStatus = $it.SlaStatus }))
        }
        $targetCell = {
            param($it)
            if (-not $it.TargetDate) { return $(if ($it.IsOpen) { '<span class="muted">Not set</span>' } else { '' }) }
            $warn = $it.IsOpen -and (($it.DueDate -and $it.TargetDate -gt $it.DueDate) -or $it.TargetDate -lt $AsOf.Date)
            return "<span class=""due$(if ($warn) {' overdue'})""><strong>$(& $fmt $it.TargetDate)</strong></span>"
        }
        $fixCell = {
            param($it)
            $h = & $e $it.Fix
            if ($it.Finding -and $it.Finding -ne $it.Fix) { $h += "<span class=""src"">$(& $e $it.Finding)</span>" }
            return $h
        }

        # ---- Needs attention
        & $w '<section class="newpage"><h2>Needs attention</h2>'
        & $w '<p class="intro">Open items that are past their SLA due date, have no owner, have a target date later than the SLA allows or already missed, or were added to the CISA Known Exploited Vulnerabilities catalog after the plan was made.</p>'
        if ($attention.Count) {
            & $w '<div class="tablewrap"><table class="fixed"><colgroup><col style="width:13%"><col style="width:25%"><col style="width:9%"><col style="width:13%"><col style="width:10%"><col style="width:10%"><col style="width:20%"></colgroup><thead><tr><th>CVE ID</th><th>Fix</th><th>Severity</th><th>Owner / Status</th><th>SLA due</th><th>Target</th><th>Issue</th></tr></thead><tbody>'
            $sorted = $attention | Sort-Object @{ e = { if ($_.DueDate) { $_.DueDate } else { [datetime]::MaxValue } } }, @{ e = { $_.SeverityRank }; Descending = $true }
            foreach ($it in $sorted) {
                $kevTag = if ($it.IsKev) { '<br><span class="kev">CISA KEV</span>' } else { '' }
                $iss = (@($it.Issues) | ForEach-Object { "<span class=""issue"" style=""margin-top:0"">$(& $e $_)</span>" }) -join ''
                & $w "<tr><td>$(& $cveCell $it)</td><td class=""fix"">$(& $fixCell $it)</td><td>$(Get-SevPill $it.Severity $it.Cvss)$kevTag</td><td>$(& $statusCell $it)</td><td>$(& $dueCell $it)</td><td>$(& $targetCell $it)</td><td>$iss</td></tr>"
            }
            & $w '</tbody></table></div>'
        } else { & $w '<div class="empty">Nothing needs attention. Every open item has an owner and is on track.</div>' }
        & $w '</section>'

        # ---- All items
        & $w '<section class="newpage"><h2>All remediation items</h2>'
        & $w '<p class="intro">Open items first, soonest SLA due date first, then risk-accepted and completed items.</p>'
        & $w '<div class="tablewrap"><table class="fixed"><colgroup><col style="width:12.5%"><col style="width:10%"><col style="width:19.5%"><col style="width:10.5%"><col style="width:15.5%"><col style="width:12%"><col style="width:10%"><col style="width:10%"></colgroup><thead><tr><th>CVE ID</th><th>CWE</th><th>Fix</th><th>Severity</th><th>Affected</th><th>Owner / Status</th><th>SLA due</th><th>Target</th></tr></thead><tbody>'
        $order = $Items | Sort-Object @{ e = { if ($_.IsOpen) { 0 } elseif ($_.Status -eq 'Risk accepted') { 1 } else { 2 } } },
                                      @{ e = { if ($_.DueDate) { $_.DueDate } else { [datetime]::MaxValue } } }, @{ e = { $_.SeverityRank }; Descending = $true }
        foreach ($it in $order) {
            $kevTag = if ($it.IsKev) { '<br><span class="kev">CISA KEV</span>' } else { '' }
            & $w "<tr><td>$(& $cveCell $it)</td><td>$(Get-CweCell $it)</td><td class=""fix"">$(& $fixCell $it)</td><td>$(Get-SevPill $it.Severity $it.Cvss)$kevTag</td><td>$(Get-AssetCell $it $Cfg.MaxHostsShownPerRow)</td><td>$(& $statusCell $it)</td><td>$(& $dueCell $it)</td><td>$(& $targetCell $it)</td></tr>"
        }
        & $w '</tbody></table></div></section>'

        & $w "<footer><span>$(& $e $Cfg.Organization). $(& $e $Cfg.PreparedBy), $(& $e $Cfg.PreparedByTitle).</span>"
        & $w "<span>Remediation status only: no scanner or enrichment lookups were run. CISA KEV status checked against the current catalog. Generated $((Get-Date).ToString('yyyy-MM-dd HH:mm')) by TMS-VulnReport v$ScriptVersion.</span></footer>"
        & $w '</div></body></html>'
        return $sb.ToString()
    }

    function Invoke-RemediationReport {
        # One Remediation Status report (PDF + CSV) per Action Plan workbook
        param([string]$File, $Cfg, $Kev, [string]$OutputFolder, [datetime]$ReportDate, [int]$Index, [int]$Total)
        $leaf = Split-Path $File -Leaf
        $read = Read-RemediationRows $File
        if (-not @($read.Rows).Count) {
            Write-Bad "$leaf - no sheet with CVE IDs was found. Skipped."
            return $null
        }
        $items = @(Get-RemediationItems @($read.Rows) $Kev $ReportDate.Date)
        if (-not $items.Count) { Write-Bad "$leaf - the sheet has no remediation rows. Skipped."; return $null }
        $sheetLabel = if ($read.Sheet) { " (sheet '$($read.Sheet)')" } else { '' }
        Write-Good "$leaf$sheetLabel - remediation workbook, $($items.Count) item(s)."

        $stamp = $ReportDate.ToString('yyyy-MM') + '_' + (Get-Date -Format 'yyyyMMdd-HHmm')
        $tag = ''
        if ($Total -gt 1) {     # several workbooks in one run: add the workbook's name so the reports don't collide
            $t = [IO.Path]::GetFileNameWithoutExtension($File) -replace '(?i)^TMS_Vulnerability_Report_', ''
            $t = ($t -replace '[^A-Za-z0-9-]+', '_').Trim('_')
            if ($t.Length -gt 40) { $t = $t.Substring(0, 40).Trim('_') }
            $tag = "_$t"
        }
        $outBase = Join-Path $OutputFolder "TMS_Remediation_Status_$stamp$tag"

        $join = { param($v) (@($v) | Where-Object { $_ }) -join '; ' }
        $fmtDate = { param($d) if ($d) { ([datetime]$d).ToString('yyyy-MM-dd') } else { '' } }
        $items | Sort-Object @{ e = { if ($_.IsOpen) { 0 } else { 1 } } }, @{ e = { if ($_.DueDate) { $_.DueDate } else { [datetime]::MaxValue } } } | ForEach-Object {
            [pscustomobject][ordered]@{
                'CVE ID' = $(if (@($_.Cves).Count) { & $join $_.Cves } else { 'No CVE' })
                'CWE' = $(if (@($_.Cwes).Count) { & $join $_.Cwes } else { 'None listed' }); 'CWE Name' = $_.CweNames
                'Priority' = $_.Priority; 'Fix' = $_.Fix; 'Finding' = $_.Finding; 'Severity' = $_.Severity
                'CISA KEV' = $(if ($_.IsKev) { 'Yes' } else { 'No' })
                'Affected Hosts' = & $join $_.Hosts; 'Affected Users' = & $join $_.Users; 'Code Locations' = & $join $_.Locations
                'Owner' = $_.Owner; 'Status' = $_.Status
                'SLA Due Date' = & $fmtDate $_.DueDate; 'Days Remaining' = $(if ($_.IsOpen) { $_.DaysRemaining } else { '' }); 'SLA Status' = $_.SlaStatus
                'Target Date' = & $fmtDate $_.TargetDate
                'Issues' = & $join $_.Issues; 'Notes' = $_.Notes
            }
        } | Export-Csv -LiteralPath "$outBase.csv" -NoTypeInformation -Encoding UTF8

        $html = New-RemediationHtml -Cfg $Cfg -Items $items -SourceLabel "$leaf$sheetLabel" -LogoPath (Join-Path $ScriptRoot $Cfg.LogoFile) -AsOf $ReportDate
        $pub = Publish-Report $html $outBase
        $open = @($items | Where-Object { $_.IsOpen })
        $result = [pscustomobject]@{
            File = $leaf; Items = $items.Count; Open = $open.Count
            Completed = @($items | Where-Object { $_.Status -eq 'Completed' }).Count
            Overdue = @($open | Where-Object { $_.SlaStatus -eq 'Overdue' }).Count
            NoOwner = @($open | Where-Object { -not $_.Owner }).Count
            Attention = @($open | Where-Object { $_.Issues.Count }).Count
            Pdf = $pub.Pdf; Html = $pub.Html; Csv = "$outBase.csv"
        }
        Write-Log 'INFO' ("Remediation report for {0}: items {1} | open {2} | completed {3} | overdue {4} | no owner {5}" -f $leaf, $result.Items, $result.Open, $result.Completed, $result.Overdue, $result.NoOwner)
        return $result
    }
}

process {
    foreach ($p in @($Path)) { if ($p) { $CollectedPaths.Add($p) } }
}

end {
    $started = Get-Date
    $cfg = Import-TmsSettings $SettingsPath

    if (-not (Test-Path -LiteralPath $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null }
    $OutputFolder = (Resolve-Path -LiteralPath $OutputFolder).ProviderPath     # .NET file APIs need a full path
    $cacheDir = Join-Path $ScriptRoot 'cache'
    if (-not (Test-Path -LiteralPath $cacheDir)) { New-Item -ItemType Directory -Path $cacheDir -Force | Out-Null }
    $script:LogFile = Join-Path $OutputFolder 'operator.log'

    Show-Banner $cfg
    Write-Log 'INFO' "Run started by $env:USERNAME on $env:COMPUTERNAME (v$ScriptVersion)."

    # ---- 1. Input files ------------------------------------------------------
    $inputs = @($CollectedPaths)
    if (-not $inputs.Count) { $inputs = @(Select-CsvInteractively) }
    $files = @(Resolve-InputCsv -Paths $inputs -Recurse:$Recurse)
    if (-not $files.Count) { Write-Bad 'No files to process. Pass CSV exports or Action Plan workbooks with -Path.'; return }

    # ---- 1b. Split by file name: Action Plan workbooks go to the remediation report ----
    $remFiles = New-Object System.Collections.Generic.List[string]
    $scanFiles = New-Object System.Collections.Generic.List[string]
    foreach ($f in $files) {
        $leaf = Split-Path $f -Leaf
        $ext = [IO.Path]::GetExtension($f).ToLowerInvariant()
        if (Test-IsReportOutput $f) { Write-Info "$leaf - output from an earlier run, skipped (reading it back would double-count)."; continue }
        if (Test-RemediationFileName $f $cfg) {
            if ($ext -eq '.csv') {
                $apRows = @()
                try { $apRows = @(Import-Csv -LiteralPath $f) } catch { }
                if (Test-ActionPlanHasEntries $apRows) { $remFiles.Add($f) }
                else { Write-Info "$leaf - Action Plan with no Owner, Status, Target Date or Notes filled in yet, skipped." }
            } else { $remFiles.Add($f) }
            continue
        }
        if ($ext -in '.xlsx', '.xlsm') {
            Write-Bad "$leaf - Excel files are read only as Action Plan workbooks (the name must contain 'ActionPlan'; see RemediationFilePatterns in settings.psd1). Skipped."
            continue
        }
        $scanFiles.Add($f)
    }
    Write-Good ("{0} scanner export(s) and {1} Action Plan workbook(s) queued." -f $scanFiles.Count, $remFiles.Count)

    # ---- 1c. Remediation-only reports (no scanner parsing, no NVD/CIRCL/CWE calls) ----
    $remResults = New-Object System.Collections.Generic.List[object]
    $kev = $null
    if ($remFiles.Count) {
        $kev = Get-KevCatalog -Cfg $cfg -CacheDir $cacheDir -Offline:$Offline
        $idx = 0
        foreach ($rf in $remFiles) {
            $idx++
            try {
                $res = Invoke-RemediationReport -File $rf -Cfg $cfg -Kev $kev -OutputFolder $OutputFolder -ReportDate $ReportDate -Index $idx -Total $remFiles.Count
                if ($res) { $remResults.Add($res) }
            } catch { Write-Bad "$(Split-Path $rf -Leaf) - failed to read: $($_.Exception.Message)" }
        }
    }
    $showRemediation = {
        foreach ($rr in $remResults) {
            Write-Host ''
            Write-Host (' Remediation status: {0}' -f $rr.File) -ForegroundColor White
            Write-Host (' {0,-26}{1} open / {2} completed / {3} total' -f 'Items:', $rr.Open, $rr.Completed, $rr.Items)
            Write-Host (' {0,-26}' -f 'Past SLA due date:') -NoNewline; Write-Host $rr.Overdue -ForegroundColor $(if ($rr.Overdue) { 'Red' } else { 'Green' })
            Write-Host (' {0,-26}' -f 'No owner:') -NoNewline; Write-Host $rr.NoOwner -ForegroundColor $(if ($rr.NoOwner) { 'Yellow' } else { 'Green' })
            Write-Host (' {0,-26}{1}' -f 'Needs attention:', $rr.Attention)
            if ($rr.Pdf) { Write-Host (' {0,-26}' -f 'PDF report:') -NoNewline; Write-Host $rr.Pdf -ForegroundColor Cyan }
            if ($rr.Html) { Write-Host (' {0,-26}' -f 'HTML report:') -NoNewline; Write-Host $rr.Html -ForegroundColor $(if ($rr.Pdf) { 'Gray' } else { 'Yellow' }) }
            Write-Host (' {0,-26}' -f 'Status CSV:') -NoNewline; Write-Host $rr.Csv -ForegroundColor Gray
        }
    }
    $isInteractiveWindows = (($PSVersionTable.PSEdition -eq 'Desktop') -or ($IsWindows -eq $true)) -and [Environment]::UserInteractive
    if (-not $scanFiles.Count) {
        if (-not $remResults.Count) { Write-Bad 'Nothing was processed.'; return }
        Write-Host ''
        Write-Host ('=' * 64) -ForegroundColor Cyan
        Write-Host '                 REMEDIATION STATUS COMPLETE' -ForegroundColor White
        Write-Host ('=' * 64) -ForegroundColor Cyan
        & $showRemediation
        Write-Host ''
        Write-Log 'INFO' "Run complete: $($remResults.Count) remediation report(s), no scanner exports."
        foreach ($rr in $remResults) {
            $toOpen = if ($rr.Pdf) { $rr.Pdf } else { $rr.Html }
            if (-not $NoOpen -and $isInteractiveWindows -and $toOpen) { try { Invoke-Item -LiteralPath $toOpen } catch { } }
        }
        return
    }
    $files = $scanFiles.ToArray()

    # ---- 2. Detect + parse -----------------------------------------------------
    $all = New-Object System.Collections.Generic.List[object]
    $sourceStats = New-Object System.Collections.Generic.List[object]
    foreach ($f in $files) {
        $leaf = Split-Path $f -Leaf
        try {
            $type = Get-CsvSourceType $f
            $parsed = switch ($type) {
                'Nessus' { Read-NessusCsv $f }
                'CrowdStrike' { Read-CrowdStrikeCsv $f }
                'Blumira' { Read-BlumiraCsv $f }
                'CodeQL' { Read-CodeQLCsv $f $cfg.CodeQLRepositoryName }
                'GitHub' { Read-GitHubOverviewCsv $f }
                'Generic' { Read-GenericCsv $f }
                default { @() }
            }
            $parsed = @($parsed)
            $rowCount = @(Get-Content -LiteralPath $f).Count
            if ($type -ne 'CodeQL' -and $rowCount -gt 0) { $rowCount-- }
            $typeLabel = if ($type -eq 'GitHub') { 'GitHub Security overview (CodeQL / Dependabot / secret scanning)' } else { $type }
            if ($type -in 'Unknown', 'Empty') {
                Write-Bad "$leaf - could not identify the source (not Nessus, CrowdStrike, Blumira, CodeQL or GitHub Security overview). Skipped."
                $hdr = Get-Content -LiteralPath $f -TotalCount 1
                if ($hdr) { Write-Bad "    Its header row is: $($hdr.Substring(0, [Math]::Min(300, $hdr.Length)))" }
            }
            else {
                Write-Good ("{0} - detected as {1}, {2} finding(s)." -f $leaf, $typeLabel, $parsed.Count)
                if ($type -eq 'GitHub') {
                    $mix = $parsed | Group-Object Source | ForEach-Object { "$($_.Count) $($_.Name)" }
                    if ($mix) { Write-Info ("    " + ($mix -join ', ')) }
                }
            }
            foreach ($x in $parsed) { $all.Add($x) }
            $sourceStats.Add([pscustomobject]@{ File = $leaf; Path = $f; Type = $typeLabel; Rows = $rowCount; Findings = $parsed.Count; Affecting = 0 })
        } catch {
            Write-Bad "$leaf - failed to read: $($_.Exception.Message)"
            $sourceStats.Add([pscustomobject]@{ File = $leaf; Path = $f; Type = 'Error'; Rows = 0; Findings = 0; Affecting = 0 })
        }
    }
    if (-not $all.Count) { Write-Bad 'No findings were parsed from the input files.'; return }

    # ---- 3. Enrichment ---------------------------------------------------------
    $apiKey = if ($env:TMS_NVD_API_KEY) { $env:TMS_NVD_API_KEY } else { "$($cfg.Api.NvdApiKey)" }
    $cves = @($all | Where-Object { $_.Cve } | ForEach-Object { $_.Cve } | Sort-Object -Unique)
    Write-Info "$($cves.Count) unique CVE(s) to enrich."

    if ($null -eq $kev) { $kev = Get-KevCatalog -Cfg $cfg -CacheDir $cacheDir -Offline:$Offline }

    $nvdFile = Join-Path $cacheDir 'nvd_cache.json';     $nvdCache = Read-JsonCache $nvdFile
    $circlFile = Join-Path $cacheDir 'circl_cache.json'; $circlCache = Read-JsonCache $circlFile
    $cweFile = Join-Path $cacheDir 'cwe_cache.json';     $cweCache = Read-JsonCache $cweFile

    if (-not $Offline -and -not $SkipNvd -and $cves.Count) {
        $todo = @($cves | Where-Object { -not (Test-CacheFresh $nvdCache[$_] $cfg.CacheHours.Nvd) })
        $delay = if ($apiKey) { [double]$cfg.NvdDelaySeconds.WithKey } else { [double]$cfg.NvdDelaySeconds.WithoutKey }
        if ($todo.Count) {
            Write-Info ("Querying NIST NVD for {0} CVE(s) ({1}; about {2:N0} s)." -f $todo.Count, $(if ($apiKey) { 'API key in use' } else { 'no API key - set TMS_NVD_API_KEY to go faster' }), ($todo.Count * $delay))
        }
        $i = 0; $fail = 0
        foreach ($c in $todo) {
            $i++
            Write-Progress -Activity 'NIST NVD' -Status $c -PercentComplete ($i * 100 / $todo.Count)
            try { $nvdCache[$c] = Get-NvdRecord $c $cfg $apiKey; $fail = 0 }
            catch { $fail++; Write-Log 'WARN' "NVD lookup failed for $c : $($_.Exception.Message)"; if ($fail -ge 2) { Write-Bad "NVD is not responding ($($_.Exception.Message)) - using scanner scores for the rest."; break } }
            Start-Sleep -Milliseconds ([int]($delay * 1000))
        }
        Write-Progress -Activity 'NIST NVD' -Completed
        Save-JsonCache $nvdCache $nvdFile
    }

    if (-not $Offline -and -not $SkipCircl -and $cves.Count) {
        $todo = @($cves | Where-Object { -not (Test-CacheFresh $circlCache[$_] $cfg.CacheHours.Circl) })
        if ($todo.Count) { Write-Info "Querying CIRCL for $($todo.Count) CVE(s) (vendor fixes and CISA SSVC data)." }
        $i = 0; $fail = 0
        foreach ($c in $todo) {
            $i++
            Write-Progress -Activity 'CIRCL CVE' -Status $c -PercentComplete ($i * 100 / $todo.Count)
            try { $circlCache[$c] = Get-CirclRecord $c $cfg; $fail = 0 }
            catch { $fail++; Write-Log 'WARN' "CIRCL lookup failed for $c : $($_.Exception.Message)"; if ($fail -ge 2) { Write-Bad "CIRCL is not responding ($($_.Exception.Message)) - skipping the remaining CIRCL lookups."; break } }
            Start-Sleep -Milliseconds 250
        }
        Write-Progress -Activity 'CIRCL CVE' -Completed
        Save-JsonCache $circlCache $circlFile
    }

    # CWE IDs come from the scanners, NVD, and CIRCL
    foreach ($x in $all) {
        if ($x.Cve) {
            $extra = @()
            if ($nvdCache[$x.Cve]) { $extra += @($nvdCache[$x.Cve].Cwes) }
            if ($circlCache[$x.Cve]) { $extra += @($circlCache[$x.Cve].Cwes) }
            if ($kev[$x.Cve] -and $kev[$x.Cve].cwes) { $extra += @($kev[$x.Cve].cwes) }
            $x.Cwes = @(Join-Unique (@($x.Cwes) + $extra | Where-Object { $_ -match '^CWE-\d+$' }))
        }
    }
    $cweIds = @($all | ForEach-Object { $_.Cwes } | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $Offline -and -not $SkipCwe -and $cweIds.Count) {
        $todo = @($cweIds | Where-Object { -not (Test-CacheFresh $cweCache[$_] $cfg.CacheHours.Cwe) })
        if ($todo.Count) {
            Write-Info "Querying MITRE CWE API for $($todo.Count) weakness(es)."
            Get-CweRecords -Ids $todo -Cfg $cfg -Cache $cweCache
            Save-JsonCache $cweCache $cweFile
        }
    }

    # ---- 3b. nslookup: IP -> host name on the domain controllers -------------------
    $dnsNames = @{}
    if ($cfg.ResolveIpsWithDns -and -not $SkipDns) {
        $toResolve = @($all | Where-Object { $_.IP -and -not $_.Host -and (Test-InternalIp $_.IP $cfg) } |
                       ForEach-Object { $_.IP } | Sort-Object -Unique)
        if ($toResolve.Count) {
            # "DC01,DC02" arrives as one string from cmd.exe / Task Scheduler - split it
            $split = { param($v) @(@($v) -split '[,;\s]+' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
            $servers = if ($DnsServer) { & $split $DnsServer }
                       elseif (@(& $split $cfg.DnsServers).Count) { & $split $cfg.DnsServers }
                       else { @(Get-TmsDomainControllers) }
            $via = if (@($servers).Count) { $servers -join ', ' } else { "this computer's DNS servers" }
            Write-Info "nslookup: $($toResolve.Count) IP address(es) with no host name, asking $via..."
            $dnsNames = Resolve-IpNamesOnDcs $toResolve $servers
            Write-Good "nslookup: found host names for $($dnsNames.Count) of $($toResolve.Count)."
            $missing = @($toResolve | Where-Object { -not $dnsNames.ContainsKey($_) })
            if ($missing.Count) {
                Write-Info "    No PTR record for $($missing.Count) IP(s); they will show as the IP. List is in operator.log."
                Write-Log 'INFO' ("No PTR record on the DCs for: " + ($missing -join ', '))
            }
        }
    }

    # ---- 4. Score, scope, SLA, remediation per finding -----------------------------
    $ledgerFile = Join-Path $cacheDir 'first_seen_ledger.json'
    $ledger = Read-JsonCache $ledgerFile
    $ledgerHadData = $ledger.Count -gt 0
    $scopeOn = (@($cfg.InScopeNetworks | Where-Object { $_ }).Count + @($cfg.InScopeHostPatterns | Where-Object { $_ }).Count) -gt 0
    $closedPattern = '(?i)^\s*(closed|fixed|resolved|remediated|mitigated|dismissed|auto.?dismissed|false.?positive|not.?affected|patched|inactive|suppressed|expired|revoked|used.?in.?tests|wont.?fix)'
    $today = $ReportDate.Date

    foreach ($x in $all) {
        $nvd = if ($x.Cve) { $nvdCache[$x.Cve] } else { $null }
        $circl = if ($x.Cve) { $circlCache[$x.Cve] } else { $null }
        $k = if ($x.Cve) { $kev[$x.Cve] } else { $null }

        # CVSS: NVD is authoritative; fall back to the scanner's own score
        if ($nvd -and $null -ne $nvd.Score) { $x.Cvss = [double]$nvd.Score; $x.CvssVersion = "$($nvd.Version)"; $x.CvssVector = "$($nvd.Vector)" }
        elseif ($null -ne $x.SourceScore) { $x.Cvss = [double]$x.SourceScore }
        if (-not $x.Description) { if ($nvd -and $nvd.Description) { $x.Description = $nvd.Description } elseif ($circl -and $circl.Description) { $x.Description = $circl.Description } }
        if (-not $x.Title -and $k) { $x.Title = $k.vulnerabilityName }

        $x.Severity = Get-SeverityFromScore $x.Cvss $cfg.Thresholds
        if (-not $x.Severity -or ($x.Severity -eq 'Info' -and $x.SourceSeverity -ne 'Info')) { $x.Severity = if ($x.SourceSeverity) { $x.SourceSeverity } else { 'Info' } }
        $x.SeverityRank = Get-SeverityRank $x.Severity

        $x.CweNames = (@($x.Cwes) | ForEach-Object { if ($cweCache[$_] -and $cweCache[$_].Name) { $cweCache[$_].Name } }) -join '; '

        if ($k) {
            $x.IsKev = $true; $x.KevDueDate = "$($k.dueDate)"; $x.KevAction = "$($k.requiredAction)"; $x.KevRansomware = "$($k.knownRansomwareCampaignUse)"
        }
        if ($circl) { $x.SsvcExploitation = "$($circl.Exploitation)"; $x.SsvcAutomatable = "$($circl.Automatable)"; $x.SsvcTechnicalImpact = "$($circl.TechnicalImpact)" }
        $x.InternetFacing = Test-AssetMatch $x $cfg.InternetFacingNetworks $cfg.InternetFacingHostPatterns

        $inScope = (-not $scopeOn) -or (Test-AssetMatch $x $cfg.InScopeNetworks $cfg.InScopeHostPatterns)
        # Blumira's source IP is often the outside attacker, not a TMS asset - keep only the user
        if ($x.Source -eq 'Blumira' -and -not $x.Host -and $x.IP -and $scopeOn -and -not $inScope -and $x.User) { $x.IP = ''; $inScope = $true }
        if ($x.Source -match '^(CodeQL|GitHub)') { $inScope = $true }   # code repositories are not network assets
        $fromDns = $false
        if (-not $x.Host -and $x.IP -and $dnsNames.ContainsKey($x.IP)) { $x.Host = $dnsNames[$x.IP]; $fromDns = $true }
        $short = if ($x.Host) { $x.Host.Split('.')[0] } else { '' }
        $x.DisplayName = if ($x.Host -and $x.Host -ne $x.IP) { if ($fromDns -and $cfg.DnsShortNames) { $short } else { $x.Host } } else { '' }
        if ($fromDns -and $scopeOn -and -not $inScope) { $inScope = Test-AssetMatch $x $cfg.InScopeNetworks $cfg.InScopeHostPatterns }
        $x.HostLabel = if ($x.DisplayName -and $x.IP) { "$($x.DisplayName) ($($x.IP))" } elseif ($x.DisplayName) { $x.DisplayName } elseif ($x.IP) { $x.IP } elseif ($x.User) { '' } else { '(unidentified asset)' }

        # Does it affect the current network?
        if ($x.Status -match $closedPattern) { $x.AffectsNetwork = $false; $x.AffectsReason = "Status in $($x.Source): $($x.Status)" }
        elseif (-not $inScope) { $x.AffectsNetwork = $false; $x.AffectsReason = 'Outside configured TMS networks' }
        elseif ($x.LastSeen -and ($today - $x.LastSeen.Date).TotalDays -gt $cfg.StaleAfterDays) { $x.AffectsNetwork = $false; $x.AffectsReason = "Last seen $($x.LastSeen.ToString('yyyy-MM-dd')) (over $($cfg.StaleAfterDays) days ago)" }
        else { $x.AffectsNetwork = $true; $x.AffectsReason = if ($scopeOn) { 'Open on an in-scope TMS asset' } else { 'Open on a scanned asset' } }

        # SLA tier
        if ($x.IsKev -and $x.InternetFacing -and $x.SsvcAutomatable -eq 'yes' -and $x.SsvcTechnicalImpact -eq 'total') {
            $x.SlaTier = 'CISA Immediate'; $x.SlaDays = [int]$cfg.CisaImmediateDays
        } elseif ($x.IsKev -and $cfg.KevEscalatesToCritical) {
            $x.SlaTier = 'Critical'; $x.SlaDays = [int]$cfg.RemediationSlaDays.Critical
        } elseif ($x.Severity -ne 'Info') {
            $x.SlaTier = $x.Severity; $x.SlaDays = [int]$cfg.RemediationSlaDays[$x.Severity]
        } else { $x.SlaTier = 'None' }

        # First-seen ledger keeps the SLA clock running between monthly reports
        $lk = '{0}|{1}|{2}|{3}' -f $x.VulnId, $x.HostLabel, $x.Location, $x.User
        $base = $today
        if ($x.FirstSeen -and $x.FirstSeen.Date -lt $base) { $base = $x.FirstSeen.Date }
        $prev = $ledger[$lk]
        if ($prev) { $pd = ConvertTo-DateOrNull "$($prev.FirstSeen)"; if ($pd -and $pd -lt $base) { $base = $pd } }
        elseif ($ledgerHadData -and -not $x.FirstSeen) { $x.IsNew = $true }
        if ($x.FirstSeen -and ($today - $x.FirstSeen.Date).TotalDays -le 31 -and -not $prev) { $x.IsNew = $true }
        if ($x.AffectsNetwork) { $ledger[$lk] = [pscustomobject]@{ FirstSeen = $base.ToString('yyyy-MM-dd'); LastReported = $today.ToString('yyyy-MM-dd') } }
        $x.BaseDate = $base

        if ($x.SlaDays) {
            $x.DueDate = $base.AddDays($x.SlaDays)
            $x.DaysRemaining = [int][Math]::Floor(($x.DueDate - $today).TotalDays)
            $x.SlaStatus = if ($x.DaysRemaining -lt 0) { 'Overdue' } elseif ($x.DaysRemaining -le 14) { 'Due soon' } else { 'On track' }
        } else { $x.SlaStatus = 'No SLA' }

        Set-Remediation $x $cfg $circl $cweCache
    }
    Save-JsonCache $ledger $ledgerFile

    if (-not $IncludeInformational) {
        $infoCount = @($all | Where-Object { $_.Severity -eq 'Info' }).Count
        if ($infoCount) { Write-Info "$infoCount informational finding(s) left out of the report (use -IncludeInformational to keep them)." }
    }
    $inReport = @($all | Where-Object { $IncludeInformational -or $_.Severity -ne 'Info' })
    $affecting = @($inReport | Where-Object { $_.AffectsNetwork })
    $excluded = @($inReport | Where-Object { -not $_.AffectsNetwork })
    foreach ($ss in $sourceStats) { $ss.Affecting = @($affecting | Where-Object { $_.SourceFile -eq $ss.Path }).Count }

    # ---- 5. Grouping --------------------------------------------------------------
    $prioritySort = @(
        @{ e = { [int]$_.IsKev }; Descending = $true },
        @{ e = { $_.SeverityRank }; Descending = $true },
        @{ e = { if ($_.DueDate) { $_.DueDate } else { [datetime]::MaxValue } }; Descending = $false },
        @{ e = { @($_.Hosts).Count }; Descending = $true })

    $groups = @($affecting | Group-Object { "$($_.VulnId)||$($_.RemediationKey)" } | ForEach-Object { New-GroupRow @($_.Group) 'Vulnerability' } | Sort-Object $prioritySort)
    $actionPlan = @($affecting | Group-Object { $_.RemediationKey } | ForEach-Object { New-GroupRow @($_.Group) 'Action' } | Sort-Object $prioritySort)
    $notAffecting = @($excluded | Group-Object { "$($_.VulnId)||$($_.AffectsReason)" } | ForEach-Object { New-GroupRow @($_.Group) 'Excluded' } | Sort-Object @{ e = { $_.SeverityRank }; Descending = $true })

    $bySev = @{}
    foreach ($sv in 'Critical', 'High', 'Medium', 'Low', 'Info') { $bySev[$sv] = @($groups | Where-Object { $_.Severity -eq $sv }).Count }
    $stats = [pscustomobject]@{
        OpenVulns = $groups.Count
        Actions = $actionPlan.Count
        Hosts = @(Join-Unique ($affecting | Where-Object { $_.Source -notmatch '^(CodeQL|GitHub)' } | ForEach-Object { $_.HostLabel })).Count
        Users = @(Join-Unique ($affecting | ForEach-Object { $_.User })).Count
        Kev = @(Join-Unique ($affecting | Where-Object { $_.IsKev } | ForEach-Object { $_.Cve })).Count
        Overdue = @($groups | Where-Object { $_.SlaStatus -eq 'Overdue' }).Count
        DueSoon = @($groups | Where-Object { $_.SlaStatus -eq 'Due soon' }).Count
        New = @($groups | Where-Object { $_.NewCount -gt 0 }).Count
        BySeverity = $bySev
    }

    # ---- 6. Output ---------------------------------------------------------------
    $stamp = $ReportDate.ToString('yyyy-MM') + '_' + (Get-Date -Format 'yyyyMMdd-HHmm')
    $outBase = Join-Path $OutputFolder "TMS_Vulnerability_Report_$stamp"
    $join = { param($v) (@($v) | Where-Object { $_ }) -join '; ' }
    $fmtDate = { param($d) if ($d) { ([datetime]$d).ToString('yyyy-MM-dd') } else { '' } }

    $n = 0
    $actionPlan | ForEach-Object {
        $n++
        [pscustomobject][ordered]@{
            'CVE ID' = $(if (@($_.Cves).Count) { & $join $_.Cves } else { 'No CVE' })
            'CWE' = $(if (@($_.Cwes).Count) { & $join $_.Cwes } else { 'None listed' }); 'CWE Name' = $_.CweNames
            'Priority' = $n; 'Fix' = $_.Remediation; 'Fix Source' = $_.RemediationSource
            'Severity' = $_.Severity; 'Max CVSS' = $_.Cvss; 'CISA KEV' = $(if ($_.IsKev) { 'Yes' } else { 'No' })
            'Finding' = & $join $_.Titles; 'Finding IDs' = & $join (@($_.VulnIds) | Where-Object { $_ -notmatch '^CVE-' })
            'Affected Hosts' = & $join $_.Hosts; 'Affected Users' = & $join $_.Users
            'Code Locations' = & $join $_.Locations; 'Host Count' = @($_.Hosts).Count; 'SLA Tier' = $_.SlaTier
            'Due Date' = & $fmtDate $_.DueDate; 'Days Remaining' = $_.DaysRemaining; 'SLA Status' = $_.SlaStatus
            'Found By' = $_.Sources; 'Owner' = ''; 'Status' = ''; 'Target Date' = ''; 'Notes' = ''
        }
    } | Export-Csv -LiteralPath "$outBase`_ActionPlan.csv" -NoTypeInformation -Encoding UTF8

    $groups | ForEach-Object {
        [pscustomobject][ordered]@{
            'CVE ID' = $(if (@($_.Cves).Count) { & $join $_.Cves } else { 'No CVE' })
            'CWE' = $(if (@($_.Cwes).Count) { & $join $_.Cwes } else { 'None listed' }); 'CWE Name' = $_.CweNames
            'Finding ID' = & $join $_.VulnIds; 'Title' = $_.Title; 'Severity' = $_.Severity; 'CVSS' = $_.Cvss; 'CVSS Vector' = $_.CvssVector
            'CISA KEV' = $(if ($_.IsKev) { 'Yes' } else { 'No' }); 'KEV Due Date' = $_.KevDueDate
            'CISA Required Action' = $_.KevAction; 'CISA SSVC' = $_.Ssvc
            'Affected Hosts' = & $join $_.Hosts; 'Affected Users' = & $join $_.Users; 'Code Locations' = & $join $_.Locations
            'Instances' = $_.Instances; 'Found By' = $_.Sources; 'SLA Tier' = $_.SlaTier; 'Due Date' = & $fmtDate $_.DueDate
            'Days Remaining' = $_.DaysRemaining; 'SLA Status' = $_.SlaStatus; 'Remediation' = $_.Remediation
            'Remediation Source' = $_.RemediationSource; 'Description' = $_.Description
        }
    } | Export-Csv -LiteralPath "$outBase`_Findings.csv" -NoTypeInformation -Encoding UTF8

    $all | ForEach-Object {
        [pscustomobject][ordered]@{
            'CVE ID' = $(if ($_.Cve) { $_.Cve } else { 'No CVE' })
            'CWE' = $(if (@($_.Cwes).Count) { & $join $_.Cwes } else { 'None listed' }); 'CWE Name' = $_.CweNames
            'Source' = $_.Source; 'Source File' = (Split-Path $_.SourceFile -Leaf); 'Finding ID' = $_.VulnId; 'Title' = $_.Title
            'Display Name' = $_.DisplayName; 'Host' = $_.Host; 'IP' = $_.IP; 'User' = $_.User; 'Port' = $_.Port; 'Location' = $_.Location; 'Product' = $_.Product
            'Severity' = $_.Severity; 'CVSS' = $_.Cvss; 'CISA KEV' = $(if ($_.IsKev) { 'Yes' } else { 'No' })
            'Status' = $_.Status; 'Affects Network' = $(if ($_.AffectsNetwork) { 'Yes' } else { 'No' }); 'Reason' = $_.AffectsReason
            'First Seen' = & $fmtDate $_.BaseDate; 'Due Date' = & $fmtDate $_.DueDate; 'SLA Status' = $_.SlaStatus
            'Remediation' = $_.Remediation; 'Remediation Source' = $_.RemediationSource
        }
    } | Export-Csv -LiteralPath "$outBase`_AllFindings.csv" -NoTypeInformation -Encoding UTF8

    $logo = Join-Path $ScriptRoot $cfg.LogoFile
    $html = New-HtmlReport -Cfg $cfg -Stats $stats -ActionPlan $actionPlan -Groups $groups -NotAffecting $notAffecting -SourceStats $sourceStats -LogoPath $logo -AsOf $ReportDate
    $pub = Publish-Report $html $outBase
    $pdfPath = $pub.Pdf; $htmlPath = $pub.Html

    # ---- 7. Terminal dashboard ------------------------------------------------------
    $runtime = [Math]::Round(((Get-Date) - $started).TotalSeconds, 1)
    Write-Host ''
    Write-Host ('=' * 64) -ForegroundColor Cyan
    Write-Host '                       REPORT COMPLETE' -ForegroundColor White
    Write-Host ('=' * 64) -ForegroundColor Cyan
    $line = { param($label, $value, $color = 'White') Write-Host (' {0,-26}' -f $label) -NoNewline; Write-Host $value -ForegroundColor $color }
    & $line 'Files processed:' $files.Count
    & $line 'Findings parsed:' $all.Count
    & $line 'Affecting the network:' $affecting.Count
    & $line 'Open vulnerabilities:' $stats.OpenVulns
    & $line '  Critical / High:' ("{0} / {1}" -f $bySev.Critical, $bySev.High) $(if ($bySev.Critical) { 'Red' } else { 'White' })
    & $line '  Medium / Low:' ("{0} / {1}" -f $bySev.Medium, $bySev.Low)
    & $line 'Remediation actions:' $stats.Actions
    & $line 'Hosts / users affected:' ("{0} / {1}" -f $stats.Hosts, $stats.Users)
    & $line 'CISA KEV matches:' $stats.Kev $(if ($stats.Kev) { 'Red' } else { 'Green' })
    & $line 'Past due:' $stats.Overdue $(if ($stats.Overdue) { 'Red' } else { 'Green' })
    & $line 'Runtime:' "$runtime s"
    Write-Host ('=' * 64) -ForegroundColor Cyan
    if ($pdfPath) { & $line 'PDF report:' $pdfPath 'Cyan' }
    if ($htmlPath) { & $line 'HTML report:' $htmlPath $(if ($pdfPath) { 'Gray' } else { 'Yellow' }) }
    & $line 'Action plan CSV:' "$outBase`_ActionPlan.csv" 'Gray'
    & $line 'Findings CSV:' "$outBase`_Findings.csv" 'Gray'
    & $line 'All findings CSV:' "$outBase`_AllFindings.csv" 'Gray'
    & $showRemediation
    Write-Host ''
    Write-Log 'INFO' ("Run complete in {0}s | files {1} | findings {2} | affecting {3} | vulns {4} | actions {5} | KEV {6} | overdue {7}" -f $runtime, $files.Count, $all.Count, $affecting.Count, $stats.OpenVulns, $stats.Actions, $stats.Kev, $stats.Overdue)

    $toOpen = if ($pdfPath) { $pdfPath } else { $htmlPath }
    if (-not $NoOpen -and $isInteractiveWindows -and $toOpen) { try { Invoke-Item -LiteralPath $toOpen } catch { } }
}
