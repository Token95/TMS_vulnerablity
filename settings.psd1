@{
    # ------------------------------------------------------------------
    #  TMS (Times Microwave Systems) Internal - Vulnerability Report
    #  Settings for TMS-VulnReport.ps1
    # ------------------------------------------------------------------

    Organization    = 'TMS (Times Microwave Systems) Internal'
    ReportTitle     = 'Monthly Vulnerability Remediation Report'
    PreparedBy      = 'Devon Brown'
    PreparedByTitle = 'Network Security Engineer'
    LogoFile        = 'TMS_Logo.png'      # relative to the script folder

    Api = @{
        # NIST NVD 2.0 - CVSS score/vector and CVE -> CWE mapping
        NvdUrl    = 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId='
        # Leave blank and set the environment variable TMS_NVD_API_KEY instead,
        # so the key never lands in source control.
        NvdApiKey = ''

        # CIRCL Vulnerability-Lookup - description, vendor solution text,
        # and CISA "Vulnrichment" SSVC data (Exploitation/Automatable/Impact)
        CirclUrl  = 'https://cve.circl.lu/api/cve/'

        # CISA Known Exploited Vulnerabilities catalog (one download per run)
        KevUrl    = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

        # MITRE CWE REST API - weakness name, description, potential mitigations
        CweUrl    = 'https://cwe-api.mitre.org/api/v1/cwe/weakness/'
    }

    # TMS remediation SLA for servers (calendar days from first detection)
    RemediationSlaDays = @{
        Critical = 30     # CVSS 9.0 - 10.0
        High     = 60     # CVSS 7.0 - 8.9
        Medium   = 90     # CVSS 4.0 - 6.9
        Low      = 180    # CVSS 0.1 - 3.9
    }

    # CISA KEV entries are known to be exploited in the wild.
    # When $true they are held to the Critical window regardless of CVSS.
    KevEscalatesToCritical = $true

    # CISA BOD 26-04 top tier: KEV + publicly exposed + automatable + total
    # technical impact. Only applies to hosts listed as internet-facing below.
    CisaImmediateDays = 3

    # CVSS base-score cut-offs (lowest score in each band)
    #   Critical 9.0 - 10.0 | High 7.0 - 8.9 | Medium 4.0 - 6.9 | Low 0.1 - 3.9
    #   A score of 0.0 is Informational and gets no SLA.
    Thresholds = @{
        Critical = 9.0
        High     = 7.0
        Medium   = 4.0
        Low      = 0.1    # Low runs from here up to 3.9 (just under Medium)
    }

    # ---- "Does it affect the current network?" -----------------------
    # Leave both empty to treat every host in the exports as in scope.
    InScopeNetworks     = @()          # e.g. '10.0.0.0/8', '192.168.50.0/24'
    InScopeHostPatterns = @()          # e.g. '*.tms.local', 'TMS-*'

    # Internet-facing assets (used for the CISA BOD 26-04 exposure check)
    InternetFacingNetworks     = @()   # e.g. '203.0.113.0/28'
    InternetFacingHostPatterns = @()   # e.g. 'vpn*', 'www*'

    # ---- Remediation workbooks ------------------------------------------
    # Every Excel file (.xlsx/.xlsm) passed in is read as a remediation tracker
    # and gets its own Remediation Status report (PDF + CSV). The sheet is
    # picked automatically: one named like "Tracker" or "Action Plan" that has
    # CVE IDs, otherwise the sheet with the most CVE IDs. A sheet named
    # "...Completed" is used to mark items done when there is no Status column.
    # Set RemediationSheetName to force a sheet, e.g. 'Vulnerability Tracker'.
    RemediationSheetName = ''
    # A .csv whose name matches one of these is also read as a tracker (once
    # Owner/Status/Target Date/Notes is filled in).
    RemediationFilePatterns = @('*ActionPlan*', '*Action_Plan*', '*Action Plan*', '*Action-Plan*', '*Tracker*')

    # ---- IP address -> host name (nslookup on the domain controllers) ----
    # IPs that arrive without a host name (Nessus, Blumira) are looked up as
    # PTR records. List your DCs here, or leave empty to find them from AD
    # automatically (the _ldap._tcp.dc._msdcs.<domain> SRV record).
    ResolveIpsWithDns = $true
    DnsServers        = @()       # e.g. 'TMS-DC01', 'TMS-DC02'  or  '10.20.0.10', '10.20.0.11'
    DnsShortNames     = $true     # show "tms-web01" instead of "tms-web01.tms.local"

    # A finding whose "last seen" is older than this is treated as stale.
    StaleAfterDays = 30

    # Name to use for the asset column on CodeQL rows (blank = CSV file name)
    CodeQLRepositoryName = ''

    # ---- API caching / pacing -----------------------------------------
    CacheHours = @{
        Kev   = 24
        Nvd   = 168
        Circl = 168
        Cwe   = 720
    }
    NvdDelaySeconds = @{
        WithKey    = 0.7
        WithoutKey = 6.5
    }

    # Throttling for CIRCL and MITRE CWE (and the retry rules for all APIs).
    # On HTTP 429/503 the script waits (Retry-After if sent, else 10, 20, 40,
    # 80, 120 s), doubles the gap for that site for the rest of the run, and
    # carries on. Finished lookups are saved every SaveCacheEvery requests, so
    # a run that is stopped picks up where it left off.
    ApiThrottle = @{
        CirclDelaySeconds = 1.0    # one CIRCL request per second (658 CVEs = about 11 min)
        CweDelaySeconds   = 0.5
        MaxRetries        = 6      # per request, on 429/503/5xx
        MaxBackoffSeconds = 120
        MaxDelaySeconds   = 10     # the gap never grows past this
        SaveCacheEvery    = 25
    }

    # Report layout
    MaxHostsShownPerRow = 40
}
