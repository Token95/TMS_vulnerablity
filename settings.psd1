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
    # An Excel file (.xlsx/.xlsm) whose name matches one of these patterns is
    # treated as a filled-in Action Plan and gets its own Remediation Status
    # report (PDF + CSV). The sheet with the CVE IDs is used. A .csv with a
    # matching name is used only once Owner/Status/Target Date/Notes is filled in.
    RemediationFilePatterns = @('*ActionPlan*', '*Action_Plan*', '*Action Plan*', '*Action-Plan*')

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

    # Report layout
    MaxHostsShownPerRow = 40
}
