package web_vulnerabilities_constants;

/*
    enum used to store all supported vulnerabilities by the extension,
    every new vulnerability MUST be added here.
 */

public enum AvailableVulnerabilities {
    SQLi("SQLi",
            StatusCodes.WARNING_LOG + "potentially vulnerable site to query logic subverting on URL, might contain SQL query patterns (e.g. 'id' in 'www.site.com/index.php?id=1')",
            StatusCodes.CRITICAL_LOG + "SQLi PRESENT ON SYSTEM DUE TO INTERNAL SERVER ERROR WHEN PARSING A ' CHARACTER TO QUERY"),

    XSS("XSS",
            StatusCodes.WARNING_LOG + "potentially vulnerable site to reflected XSS on URL, might contain XSS query patterns (e.g. 'search' in 'www.site.com/?search=omori')",
            StatusCodes.CRITICAL_LOG + "XSS PRESENT ON SYSTEM DUE TO alert(1) REFLECTED ON RESPONSE BODY"),

    LFI("LFI",
            StatusCodes.WARNING_LOG + "potentially vulnerable site to LFI on URL, might contain LFI query patterns (e.g. 'file' in 'www.site.com/?file=mewo.php')",
            StatusCodes.CRITICAL_LOG + "LFI PRESENT ON SYSTEM DUE TO /etc/passwd CONTENTS SUCCESSFULLY RETRIEVED");

    private final String VULNERABILITY;
    private final String MIGHT_BE_VULNERABLE_LOG;
    private final String IS_VULNERABLE_LOG;

    AvailableVulnerabilities(String VULNERABILITY, String MIGHT_BE_VULNERABLE_LOG, String IS_VULNERABLE_LOG) {
        this.VULNERABILITY = VULNERABILITY;
        this.MIGHT_BE_VULNERABLE_LOG = MIGHT_BE_VULNERABLE_LOG;
        this.IS_VULNERABLE_LOG = IS_VULNERABLE_LOG;
    }

    public String getVULNERABILITY() { return this.VULNERABILITY; }
    public String getMIGHT_BE_VULNERABLE_LOG() {return this.MIGHT_BE_VULNERABLE_LOG; }
    public String getIS_VULNERABLE_LOG() { return this.IS_VULNERABLE_LOG; }
}
