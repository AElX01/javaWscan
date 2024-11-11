package web_vulnerabilities_constants;

/*
    enum that contains vulnerabilities' payloads and necessary REGEX to check for specific patterns
 */

public enum Patterns {
    QUERY_PARAM_PATTERN("\\?(\\w+)=([^&]+)"), // REGEX USAGE TO CHECK FOR QUERY PATTERNS SYMBOLS (e.g. '?', '=')

    SQL_QUERY_PARAM_PATTERN("(?i)(id|user|product|item|page|cat|type)"), // FINDS SPECIFIC SQL QUERY PATTERNS
    SQL_PAYLOAD("'"), // SQL ESCAPE SEQUENCE CHARACTER

    XSS_QUERY_PARAM_PATTERN("(?i)(search|message|query|comment|name|email|id|user)"), // FINDS SPECIFIC XSS QUERY PATTERNS
    XSS_PAYLOAD("<script>alert(1)</script>"), // XSS POC PAYLOAD

    LFI_QUERY_PARAM_PATTERN("(?i)(file|path|page|template|include|dir|doc|language)"), // FIND SPECIFIC FILE INCLUSION PATTERNS
    LFI_PAYLOAD("../../../../../../../../../etc/passwd"); // LFI PAYLOAD TO RETRIEVE THE CONTENTS OF /etc/passwd FILE


    private final String REGEX;

    Patterns(String REGEX) { this.REGEX = REGEX; }
    public String getREGEX() { return this.REGEX; }
}
