package web_vulnerabilities_constants;

/*
    enum structure to define isVulnerable() method codes necessary to log the right messages to STDOUT or STDERR
 */

public enum IsVulnerableCodes {
    VULNERABLE,
    SAFE,
    URL_SYNTAX_ERROR,
    REQUEST_PROBLEM
}
