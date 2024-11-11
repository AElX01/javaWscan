package web_vulnerabilities;

import burp.api.montoya.proxy.http.InterceptedRequest;

import web_vulnerabilities_constants.AvailableVulnerabilities;
import web_vulnerabilities_constants.IsVulnerableCodes;
import web_vulnerabilities_constants.Patterns;

import static web_vulnerabilities.IsVulnerable.isVulnerable;
import static web_vulnerabilities.MightBeVulnerable.mightBeVulnerable;

public abstract class ReflectedXss {

    // CHECK mightBeVulnerable() METHOD
    public static boolean testXss(InterceptedRequest interceptedRequest) {
        return mightBeVulnerable(interceptedRequest, Patterns.QUERY_PARAM_PATTERN.getREGEX(), Patterns.XSS_QUERY_PARAM_PATTERN.getREGEX());
    }

    // CHECK isVulnerable() METHOD
    public static IsVulnerableCodes isVulnerableToXss(InterceptedRequest interceptedRequest) {
        return isVulnerable(interceptedRequest, Patterns.XSS_PAYLOAD.getREGEX(), AvailableVulnerabilities.XSS);
    }
}
