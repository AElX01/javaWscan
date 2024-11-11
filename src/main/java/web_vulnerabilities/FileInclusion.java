package web_vulnerabilities;

import burp.api.montoya.proxy.http.InterceptedRequest;
import web_vulnerabilities_constants.AvailableVulnerabilities;
import web_vulnerabilities_constants.IsVulnerableCodes;
import web_vulnerabilities_constants.Patterns;

import static web_vulnerabilities.IsVulnerable.isVulnerable;
import static web_vulnerabilities.MightBeVulnerable.mightBeVulnerable;

public class FileInclusion {

    // CHECK mightBeVulnerable() METHOD
    public static boolean testLFI(InterceptedRequest interceptedRequest) {
        return mightBeVulnerable(interceptedRequest, Patterns.QUERY_PARAM_PATTERN.getREGEX(), Patterns.LFI_QUERY_PARAM_PATTERN.getREGEX());
    }

    // CHECK isVulnerable() METHOD
    public static IsVulnerableCodes isVulnerableToLFI(InterceptedRequest interceptedRequest) {
        return isVulnerable(interceptedRequest, Patterns.LFI_PAYLOAD.getREGEX(), AvailableVulnerabilities.LFI);
    }
}
