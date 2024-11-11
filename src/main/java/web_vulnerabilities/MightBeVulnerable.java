package web_vulnerabilities;

import burp.api.montoya.proxy.http.InterceptedRequest;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
    mightBeVulnerable() uses the compiled regular expressions to find query patterns such as '?' '=', if any of those are found
    the method will proceed to check what the request is querying, if any patterns are found, it will return "true",
    meaning that the target webpage might be vulnerable to a certain vulnerability.
*/

abstract class MightBeVulnerable {
    public static boolean mightBeVulnerable(InterceptedRequest interceptedRequest, String URL_PARAM_PATTERN, String VULN_PARAM_PATTERN) {

        // COMPILE REGEX PATTERNS TO FURTHER MATCH THEM ON THE URL/PATH
        Pattern urlPattern = Pattern.compile(URL_PARAM_PATTERN);
        Pattern urlVulnPattern = Pattern.compile(VULN_PARAM_PATTERN);

        Matcher urlParamMatcher = urlPattern.matcher(interceptedRequest.path()); // GENERATES A MATCHER OF THE COMPILED PATTERNS WITH THE ORIGINAL PATH OF THE INTERCEPTED REQUEST

        while (urlParamMatcher.find()) { // WHILE A MATCH HAS BEEN FOUND...
            String parameter = urlParamMatcher.group(1); // SUBTRACTING FOUND MATCH
            Matcher urlVulnParamMatcher = urlVulnPattern.matcher(parameter); // CREATES A MATCH OF PATTERNS
            if (urlVulnParamMatcher.find()) return true; // IF ANY PATTERN FOUND, RETURN TRUE
        }

        return false;
    }
}
