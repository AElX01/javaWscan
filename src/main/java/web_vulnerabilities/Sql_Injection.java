package web_vulnerabilities;

import burp.api.montoya.proxy.http.InterceptedRequest;

import web_vulnerabilities_constants.AvailableVulnerabilities;
import web_vulnerabilities_constants.IsVulnerableCodes;
import web_vulnerabilities_constants.Patterns;

import static web_vulnerabilities.IsVulnerable.isVulnerable;
import static web_vulnerabilities.MightBeVulnerable.mightBeVulnerable;


public interface Sql_Injection
{
    // CHECK mightBeVulnerable() METHOD
    static boolean testSql(InterceptedRequest interceptedRequest) {
        return mightBeVulnerable(interceptedRequest, Patterns.QUERY_PARAM_PATTERN.getREGEX(), Patterns.SQL_QUERY_PARAM_PATTERN.getREGEX());
    }

    // CHECK isVulnerable() METHOD
    static IsVulnerableCodes isVulnerableToSQLi(InterceptedRequest interceptedRequest) {
        return isVulnerable(interceptedRequest, Patterns.SQL_PAYLOAD.getREGEX(), AvailableVulnerabilities.SQLi);
    }
}
