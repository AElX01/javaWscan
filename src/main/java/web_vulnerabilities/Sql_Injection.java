package web_vulnerabilities;

import RequestsResponsesHandlers.CheckRequestType;
import burp.api.montoya.proxy.http.InterceptedRequest;

import java.util.regex.*;


public abstract class Sql_Injection extends CheckRequestType
{
    private static final String QUERY_PARAM_PATTERN = "\\?(\\w+)=([^&]+)"; // EXTRACTS INPUT VALUES IN URL
    private static final String SQL_PARAM_PATTERN = "(?i)(id|user|product|item|page|cat|type)"; // FINDS SPECIFIC SQL QUERY PATTERNS

    public static InterceptedRequest SubertAppLogic(InterceptedRequest interceptedRequest) {
        return null;
    }

    public static boolean isVulnerable(InterceptedRequest interceptedRequest) {
        final Pattern urlQueryPattern = Pattern.compile(QUERY_PARAM_PATTERN);
        final Pattern urlSqlQueryPattern = Pattern.compile(SQL_PARAM_PATTERN);
        Matcher urlParamMatcher = urlQueryPattern.matcher(interceptedRequest.url());

        while (urlParamMatcher.find()) {
            String parameter = urlParamMatcher.group(1);
            Matcher urlSqlParamMatcher = urlSqlQueryPattern.matcher(parameter);
            if (urlSqlParamMatcher.find()) return true;
        }
//
        return false;
    }
}
