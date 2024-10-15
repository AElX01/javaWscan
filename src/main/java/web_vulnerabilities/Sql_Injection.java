package web_vulnerabilities;

import RequestsResponsesHandlers.CheckRequestType;
import burp.api.montoya.proxy.http.InterceptedRequest;

import java.util.regex.*;


public abstract class Sql_Injection extends CheckRequestType
{
    private static final String QUERY_PARAM_PATTERN = "\\?(\\w+)=([^&]+)"; // CHECKS IF THERE ARE ANY QUERIES ON URL
    private static final String SQL_PARAM_PATTERN = "(?i)(id|user|product|item|page|cat|type)"; // FINDS SPECIFIC SQL QUERY PATTERNS
    private static final String[] PAYLOADS = {"'", "+OR+1=1--"};
    private static final Pattern urlQueryPattern = Pattern.compile(QUERY_PARAM_PATTERN);
    private static final Pattern urlSqlQueryPattern = Pattern.compile(SQL_PARAM_PATTERN);

    public static InterceptedRequest SubvertQueryLogic(InterceptedRequest interceptedRequest) {
        String baseUrl = interceptedRequest.url().split("\\?")[0];

        for (String payload: PAYLOADS) {
            return null;
        }

        return null;
    }

    public static boolean isVulnerable(InterceptedRequest interceptedRequest) {
        Matcher urlParamMatcher = urlQueryPattern.matcher(interceptedRequest.url());

        while (urlParamMatcher.find()) {
            String parameter = urlParamMatcher.group(1);
            Matcher urlSqlParamMatcher = urlSqlQueryPattern.matcher(parameter);
            if (urlSqlParamMatcher.find()) return true;
        }

        return false;
    }

}
