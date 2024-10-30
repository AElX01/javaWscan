package web_vulnerabilities;

import RequestsResponsesHandlers.CheckRequestType;
import burp.api.montoya.proxy.http.InterceptedRequest;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.regex.*;


public abstract class Sql_Injection extends CheckRequestType
{

    private static final String QUERY_PARAM_PATTERN = "\\?(\\w+)=([^&]+)"; // REGEX USAGE TO CHECK FOR SQL QUERY PATTERNS SYMBOLS (e.g. '?', '=')
    private static final String SQL_PARAM_PATTERN = "(?i)(id|user|product|item|page|cat|type)"; // FINDS SPECIFIC SQL QUERY PATTERNS
    private static final String PAYLOAD = "'"; // CHARACTER TO SCAPE SQL QUERY

    // COMPILE REGEX PATTERNS TO FURTHER MATCH THEM ON THE URL/PATH
    private static final Pattern urlQueryPattern = Pattern.compile(QUERY_PARAM_PATTERN);
    private static final Pattern urlSqlQueryPattern = Pattern.compile(SQL_PARAM_PATTERN);


    /*
    once a website is labeled as possibly vulnerable, isVulnerable() will replace whatever is on the query after the "=" symbol with the ' character
    to send a request and check for any internal server error status code indicating a very high possibility of the website being vulnerable to SQLi
     */
    public static IsVulnerableCodes isVulnerable(InterceptedRequest interceptedRequest) {
        String newUrl = interceptedRequest.url().replaceFirst("(=)[^&]*", "$1" + PAYLOAD); // REPLACE ORIGINAL QUERY (e.g. ?category=gift) WITH A ' TO SCAPE THE SQL QUERY
        HttpClient client = HttpClient.newHttpClient(); // CREATES AN HTTP CLIENT

        try { // HANDLES URL SYNTAX PROBLEMS
            HttpRequest request = HttpRequest.newBuilder().uri(new URI(newUrl)).GET().build(); // CRAFTS A GET REQUEST WITH THE SPECIFIED URL
            try { // HANDLES REQUEST CONNECTIVITY PROBLEMS
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString()); // SENDS A REQUEST AND RETRIEVE ITS RESPONSE
                return (response.statusCode() == 500) ? IsVulnerableCodes.VULNERABLE : IsVulnerableCodes.SAFE; // CHECKS IF HTTP REQUEST RESPONSE RETRIEVES AN INTERNAL SERVER ERROR INDICATING SQLi VULNERABILITY PRESENT ON WEBPAGE
            } catch(IOException | InterruptedException e) {
                return IsVulnerableCodes.REQUEST_PROBLEM;
            }
        } catch (URISyntaxException e) {
            return IsVulnerableCodes.URL_SYNTAX_ERROR;
        }

    }

    /*
    mightBeVulnerable() uses the compiled regular expressions to find query patterns such as '?' '=', if any of those are found
    the method will proceed to check what the request is querying, if any SQL query patterns are found, it will return "true",
    meaning that the target webpage might be vulnerable.
     */
    public static boolean mightBeVulnerable(InterceptedRequest interceptedRequest) {
        Matcher urlParamMatcher = urlQueryPattern.matcher(interceptedRequest.path()); // GENERATES A MATCHER OF THE COMPILED PATTERNS WITH THE ORIGINAL PATH OF THE INTERCEPTED REQUEST

        while (urlParamMatcher.find()) { // WHILE IT FINDS A MATCH...
            String parameter = urlParamMatcher.group(1); // SUBTRACTING FOUND MATCH
            Matcher urlSqlParamMatcher = urlSqlQueryPattern.matcher(parameter); // CREATES A MATCH OF SQL PATTERNS
            if (urlSqlParamMatcher.find()) return true;
        }

        return false;
    }

}
