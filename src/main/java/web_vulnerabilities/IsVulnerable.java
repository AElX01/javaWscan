package web_vulnerabilities;

import burp.api.montoya.proxy.http.InterceptedRequest;
import web_vulnerabilities_constants.AvailableVulnerabilities;
import web_vulnerabilities_constants.IsVulnerableCodes;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

/*
    isVulnerable() will replace the actual URL query contents with a payload that corresponds to the desired
    vulnerability to scan, it will then create an HTTP client to send and HTTP request with the modified url,
    after sending a request, it will intercept its response, based on the response content, a value will be returned,
    the value will correspond to the "IN-DANGER" status of the website.
 */

abstract class IsVulnerable {
    public static IsVulnerableCodes isVulnerable(InterceptedRequest interceptedRequest, String PAYLOAD, AvailableVulnerabilities VULNTOSCAN) {
        PAYLOAD = URLEncoder.encode(PAYLOAD, StandardCharsets.UTF_8); // CREATES A SAFE ENCODED PAYLOAD TO AVOID ANY URL SYNTAX ERRORS
        String newUrl = interceptedRequest.url().replaceFirst("(=)[^&]*", "$1" + PAYLOAD); // REPLACE ORIGINAL QUERY (e.g. ?category=gift) WITH A ' TO SCAPE THE SQL QUERY
        HttpClient client = HttpClient.newHttpClient(); // CREATES AN HTTP CLIENT

        try { // HANDLES URL SYNTAX PROBLEMS
            HttpRequest request = HttpRequest.newBuilder().uri(new URI(newUrl)).GET().build(); // CRAFTS A GET REQUEST WITH THE SPECIFIED URL
            try { // HANDLES REQUEST CONNECTIVITY PROBLEMS
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString()); // SENDS A REQUEST AND RETRIEVE ITS RESPONSE

                return switch (VULNTOSCAN) {
                    case SQLi ->
                            (response.statusCode() == 500) ? IsVulnerableCodes.VULNERABLE : IsVulnerableCodes.SAFE; // CHECKS IF HTTP RESPONSE RETRIEVES AN INTERNAL SERVER ERROR
                    case XSS ->
                            (response.statusCode() == 200) ? IsVulnerableCodes.VULNERABLE : IsVulnerableCodes.SAFE; // CHECKS IF HTTP RESPONSE CONTAINS THE <script>alert(1)</script> PAYLOAD REFLECTED ON THE RESPONSE BODY
                    case LFI ->
                            (response.body().contains("root:x:0:0:")) ? IsVulnerableCodes.VULNERABLE : IsVulnerableCodes.SAFE; // CHECKS IF HTTP RESPONSE BODY CONTAINS THE CONTENTS OF /etc/passwd FILE
                };

            } catch(IOException | InterruptedException e) { // CATCHES EXCEPTIONS RELATED TO CONNECTIVITY PROBLEMS WHEN SENDING THE HTTP REQUEST, PERHAPS, AN INVALID URL SENT
                return IsVulnerableCodes.REQUEST_PROBLEM;
            }
        } catch (URISyntaxException e) { // CATCHES EXCEPTIONS RELATED TO URL SYNTAX PROBLEMS (MAL-FORMED URLs)
            return IsVulnerableCodes.URL_SYNTAX_ERROR;
        }
    }
}
