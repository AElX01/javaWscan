package RequestsResponsesHandlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;

import web_vulnerabilities.IsVulnerableCodes;
import web_vulnerabilities.StatusCodes;
import static web_vulnerabilities.Sql_Injection.*;


public class ProxyHttpRequestHandler extends CheckRequestType implements ProxyRequestHandler {
    private final Logging logging; // SETS A Logging TYPE VARIABLE TO DISPLAY ON OUTPUT EXTENSION FINDS

    public ProxyHttpRequestHandler(MontoyaApi api) { // PARSES MONTOYA API TO METHOD TO ASSIGN LOGGING FUNCTIONALITY TO THE ABOVE VARIABLE
        this.logging = api.logging();
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        logging.logToOutput(""); // FOR EACH SCANNED WEBSITE, ACCOMMODATES OUTPUT MAKING IT MORE READABLE

        if (isGet(interceptedRequest)) {
            if (mightBeVulnerable(interceptedRequest)) {
                logging.logToOutput(StatusCodes.WARNING_LOG + "potentially vulnerable site to query logic subverting on URL, might contain SQL query patterns (e.g. 'id' in 'www.site.com/index.php?id=1')");
                logging.logToOutput(StatusCodes.INFO_LOG + "looking for SQLi on " + interceptedRequest.url());

                switch (isVulnerable(interceptedRequest)) {
                    case VULNERABLE:
                        logging.logToOutput(StatusCodes.CRITICAL_LOG + "SQLi PRESENT ON SYSTEM DUE TO INTERNAL SERVER ERROR WHEN PARSING A ' CHARACTER TO QUERY");
                        break;
                    case URL_SYNTAX_ERROR:
                        logging.logToError(StatusCodes.ERROR_LOG + "url syntax error on the http request");
                        break;
                    case REQUEST_PROBLEM:
                        logging.logToError(StatusCodes.ERROR_LOG + "there was a problem sending the HTTP request, check internet connection");
                        break;
                    default:
                        break;
                }

            }
        }
        return ProxyRequestReceivedAction.continueWith(interceptedRequest); // FORWARDS INTERCEPTED REQUEST WITHOUT MODIFYING IT
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return null;
    }
}
