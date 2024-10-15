package RequestsResponsesHandlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;

import java.time.LocalTime;

import static web_vulnerabilities.Sql_Injection.*;


public class ProxyHttpRequestHandler extends CheckRequestType implements ProxyRequestHandler {
    private final Logging logging;
    private static final String INFO = "INFO";
    private static final String WARNING = "WARNING";
    private static final String CRITICAL = "CRITICAL";

    public ProxyHttpRequestHandler(MontoyaApi api) {
        this.logging = api.logging();
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        if (isPost(interceptedRequest) || isGet(interceptedRequest)) {
            if (isGet(interceptedRequest) && isVulnerable(interceptedRequest)) {
                logging.logToOutput("[" + java.time.LocalTime.now() + "]" + " [" + WARNING + "] " + "potentially vulnerable site to query logic subverting on URL, might contain SQL query patterns (e.g. 'id' in 'www.site.com/index.php?id=1'");

            }
        }
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }
}
