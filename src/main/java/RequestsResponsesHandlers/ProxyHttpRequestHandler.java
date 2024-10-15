package RequestsResponsesHandlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;

import java.net.http.HttpRequest;

import static web_vulnerabilities.Sql_Injection.*;


public class ProxyHttpRequestHandler extends CheckRequestType implements ProxyRequestHandler {
    private final Logging logging;

    public ProxyHttpRequestHandler(MontoyaApi api) {
        this.logging = api.logging();
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        if (isPost(interceptedRequest) || isGet(interceptedRequest)) {
            if (isGet(interceptedRequest) && isVulnerable(interceptedRequest)) {
                logging.logToOutput("");
            }
        }
        return ProxyRequestReceivedAction.continueWith(interceptedRequest);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }
}
