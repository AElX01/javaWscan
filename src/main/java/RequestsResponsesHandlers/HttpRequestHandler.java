/*
package RequestsResponsesHandlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.logging.Logging;

import static web_vulnerabilities.Sql_Injection.SubertAppLogic;

public class HttpRequestHandler extends CheckRequestType implements HttpHandler
{
    private final Logging logging;

    public HttpRequestHandler(MontoyaApi api) {
        this.logging = api.logging();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent httpRequestToBeSent) {
        if (isPost(httpRequestToBeSent) || isGet(httpRequestToBeSent)) logging.logToOutput("xdxdxddx");
        return null;
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived httpResponseReceived) {
        return null;
    }
}
*/