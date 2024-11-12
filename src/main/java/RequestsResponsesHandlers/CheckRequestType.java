package RequestsResponsesHandlers;

import burp.api.montoya.proxy.http.InterceptedRequest;

public interface CheckRequestType
{
    static boolean isGet(InterceptedRequest interceptedRequest) {
        return interceptedRequest.method().equalsIgnoreCase("GET");
    }
}
