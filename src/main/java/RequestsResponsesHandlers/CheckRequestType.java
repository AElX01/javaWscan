package RequestsResponsesHandlers;

import burp.api.montoya.proxy.http.InterceptedRequest;

public abstract class CheckRequestType
{
    public static boolean isPost(InterceptedRequest interceptedRequest) {
        return interceptedRequest.method().equalsIgnoreCase("POST");
    }

    public static boolean isGet(InterceptedRequest interceptedRequest) {
        return interceptedRequest.method().equalsIgnoreCase("GET");
    }
}
