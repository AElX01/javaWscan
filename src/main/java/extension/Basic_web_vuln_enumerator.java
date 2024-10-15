package extension;

import RequestsResponsesHandlers.ProxyHttpRequestHandler;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;


public class Basic_web_vuln_enumerator implements BurpExtension
{
    public final String EXTENSION_NAME = "basic web enumerator";

    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName(EXTENSION_NAME);
        api.proxy().registerRequestHandler(new ProxyHttpRequestHandler(api));
    }

}