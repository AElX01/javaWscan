package extension;

import RequestsResponsesHandlers.ProxyHttpRequestHandler;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

public class JavaWScan implements BurpExtension
{
    public final String EXTENSION_NAME = "JavaWScan";

    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName(EXTENSION_NAME);
        api.proxy().registerRequestHandler(new ProxyHttpRequestHandler(api));
        api.logging().logToOutput("[!] legal disclaimer: using this extension to scan/hack a site without EXPLICIT consent is illegal");
        api.logging().logToOutput("\n[*] starting @ " + java.time.LocalTime.now() + " " + java.time.LocalDate.now() + "\n");
    }

}