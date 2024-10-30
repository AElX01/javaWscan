/*
AElX01 RED TEAM EXTENSION

THIS IS A JAVA EXTENSION DESIGNED TO LOOK FOR BASIC VULNERABILITIES ON A WEB APPLICATION.
THE BELOW CODE CREATES A BURP SUITE EXTENSION WHICH WILL INTERCEPT HTTP REQUESTS TROUGH THE BURP SUITE PROXY
SO CERTAIN CLASSES WITHIN THIS EXTENSION CAN DETECT CERTAIN PATTERNS AND PERFORM HARMLESS TESTS ON WEBSITES.
 */

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
        api.proxy().registerRequestHandler(new ProxyHttpRequestHandler(api)); // REGISTER CLASS WITH PROXY HANDLERS BURP SUITE MUST COMMUNICATE TO
        api.logging().logToOutput("[!] legal disclaimer: using this extension to scan/hack a site without EXPLICIT consent is illegal");
        api.logging().logToOutput("\n[*] starting @ " + java.time.LocalTime.now() + " " + java.time.LocalDate.now() + "\n");
    }

}