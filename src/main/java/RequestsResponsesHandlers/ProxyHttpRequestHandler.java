package RequestsResponsesHandlers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;

import web_vulnerabilities_constants.AvailableVulnerabilities;
import web_vulnerabilities_constants.StatusCodes;

import static output_messages.OutputMessages.*;

public class ProxyHttpRequestHandler extends CheckRequestType implements ProxyRequestHandler {
    private final Logging logging; // SETS A Logging TYPE VARIABLE TO DISPLAY EXTENSION FINDS

    // ARRAY USED TO ITERATE OVER ALL AVAILABLE VULNERABILITIES AND GET THEIR LOG MESSAGES TO REDUCE ProxyHttpRequestHandler CLASS SIZE
    private final AvailableVulnerabilities[] VULNERABILITIES = {
            AvailableVulnerabilities.SQLi,
            AvailableVulnerabilities.XSS,
            AvailableVulnerabilities.LFI
    };

    public ProxyHttpRequestHandler(MontoyaApi api) { // PARSES MONTOYA API TO METHOD TO ASSIGN LOGGING FUNCTIONALITY TO THE ABOVE VARIABLE
        this.logging = api.logging();
    }

    /*
    When Burp Suit intercepts a request, it automatically calls handleRequestReceived(). in this case, this will servers as
    the main() method of the extension as it every test is performed from here.
     */
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {

        if (isGet(interceptedRequest)) {
            for (AvailableVulnerabilities VULN: VULNERABILITIES) {
                logging.logToOutput(StatusCodes.INFO_LOG + "looking for " + VULN.getVULNERABILITY() + " on " + interceptedRequest.url());
                output(VULN, interceptedRequest, logging); // GENERATE THE RIGHT STDOUT/STDERR OUTPUT
            }
        }

        return ProxyRequestReceivedAction.continueWith(interceptedRequest); // FORWARDS INTERCEPTED REQUEST WITHOUT MODIFYING IT
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return null;
    }
}
