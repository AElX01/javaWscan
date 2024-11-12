package output_messages;

import burp.api.montoya.logging.Logging;

import burp.api.montoya.proxy.http.InterceptedRequest;
import web_vulnerabilities.FileInclusion;
import web_vulnerabilities.ReflectedXss;
import web_vulnerabilities.Sql_Injection;
import web_vulnerabilities_constants.AvailableVulnerabilities;
import web_vulnerabilities_constants.IsVulnerableCodes;
import web_vulnerabilities_constants.StatusCodes;


public abstract class OutputMessages implements Sql_Injection, ReflectedXss, FileInclusion {
    private static final String URL_SYNTAX_ERROR = StatusCodes.ERROR_LOG + "url syntax error on the http request";
    private static final String INVALID_REQUEST_ERROR = StatusCodes.ERROR_LOG + "invalid HTTP request";

    public static void output(AvailableVulnerabilities VULNERABILITY, InterceptedRequest interceptedRequest, Logging logging) {
        switch (VULNERABILITY) {
            case SQLi:
                if (Sql_Injection.testSql(interceptedRequest)) outputIfMight(VULNERABILITY, logging);
                outputIfIs(VULNERABILITY, logging, Sql_Injection.isVulnerableToSQLi(interceptedRequest));
                break;
            case XSS:
                if (ReflectedXss.testXss(interceptedRequest)) outputIfMight(VULNERABILITY, logging);
                outputIfIs(VULNERABILITY, logging, ReflectedXss.isVulnerableToXss(interceptedRequest));
                break;
            case LFI:
                if (FileInclusion.testLFI(interceptedRequest)) outputIfMight(VULNERABILITY, logging);
                outputIfIs(VULNERABILITY, logging, FileInclusion.isVulnerableToLFI(interceptedRequest));
                break;
        }
    }

    private static void outputIfMight(AvailableVulnerabilities VULNERABILITY, Logging logging) { // OUTPUT IN CASE A VULNERABILITY MIGHT BE POSSIBLE
        logging.logToOutput(VULNERABILITY.getMIGHT_BE_VULNERABLE_LOG());
    }

    private static void outputIfIs(AvailableVulnerabilities VULNERABILITY, Logging logging, IsVulnerableCodes codeToOutput) { // OUTPUT IN CASE A VULNERABILITY HAS BEEN CONFIRMED
        switch (codeToOutput) {
            case VULNERABLE:
                logging.logToOutput(VULNERABILITY.getIS_VULNERABLE_LOG());
                break;
            case URL_SYNTAX_ERROR:
                logging.logToError(URL_SYNTAX_ERROR);
                break;
            case REQUEST_PROBLEM:
                logging.logToError(INVALID_REQUEST_ERROR);
                break;
        }
    }
}
