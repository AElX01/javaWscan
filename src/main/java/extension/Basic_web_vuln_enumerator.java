package extension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;


public class Basic_web_vuln_enumerator implements BurpExtension
{
    @Override
    public void initialize(MontoyaApi api)
    {
        api.extension().setName("basic web enumerator");
        api.userInterface().registerSuiteTab("web scan", extension_ui.getUser_interface(api));
    }

}