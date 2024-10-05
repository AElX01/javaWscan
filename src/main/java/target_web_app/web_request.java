package target_web_app;

import java.io.IOException;
import enums.app_availability;

import static enums.app_availability.*;


public class web_request extends web_application
{
    private static final String request_method = "GET";

    protected web_request(String url) throws IOException
    {
        web_app = getInstance(url);
    }

    public static app_availability check_url(String url) throws IOException
    {
        try {
            if (applicationExist(url)) return AVAILABLE;
            return UNREACHABLE;
        } catch (IOException e) {
            return IO_EXCEPTION;
        }
    }

}
