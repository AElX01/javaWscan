package target_web_app;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;


abstract class web_application
{
    protected static URL web_app;

    protected static boolean applicationExist(String url) throws IOException {
        final HttpURLConnection request = (HttpURLConnection) web_app.openConnection();
        request.setRequestMethod("HEAD");
        final int status_code = request.getResponseCode();

        return status_code == 200;
    }

    private static boolean isValidUrl(String url)
    {
        try {
            new URL(url).toURI();
            return true;
        } catch (MalformedURLException | URISyntaxException e) {
            return false;
        }
    }

    protected static URL getInstance(String url) throws IOException
    {
        if (isValidUrl(url) && applicationExist(url)) return new URL(url);
        return null;
    }
}
