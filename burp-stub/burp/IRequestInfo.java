package burp;
import java.net.URL;
import java.util.List;
public interface IRequestInfo {
    URL getUrl();
    List<String> getHeaders();
    String getMethod();
    int getBodyOffset();
    List<IParameter> getParameters();
}
