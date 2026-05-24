package burp;
import java.util.List;
public interface IResponseInfo {
    List<String> getHeaders();
    short getStatusCode();
    int getBodyOffset();
}
