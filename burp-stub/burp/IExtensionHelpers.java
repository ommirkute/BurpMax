package burp;
import java.net.URL;
import java.util.List;
public interface IExtensionHelpers {
    IRequestInfo  analyzeRequest(IHttpRequestResponse request);
    IRequestInfo  analyzeRequest(byte[] request);
    IRequestInfo  analyzeRequest(IHttpService service, byte[] request);
    IResponseInfo analyzeResponse(byte[] response);
    String        bytesToString(byte[] bytes);
    byte[]        updateParameter(byte[] request, IParameter parameter);
    IParameter    buildParameter(String name, String value, byte type);
}
