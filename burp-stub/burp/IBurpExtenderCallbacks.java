package burp;
import java.io.OutputStream;
public interface IBurpExtenderCallbacks {
    void setExtensionName(String name);
    void registerHttpListener(IHttpListener listener);
    void registerExtensionStateListener(IExtensionStateListener listener);
    void addSuiteTab(ITab tab);
    boolean isInScope(java.net.URL url);
    IExtensionHelpers getHelpers();
    OutputStream getStdout();
    OutputStream getStderr();
    String loadExtensionSetting(String name);
    void saveExtensionSetting(String name, String value);
    void sendToRepeater(String host, int port, boolean useHttps, byte[] request, String tabCaption);
    // Active scanning support
    IHttpRequestResponse makeHttpRequest(IHttpService service, byte[] request);
    IHttpRequestResponse[] getSiteMap(String urlPrefix);
    void registerContextMenuFactory(IContextMenuFactory factory);
}
// temporarily patching to add EOF - need to edit properly
