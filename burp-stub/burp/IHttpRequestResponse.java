package burp;
public interface IHttpRequestResponse {
    byte[] getRequest();
    byte[] getResponse();
    IHttpService getHttpService();
}
