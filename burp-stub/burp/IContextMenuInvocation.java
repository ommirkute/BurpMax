package burp;
public interface IContextMenuInvocation {
    byte getInvocationContext();
    IHttpRequestResponse[] getSelectedMessages();
    byte CONTEXT_PROXY_HISTORY    = 2;
    byte CONTEXT_TARGET_SITE_MAP_TABLE = 4;
    byte CONTEXT_SCANNER_RESULTS  = 6;
    byte CONTEXT_MESSAGE_EDITOR_REQUEST  = 0;
    byte CONTEXT_MESSAGE_EDITOR_RESPONSE = 1;
    byte CONTEXT_INTRUDER_PAYLOAD = 9;
    byte CONTEXT_REPEATER_REQUEST = 12;
}
