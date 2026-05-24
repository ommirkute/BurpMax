package burp;
public interface IParameter {
    byte PARAM_URL    = 0;
    byte PARAM_BODY   = 1;
    byte PARAM_COOKIE = 2;
    String getName();
    String getValue();
    byte getType();
}
