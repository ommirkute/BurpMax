package burp;
import javax.swing.JMenuItem;
import java.util.List;
public interface IContextMenuFactory {
    List<JMenuItem> createMenuItems(IContextMenuInvocation invocation);
}
