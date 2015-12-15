import spyware.fileSystemManager.SecureFSManager;
import spyware.fileTree.FileTree;

/**
 * Created by axel on 15/12/15.
 */
public class Main {

    public static void main(String[] args) {
        // The next line should in fact be replaced by an instanciation of a subclass of
        // DefaultSecureManager.
        FSManager manager = new FSManager();
        new FileTree(manager);
    }
}
