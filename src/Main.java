import spyware.fileSystemManager.SecureFSManager;
import spyware.fileTree.FileTree;

public class Main {

    public static void main(String[] args) {
        // The next line should in fact be replaced by an instanciation of a subclass of
        // DefaultSecureManager.
        FSManager manager = new FSManager();
        new FileTree(manager);
    }
}
