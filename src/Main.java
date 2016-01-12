
import spyware.fileTree.FileTree;

import java.security.NoSuchAlgorithmException;


public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException {
        // The next line should in fact be replaced by an instanciation of a subclass of
        // DefaultSecureManager.
        FSManager manager = new FSManager();
        new FileTree(manager);
    }
}
