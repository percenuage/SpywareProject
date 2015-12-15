import spyware.fileSystemManager.DefaultSecureFSManager;

/**
 * Created by axel on 15/12/15.
 */
public class FSManager extends DefaultSecureFSManager {

    @Override
    public boolean authorize() {
        System.out.println("It's my Class !");
        return super.authorize();
    }
}
