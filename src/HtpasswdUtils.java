import org.apache.commons.codec.digest.Md5Crypt;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HtpasswdUtils {

    private static String dataHtpasswd = null;

    private HtpasswdUtils(){}

    /**
     * Set up utils class with htpasswd file
     *
     * @param htpasswdPath
     */
    public static void setupFromFile(String htpasswdPath) {
        try {
            // Get all credentials from file htpasswd
            dataHtpasswd = FileUtils.readFileToString(new File(htpasswdPath), StandardCharsets.UTF_8);
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (!isValidHtpasswd()) {
            dataHtpasswd = null;
        }
    }

    /**
     * Compare login and password with hash from htpsswd
     *
     * @param login
     * @param password
     * @return boolean
     */
    public static boolean compareCredential(String login, String password) {
        if (isSetup()) {
            // Get salt from apr1 hashed by login
            String salt = getSaltFromLogin(login);
            String hash = Md5Crypt.apr1Crypt(password, salt);
            if (dataHtpasswd.contains(login + ":" + hash)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Get the salt from htpsswd by login
     *
     * @param login
     * @return
     */
    public static String getSaltFromLogin(String login) {
        String salt = null;
        if (isSetup()) {
            // Use regex to retrieve the right credential with the login param.
            Pattern pattern = Pattern.compile(login + "(.*)");
            Matcher matcher = pattern.matcher(dataHtpasswd);
            if (matcher.find()) {
                // Salt between the second and third '$'
                salt = matcher.group(0).split("\\$")[2];
            }
        }
        return salt;
    }

    /**
     * Verify if the class was setting up calling setupFromFile method
     *
     * @return boolean
     */
    public static boolean isSetup() {
        return dataHtpasswd != null;
    }

    /**
     * Verify if the dataHtpasswd attrbute is a standard Htpasswd
     *
     * @return
     */
    private static boolean isValidHtpasswd() {
        // Use regex to verify if the data from htpasswd is correct
        Pattern pattern = Pattern.compile("((.+):\\$apr1(\\$.+){2}(\\n))+");
        Matcher matcher = pattern.matcher(dataHtpasswd);
        return matcher.matches();
    }

}
