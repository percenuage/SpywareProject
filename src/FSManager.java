import spyware.fileSystemManager.DefaultSecureFSManager;

import javax.swing.*;
import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class FSManager extends DefaultSecureFSManager {

    public static final String HTACCESS = "./.htaccess";
    public static final String ALGORITHM_HASH = "SHA-512";

    @Override
    public boolean isPasswordCorrect(String login, char[] password) {
        boolean isCorrect = false;
        // Get String from array of char
        String passwordString = String.valueOf(password);

        try {
            // Get user access data from htaccess file (login:passwordHashed)
            String data = this.getDataFromFile(HTACCESS);
            // Split data (':') in order to get login and password into array.
            String[] dataArray = data.split(":");
            // Get password hash from password string
            String passwordParamHash = this.getHash(passwordString);

            // Compare logins and passwords hashed
            if (dataArray[0].equals(login) && dataArray[1].equals(passwordParamHash)) {
                isCorrect = true;
            }
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        if (isCorrect) {
            JOptionPane.showMessageDialog(
                    getFileTree(),
                    "Nice you can access \n" + "User : " + login,
                    "Info", JOptionPane.INFORMATION_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(
                    null,
                    "Login or password is not valid for \n" + "User : " + login,
                    "Info", JOptionPane.INFORMATION_MESSAGE);
        }
        return isCorrect;
    }

    /**
     * Get data from file with filename param.
     *
     * @param filename
     * @return String
     * @throws IOException
     */
    private String getDataFromFile(String filename) throws IOException {
        Path file = Paths.get(filename);
        return new String(Files.readAllBytes(file));
    }

    /**
     * @param password
     * @return String of the password hashed
     * @throws NoSuchAlgorithmException
     */
    private String getHash(String password) throws NoSuchAlgorithmException {
        byte[] hash = password.getBytes();
        MessageDigest md = MessageDigest.getInstance(ALGORITHM_HASH);
        md.update(hash);
        return new BigInteger(1, md.digest()).toString(16);
        //return md.digest().toString();
    }

    @Override
    public void encryptDecrypt(File[] files) {
        super.encryptDecrypt(files);
    }

    @Override
    public void sign(File[] files) {
        super.sign(files);
    }

    @Override
    public void delete(File[] files) {
        for (File file : files) {
            int dialogResult = JOptionPane.showConfirmDialog(null,
                    "Do you really want to delete the file : " + file.getName(),
                    "warn", JOptionPane.YES_NO_OPTION);
            if (dialogResult == 0) {
                if (file.delete()) {
                    System.out.println("Your file has been deleted");
                }
            }

        }
    }
}
