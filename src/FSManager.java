import spyware.fileSystemManager.DefaultSecureFSManager;
import sun.misc.IOUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.swing.*;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class FSManager extends DefaultSecureFSManager {

	public static final String HTACCESS = "./.htaccess";
	public static final String ALGORITHM_HASH = "SHA-512";
	public static final String ALGORITHM_CIPHER = "DES";
	public static Charset ENCODING = StandardCharsets.UTF_8;

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
			JOptionPane.showMessageDialog(getFileTree(), "Nice you can access \n" + "User : " + login, "Info",
					JOptionPane.INFORMATION_MESSAGE);
		} else {
			JOptionPane.showMessageDialog(null, "Login or password is not valid for \n" + "User : " + login, "Info",
					JOptionPane.INFORMATION_MESSAGE);
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
		// return md.digest().toString();
	}

	@Override
	public void encryptDecrypt(File[] files) {

		KeyGeneratorSingleton keyGenerator = KeyGeneratorSingleton.getInstance();

		try {

			for (File file : files) {
				String[] options = new String[] { "Cancel", "Encrypt", "Decrypt" };
				int response = JOptionPane.showOptionDialog(null,
						"Do you want to encrypt or decrypt the file : " + file.getName(), "warn",
						JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, options, options[0]);

				if (response == 1) {
					encryptFile(file, keyGenerator.getCipher(), keyGenerator.getSecretKey());
				} else if (response == 2) {
					decryptFile(file, keyGenerator.getCipher(), keyGenerator.getSecretKey());
				}
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void sign(File[] files) {
		super.sign(files);
	}

	private void encryptFile(File file, Cipher cipher, SecretKey secretKey) throws Exception {
		byte[] bytes = Files.readAllBytes(file.toPath());
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] bytesEncrypted = cipher.doFinal(bytes);

		/*
		 * String extension = FilenameUtils.getExtension(file.getName()); byte[]
		 * byteFilenameEncrypted =
		 * cipher.doFinal(file.getName().getBytes(ENCODING)); String
		 * filenameEncrypted = new String("coucou") +"."+ extension;
		 * 
		 * System.out.println(filenameEncrypted);
		 * 
		 * file.renameTo(new File(file.getParentFile(), filenameEncrypted));
		 */

		FileUtils.writeByteArrayToFile(file, bytesEncrypted);

		System.out.println(new String(bytesEncrypted));
	}

	private void decryptFile(File file, Cipher cipher, SecretKey secretKey) throws Exception {
		byte[] bytesEncrypted = Files.readAllBytes(file.toPath());
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] bytesDecrypted = cipher.doFinal(bytesEncrypted);

		FileUtils.writeByteArrayToFile(file, bytesDecrypted);

		System.out.println(new String(bytesDecrypted));
	}

	@Override
	public void delete(File[] files) {
		for (File file : files) {
			int dialogResult = JOptionPane.showConfirmDialog(null,
					"Do you really want to delete the file : " + file.getName(), "warn", JOptionPane.YES_NO_OPTION);
			if (dialogResult == 0) {
				if (file.delete()) {
					System.out.println("Your file has been deleted");
				}
			}

		}
	}
}
