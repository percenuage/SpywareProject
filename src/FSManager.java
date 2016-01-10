import org.apache.commons.io.FilenameUtils;
import spyware.fileSystemManager.DefaultSecureFSManager;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.swing.*;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Base64;

public class FSManager extends DefaultSecureFSManager {

	public static final String HTPASSWD = "./.htpasswd";

	@Override
	public boolean isPasswordCorrect(String login, char[] password) {
		boolean isCorrect = false;
		// Get String from array of char
		String passwordString = String.valueOf(password);

		// Set up Apr1HashUtil from file htpasswd
		HtpasswdUtils.setupFromFile(HTPASSWD);

		// Compare logins and passwords hashed
		if (HtpasswdUtils.compareCredential(login, passwordString)) {
			isCorrect = true;
		}

		if (!isCorrect) {
			JOptionPane.showMessageDialog(null, "Login or password is not valid for \n" + "User : " + login, "Info",
					JOptionPane.INFORMATION_MESSAGE);
		}
		return isCorrect;
	}

	@Override
	public void encryptDecrypt(File[] files) {
		boolean isCancel = false;
		String[] options = { "Cancel", "Encrypt", "Decrypt" };

		String rootPassword = JOptionPane.showInputDialog(null, "Enter root password");
		if (rootPassword!=null && HtpasswdUtils.compareCredential("root", rootPassword)) {
			
			KeyGeneratorSingleton keyGenerator = KeyGeneratorSingleton.getInstance(rootPassword);

			try {

				for (File file : files) {
					int response = JOptionPane.showOptionDialog(null,
							"What do you want to do with the file : " + file.getName(), "warn",
							JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, options, options[0]);

					if (response == 1) {
						encryptFile(file, keyGenerator.getCipher(), keyGenerator.getSecretKey());
					} else if (response == 2) {
						decryptFile(file, keyGenerator.getCipher(), keyGenerator.getSecretKey());
					} else {
						isCancel = true;
					}
				}
				if (!isCancel) {
					this.delete(files);
				}
				

			} catch (Exception e) {
				e.printStackTrace();
			}
		} else {
			JOptionPane.showMessageDialog(null, "Password is not valid for \n" + "User : root", "Info",
					JOptionPane.INFORMATION_MESSAGE);
		}
	}

	@Override
	public void sign(File[] files) {
		String[] options = { "Cancel", "Sign", "Verify" };
		for (File file : files) {
			int response = JOptionPane.showOptionDialog(null,
					"What do you want to do with the file : " + file.getName(), "warn", JOptionPane.DEFAULT_OPTION,
					JOptionPane.PLAIN_MESSAGE, null, options, options[0]);

			if (response == 1) {
				for (File filetosign : files) {
					FileValidator.signFile(filetosign);
				}
			} else if (response == 2) {
				for (File fileToVerify : files) {
					File pkey = new File(fileToVerify.getParent(), "publicKey_"+fileToVerify.getName());
					File sign = new File(fileToVerify.getParent(), "signature_"+fileToVerify.getName());
					Boolean isValid =  FileValidator.fileIsValid(fileToVerify, pkey, sign);
					System.out.println(isValid);
				}
			}
		}

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

	/**
	 * Encrypt a file with a cipher and a key.
	 *
	 * @param file
	 * @param cipher
	 * @param secretKey
	 * @throws Exception
	 */
	private void encryptFile(File file, Cipher cipher, SecretKey secretKey) throws Exception {
		byte[] bytes = Files.readAllBytes(file.toPath());
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] bytesEncrypted = cipher.doFinal(bytes);

		String filenameBase64 = getFilenameFromBase64(file, true);

		File fileEncrypted = new File(file.getParent(), filenameBase64);

		FileUtils.writeByteArrayToFile(fileEncrypted, bytesEncrypted);
	}

	/**
	 * Decrypt a file encrypted with a cipher and a key.
	 *
	 * @param file
	 * @param cipher
	 * @param secretKey
	 * @throws Exception
	 */
	private void decryptFile(File file, Cipher cipher, SecretKey secretKey) throws Exception {
		byte[] bytesEncrypted = Files.readAllBytes(file.toPath());
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] bytesDecrypted = cipher.doFinal(bytesEncrypted);

		String filename = getFilenameFromBase64(file, false);

		File fileDecrypted = new File(file.getParent(), filename);

		FileUtils.writeByteArrayToFile(fileDecrypted, bytesDecrypted);
	}

	public String getFilenameFromBase64(File file, boolean isEncodeMode) {
		String extension = FilenameUtils.getExtension(file.getName());
		String filename = FilenameUtils.getBaseName(file.getName());
		if (isEncodeMode) {
			filename = Base64.getEncoder().encodeToString(filename.getBytes(StandardCharsets.UTF_8));
		} else {
			filename = new String(Base64.getDecoder().decode(filename));
		}
		return filename + '.' + extension;
	}

}
