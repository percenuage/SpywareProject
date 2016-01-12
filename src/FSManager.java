import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.filefilter.DirectoryFileFilter;
import org.apache.commons.io.filefilter.RegexFileFilter;
import spyware.fileSystemManager.DefaultSecureFSManager;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.swing.*;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.*;

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
		String[] options = { "Cancel", "Encrypt", "Decrypt" };

		List<File> fileList = listFiles(files[0]);

		String rootPassword = this.inputPassword();

		if (rootPassword != null && HtpasswdUtils.compareCredential("root", rootPassword)) {
			
			KeyGeneratorSingleton keyGenerator = KeyGeneratorSingleton.getInstance(rootPassword);

			try {

				for (File file : fileList) {
					int response = JOptionPane.showOptionDialog(null,
							"What do you want to do with the file : " + file.getAbsolutePath(), "warn",
							JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE, null, options, options[0]);

					if (response == 1) {
						encryptFile(file, keyGenerator.getCipher(), keyGenerator.getSecretKey());
						this.secureDelete(file);
						JOptionPane.showMessageDialog(null, "The file was encrypted", "Info",
								JOptionPane.INFORMATION_MESSAGE);
					} else if (response == 2) {
						decryptFile(file, keyGenerator.getCipher(), keyGenerator.getSecretKey());
						this.secureDelete(file);
						JOptionPane.showMessageDialog(null, "The file was decrypted", "Info",
								JOptionPane.INFORMATION_MESSAGE);
					}
				}

			} catch (IllegalArgumentException | IllegalBlockSizeException e) {
				System.out.println("You can't decrypt a clear file");
				JOptionPane.showMessageDialog(null, "You can't decrypt a clear file", "warn",
						JOptionPane.INFORMATION_MESSAGE);
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

		List<File> fileList = listFiles(files[0]);

		for (File file : fileList) {

			int response = JOptionPane.showOptionDialog(null,
					"What do you want to do with the file : " + file.getAbsolutePath(), "warn", JOptionPane.DEFAULT_OPTION,
					JOptionPane.PLAIN_MESSAGE, null, options, options[0]);

			if (response == 1) {
				FileValidator.signFile(file);
			} else if (response == 2) {
				Boolean isValid =  FileValidator.fileIsValid(file);
				if (isValid) {
					JOptionPane.showMessageDialog(null, "The file is valid", "Info",
							JOptionPane.INFORMATION_MESSAGE);
				} else {
					JOptionPane.showMessageDialog(null, "The file is not signed", "warn",
							JOptionPane.INFORMATION_MESSAGE);
				}
			}
		}

	}

	@Override
	public void delete(File[] files) {
		for (File file : files) {
			int dialogResult = JOptionPane.showConfirmDialog(null,
					"Do you really want to delete the file : " + file.getAbsolutePath(), "warn", JOptionPane.YES_NO_OPTION);
			if (dialogResult == 0) {
				if (this.secureDelete(file)) {
					System.out.println("Your file has been deleted");
				}
			}

		}
	}

	/**
	 * Secure file deletion
	 *
	 * @param file
	 * @return boolean
     */
	private Boolean secureDelete(File file) {
		boolean isDeleted = false;
		if (file.exists()) {
			try {
				SecureRandom random = new SecureRandom();
				RandomAccessFile raf = new RandomAccessFile(file, "rws");
				raf.seek(0);
				raf.getFilePointer();
				byte[] data = new byte[64];
				int pos = 0;
				while (pos < file.length()) {
					random.nextBytes(data);
					raf.write(data);
					pos += data.length;
				}
				raf.close();
				isDeleted = file.delete();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return isDeleted;
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

	/**
	 * Encode or decode a filename into Base64
	 *
	 * @param file
	 * @param isEncodeMode
     * @return string
     */
	private String getFilenameFromBase64(File file, boolean isEncodeMode) {
		String extension = FilenameUtils.getExtension(file.getName());
		String filename = FilenameUtils.getBaseName(file.getName());
		if (isEncodeMode) {
			filename = Base64.getEncoder().encodeToString(filename.getBytes(StandardCharsets.UTF_8));
		} else {
			filename = new String(Base64.getDecoder().decode(filename));
		}
		return filename + '.' + extension;
	}

	/**
	 * Get files from directory and subdirectories
	 *
	 * @param file
	 * @return list files
     */
	private List<File> listFiles(final File file) {
		List<File> files = new ArrayList<>();
		if (file.isDirectory()) {
			files.addAll(FileUtils.listFiles(file, new RegexFileFilter("^(.*?)"), DirectoryFileFilter.DIRECTORY));
		} else {
			files.add(file);
		}
		return files;
	}

	/**
	 * Show input password field
	 *
	 * @return string password
     */
	private String inputPassword() {
		String password = null;
		JPanel panel = new JPanel();
		JLabel label = new JLabel("Password: ");
		JPasswordField pass = new JPasswordField(10);
		panel.add(label);
		panel.add(pass);
		String[] options = new String[]{"OK", "Cancel"};
		int option = JOptionPane.showOptionDialog(null, panel, "Enter a root password",
				JOptionPane.NO_OPTION, JOptionPane.PLAIN_MESSAGE,
				null, options, options[1]);
		if(option == 0) {// pressing OK button
			password = new String(pass.getPassword());
		}
		return password;
	}

}
