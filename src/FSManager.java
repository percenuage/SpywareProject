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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.*;

public class FSManager extends DefaultSecureFSManager {

	public static final String HTPASSWD = "./.htpasswd";
	public static final String ROOT = "root";

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
			JOptionPane.showMessageDialog(null, "Login or password is not valid for \n" + "User : " +
					login, "Error", JOptionPane.ERROR_MESSAGE);
		}
		return isCorrect;
	}

	@Override
	public void encryptDecrypt(File[] files) {
		List<File> fileList = listFiles(files[0]);

		String rootPassword = this.inputPassword();

		if (rootPassword != null && HtpasswdUtils.compareCredential(ROOT, rootPassword)) {

			KeyGeneratorSingleton keyGenerator = KeyGeneratorSingleton.getInstance(rootPassword);

			String[] options = { "Cancel", "Encrypt", "Decrypt" };
			int response = JOptionPane.showOptionDialog(null,
					"What do you want to do with : " + files[0].getAbsolutePath(), "Options",
					JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);

			if (response == 1) {
				StringBuilder sb = new StringBuilder();
				for (File file : fileList) {
					try {
						encryptFile(file, keyGenerator.getCipher(), keyGenerator.getSecretKey());
						this.secureDelete(file);
						sb.append(file.getName()).append(" has been encrypted\n");
					} catch (Exception e) {
						sb.append(file.getName()).append(" has not been encrypted\n");
						e.printStackTrace();
					}
				}
				JOptionPane.showMessageDialog(null, sb.toString(), "Information",
						JOptionPane.INFORMATION_MESSAGE);
			} else if (response == 2) {
				StringBuilder sb = new StringBuilder();
				for (File file : fileList) {
					try {
						decryptFile(file, keyGenerator.getCipher(), keyGenerator.getSecretKey());
						this.secureDelete(file);
						sb.append(file.getName()).append(" has been decrypted\n");
					} catch (IllegalArgumentException | IllegalBlockSizeException e) {
						sb.append(file.getName()).append(" has not been decrypted because it's a clear file\n");
					} catch (Exception e) {
						sb.append(file.getName()).append(" has not been decrypted\n");
						e.printStackTrace();
					}
				}
				JOptionPane.showMessageDialog(null, sb.toString(), "Information",
						JOptionPane.INFORMATION_MESSAGE);
			}
		} else {
			JOptionPane.showMessageDialog(null, "Password is not valid for \n" + "User : " + ROOT, "Error",
					JOptionPane.ERROR_MESSAGE);
		}
}

	@Override
	public void sign(File[] files) {
		List<File> fileList = listFiles(files[0]);

		String[] options = { "Cancel", "Sign", "Verify" };
		int response = JOptionPane.showOptionDialog(null,
				"What do you want to do with : " + files[0].getAbsolutePath(),
				"Options", JOptionPane.DEFAULT_OPTION,
				JOptionPane.QUESTION_MESSAGE, null, options, options[0]);


		if (response == 1) {
			StringBuilder sb = new StringBuilder();
			for (File file : fileList) {
				if (!file.getName().contains(FileValidator.PUBLIC_KEY) &&
						!file.getName().contains(FileValidator.SIGNATURE)) {
					FileValidator.signFile(file);
					sb.append(file.getName()).append(" has been signed\n");
				}
			}
			JOptionPane.showMessageDialog(null, sb.toString(), "Information",
					JOptionPane.INFORMATION_MESSAGE);
		} else if (response == 2) {
			StringBuilder sb = new StringBuilder();
			for (File file : fileList) {
				if (FileValidator.fileIsValid(file)) {
					sb.append(file.getName()).append(" is valid\n");
				} else {
					sb.append(file.getName()).append(" is invalid or not signed !\n");
				}
			}
			JOptionPane.showMessageDialog(null, sb.toString(), "Information",
					JOptionPane.INFORMATION_MESSAGE);
		}
	}

	@Override
	public void delete(File[] files) {
		List<File> fileList = listFiles(files[0]);

		int dialogResult = JOptionPane.showConfirmDialog(null,
				"Do you really want to delete : " + files[0].getAbsolutePath(), "Confirmation",
				JOptionPane.YES_NO_OPTION);

		if (dialogResult == 0) {
			StringBuilder sb = new StringBuilder();
			for (File file : fileList) {
				try {
					this.secureDelete(file);
					sb.append(file.getName()).append(" has been securely deleted\n");
				} catch (IOException e) {
					sb.append(file.getName()).append(" has not been deleted\n");
					e.printStackTrace();
				}
			}
			if (files[0].isDirectory()) {
				files[0].delete();
				sb.append(files[0].getName()).append(" has been deleted\n");
			}
			JOptionPane.showMessageDialog(null, sb.toString(), "Information",
					JOptionPane.INFORMATION_MESSAGE);
		}
	}

	/**
	 * Secure file deletion
	 *
	 * @param file
	 * @return boolean
     */
	private void secureDelete(File file) throws IOException {
		if (file.exists()) {
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
			file.delete();
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
