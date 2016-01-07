import org.apache.commons.io.FileUtils;

import java.io.File;
import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

public class KeyGeneratorSingleton {

	public static final String CIPHER_KEY = "./spyware.key";
	public static final String CIPHER_ALGORITHM = "DES";

	private static SecretKey secretKey;
	private static Cipher cipher;

	// Constructeur privé
	private KeyGeneratorSingleton() {
		try {
			cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			byte[] key = FileUtils.readFileToByteArray(new File(CIPHER_KEY));
			DESKeySpec desKeySpec = new DESKeySpec(key);
			SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(CIPHER_ALGORITHM);
			this.secretKey = secretKeyFactory.generateSecret(desKeySpec);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// Holder
	private static class SingletonHolder {
		// Instance unique non préinitialisée
		private static final KeyGeneratorSingleton INSTANCE = new KeyGeneratorSingleton();
	}

	// Point d'accès pour l'instance unique du singleton
	public static KeyGeneratorSingleton getInstance() {
		return SingletonHolder.INSTANCE;
	}

	public SecretKey getSecretKey() {
		return secretKey;
	}

	public static Cipher getCipher() {
		return cipher;
	}

	/**
	 * Check if the file is encrypted or not.
	 *
	 * @param file
	 * @return boolean
     */
	public static boolean isEncrypted(File file) {
		//TODO
		return false;
	}

}
