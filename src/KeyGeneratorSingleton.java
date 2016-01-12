import java.nio.charset.StandardCharsets;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;

public class KeyGeneratorSingleton {

	public static final String CIPHER_ALGORITHM = "DES";

	private static String password;
	private SecretKey secretKey;
	private Cipher cipher;

	// Constructeur privé
	private KeyGeneratorSingleton() {
		try {
			cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			byte[] key = password.getBytes(StandardCharsets.UTF_8);
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
	public static KeyGeneratorSingleton getInstance(String password) {
		KeyGeneratorSingleton.password = password;
		return SingletonHolder.INSTANCE;
	}

	public SecretKey getSecretKey() {
		return secretKey;
	}

	public Cipher getCipher() {
		return cipher;
	}

}
