import java.io.File;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class KeyGeneratorSingleton {
	private static KeyGenerator keyGenerator;
	private static SecretKey secretKey;
	private static Cipher cipher;

	// Constructeur privé
	private KeyGeneratorSingleton() {
		try {
			keyGenerator = KeyGenerator.getInstance(FSManager.ALGORITHM_CIPHER);
			secretKey = keyGenerator.generateKey();
			cipher = Cipher.getInstance(FSManager.ALGORITHM_CIPHER);
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
	
	public Cipher getCipher() {
		return cipher;
	}
	
	public SecretKey getSecretKey() {
		return secretKey;
	}
	
	public static boolean isEncrypted(File file) {
		return false;
	}

}
