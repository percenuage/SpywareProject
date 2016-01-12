import java.io.File;
import java.io.FileNotFoundException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;


public class FileValidator {

	public static final String SIGNATURE = ".signature_";
	public static final String PUBLIC_KEY = ".publicKey_";

	public static final String SIGNATURE_ALGORITHM = "SHA1withDSA";
	public static final String SIGNATURE_KEY_FACTORY_ALGORITHM = "DSA";
	public static final String SIGNATURE_PROVIDER = "SUN";
	public static final String SIGNATURE_SECURE_RANDOM = "SHA1PRNG";


	/**
	 * Sign a file
	 *
	 * @param file
     */
	public static void signFile(File file) {
		try {

			/* Generate a key pair */
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(SIGNATURE_KEY_FACTORY_ALGORITHM, SIGNATURE_PROVIDER);
			SecureRandom random = SecureRandom.getInstance(SIGNATURE_SECURE_RANDOM, SIGNATURE_PROVIDER);

			keyGen.initialize(1024, random);

			KeyPair pair = keyGen.generateKeyPair();
			PrivateKey priv = pair.getPrivate();
			PublicKey pub = pair.getPublic();

			/* Create a signature object and initialize it with the private key */
			Signature dsa = Signature.getInstance(SIGNATURE_ALGORITHM, SIGNATURE_PROVIDER);
			dsa.initSign(priv);

			/* Update and sign the data */
			byte[] dataToSign = FileUtils.readFileToByteArray(file);
			dsa.update(dataToSign);

			/* Generate a signature */
			byte[] dataSigned = dsa.sign();

			// Get base name
			String filename = FilenameUtils.getBaseName(file.getName());

			// Save signature
			FileUtils.writeByteArrayToFile(new File(file.getParentFile(), SIGNATURE + filename), dataSigned);
			
			// Save public key
			FileUtils.writeByteArrayToFile(new File(file.getParentFile(), PUBLIC_KEY + filename), pub.getEncoded());

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Verify if the file is valid or not
	 *
	 * @param file
	 * @return boolean
     */
	public static boolean fileIsValid(File file) {
		boolean verifies = false;
		try {
			// Get base name
			String filename = FilenameUtils.getBaseName(file.getName());

			// Get signature
			File sign = new File(file.getParent(), SIGNATURE + filename);

			// Get public key
			File pkey = new File(file.getParent(), PUBLIC_KEY + filename);

			/* Import encoded public key */
			byte[] pubKeyEncrypted = FileUtils.readFileToByteArray(pkey);

			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyEncrypted);
			KeyFactory keyFactory = KeyFactory.getInstance(SIGNATURE_KEY_FACTORY_ALGORITHM, SIGNATURE_PROVIDER);
			PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

			/* Input the signature bytes */
			byte[] signature = FileUtils.readFileToByteArray(sign);

			/* Create a signature object and initialize it with the public key */
			Signature dsa = Signature.getInstance(SIGNATURE_ALGORITHM, SIGNATURE_PROVIDER);
			dsa.initVerify(pubKey);

			/* Update and verify the data */
			byte[] dataToVerify = FileUtils.readFileToByteArray(file);
			dsa.update(dataToVerify);

			verifies = dsa.verify(signature);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return verifies;
	}
}
