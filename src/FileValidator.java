import java.io.File;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.io.FileUtils;

public class FileValidator {

	public static void signFile(File file) {
		try {

			/* Generate a key pair */
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
			SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

			keyGen.initialize(1024, random);

			KeyPair pair = keyGen.generateKeyPair();
			PrivateKey priv = pair.getPrivate();
			PublicKey pub = pair.getPublic();

			/*
			 * Create a signature object and initialize it with the private key
			 */
			Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
			dsa.initSign(priv);

			/* Update and sign the data */
			byte[] dataToSign = FileUtils.readFileToByteArray(file);
			dsa.update(dataToSign);

			/* Generate a signature */
			byte[] dataSigned = dsa.sign();

			// Save signature
			FileUtils.writeByteArrayToFile(new File(file.getParentFile(), "signature_"+file.getName()), dataSigned);
			
			// Save public key
			FileUtils.writeByteArrayToFile(new File(file.getParentFile(),"publicKey_"+file.getName()), pub.getEncoded());

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static boolean fileIsValid(File file, File pkey, File sign) {
		boolean verifies = false;
		try {
			/* Import encoded public key */
			byte[] pubKeyEncrypted = FileUtils.readFileToByteArray(pkey);

			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pubKeyEncrypted);
			KeyFactory keyFactory = KeyFactory.getInstance("DSA", "SUN");
			PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

			/* Input the signature bytes */

			byte[] signature = FileUtils.readFileToByteArray(sign);

			/*
			 * Create a signature object and initialize it with the private key
			 */
			Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
			dsa.initVerify(pubKey);

			/* Update and verify the data */
			byte[] dataToVerify = FileUtils.readFileToByteArray(file);
			dsa.update(dataToVerify);

			verifies = dsa.verify(signature);
			
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		return verifies;
	}
}
