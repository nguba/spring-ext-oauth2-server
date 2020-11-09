/**
 * 
 */
package io.github.nguba.oauth2;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * 
 * @author <a href="mailto:nguba@mac.com">nguba@mac.com</a>
 *
 */
public final class KeyRotator {

	private final KeyPairGenerator kpg;

	/**
	 * @param keySize
	 * @throws NoSuchAlgorithmException
	 * 
	 */
	public KeyRotator(final int keySize) throws NoSuchAlgorithmException {
		kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(keySize);
	}

	/**
	 * @return
	 */
	public KeyPair makeRsa() {
		return kpg.generateKeyPair();
	}

}
