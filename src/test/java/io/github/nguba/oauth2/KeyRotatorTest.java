/**
 * 
 */
package io.github.nguba.oauth2;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * 
 * @author <a href="mailto:nguba@mac.com">nguba@mac.com</a>
 *
 */
class KeyRotatorTest {

	private KeyPair actual;
	private KeyRotator rotator;

	@Test
	public void hasExpectedKeySize() {
		assertThat(((RSAPublicKey) actual.getPublic()).getModulus().bitLength()).isEqualTo(2048);
	}

	@Test
	public void makePrivateRsa_HasExpectedAlgorithm() {
		assertThat(actual.getPrivate().getAlgorithm()).isEqualTo("RSA");
	}

	@Test
	public void makePublicRsa_HasExpectedAlgorithm() {
		assertThat(actual.getPublic().getAlgorithm()).isEqualTo("RSA");
	}

	@BeforeEach
	void setUp() throws Exception {
		rotator = new KeyRotator(2048);
		actual = rotator.makeRsa();
	}
}
