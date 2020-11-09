/**
 * 
 */
package nguba.spring.ext;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * @author <a href="mailto:nguba@deloitte.co.uk">nguba@deloitte.co.uk</a>
 *
 */
class KeyRotatorTest {

	private KeyPair actual;
	private KeyRotator rotator;

	@Test
	public void hasExpectedKeySize() {
		final RSAPublicKey rsa = (RSAPublicKey) actual.getPublic();

		assertThat(rsa.getModulus().bitLength()).isEqualTo(2048);
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
