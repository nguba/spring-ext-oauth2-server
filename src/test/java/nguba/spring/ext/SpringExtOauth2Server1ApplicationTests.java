package nguba.spring.ext;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class SpringExtOauth2Server1ApplicationTests {

	@Test
	void test() throws Exception {
		final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		final KeyPair kp = kpg.generateKeyPair();

		System.out.println(kp.getPublic());
	}
}
