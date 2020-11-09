package nguba.spring.ext;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.security.oauth2.provider.token.AccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * @author <a href="mailto:nguba@deloitte.co.uk">nguba@deloitte.co.uk</a>
 *
 */
@SpringBootConfiguration
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

	@Bean
	public JwtAccessTokenConverter accessTokenConverter(final AccessTokenConverter accessTokenConverter,
			final KeyPair keyPair) {
		final JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		converter.setKeyPair(keyPair);
		converter.setAccessTokenConverter(accessTokenConverter);
		return converter;
	}

	@Bean
	AccessTokenConverter defaultAccessTokenConverter() {
		final DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
		accessTokenConverter.setUserTokenConverter(new SubjectAttributeUserTokenConverter());
		return accessTokenConverter;
	}

	@Bean
	KeyPair keyPair() {
		try {
			final BigInteger modulus = new BigInteger(
					"18044398961479537755088511127417480155072543594514852056908450877656126120801808993616738273349107491806340290040410660515399239279742407357192875363433659810851147557504389760192273458065587503508596714389889971758652047927503525007076910925306186421971180013159326306810174367375596043267660331677530921991343349336096643043840224352451615452251387611820750171352353189973315443889352557807329336576421211370350554195530374360110583327093711721857129170040527236951522127488980970085401773781530555922385755722534685479501240842392531455355164896023070459024737908929308707435474197069199421373363801477026083786683");
			final BigInteger privateExponent = new BigInteger(
					"3851612021791312596791631935569878540203393691253311342052463788814433805390794604753109719790052408607029530149004451377846406736413270923596916756321977922303381344613407820854322190592787335193581632323728135479679928871596911841005827348430783250026013354350760878678723915119966019947072651782000702927096735228356171563532131162414366310012554312756036441054404004920678199077822575051043273088621405687950081861819700809912238863867947415641838115425624808671834312114785499017269379478439158796130804789241476050832773822038351367878951389438751088021113551495469440016698505614123035099067172660197922333993");
			final BigInteger publicExponent = new BigInteger("65537");

			final RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulus, publicExponent);
			final RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(modulus, privateExponent);

			final KeyFactory factory = KeyFactory.getInstance("RSA");

			return new KeyPair(factory.generatePublic(publicSpec), factory.generatePrivate(privateSpec));

		} catch (final Exception e) {
			throw new IllegalArgumentException(e);
		}
	}

	@Bean
	public TokenStore tokenStore(final JwtAccessTokenConverter converter) {
		return new JwtTokenStore(converter);
	}
}

/**
 * Legacy Authorization Server (spring-security-oauth2) does not support any <a
 * href target="_blank" href="https://tools.ietf.org/html/rfc7517#section-5">JWK
 * Set</a> endpoint.
 *
 * This class adds ad-hoc support in order to better support the other samples
 * in the repo.
 */
@FrameworkEndpoint
class JwkSetEndpoint {

	private final KeyPair keyPair;

	JwkSetEndpoint(final KeyPair keyPair) {
		this.keyPair = keyPair;
	}

	@GetMapping("/.well-known/jwks.json")
	@ResponseBody
	public Map<String, Object> getKey() {
		final RSAPublicKey publicKey = (RSAPublicKey) this.keyPair.getPublic();
		final RSAKey key = new RSAKey.Builder(publicKey).build();
		return new JWKSet(key).toJSONObject();
	}
}

/**
 * Legacy Authorization Server does not support a custom name for the user
 * parameter, so we'll need to extend the default. By default, it uses the
 * attribute {@code user_name}, though it would be better to adhere to the
 * {@code sub} property defined in the
 * <a target="_blank" href="https://tools.ietf.org/html/rfc7519">JWT
 * Specification</a>.
 */
class SubjectAttributeUserTokenConverter extends DefaultUserAuthenticationConverter {
	@Override
	public Map<String, ?> convertUserAuthentication(final Authentication authentication) {
		final Map<String, Object> response = new LinkedHashMap<>();
		response.put("sub", authentication.getName());
		if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty())
			response.put(AUTHORITIES, AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
		return response;
	}
}
