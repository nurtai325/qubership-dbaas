package org.qubership.cloud.dbaas.security;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.qubership.cloud.dbaas.rest.K8sOidcRestClient;

import io.smallrye.jwt.auth.principal.DefaultJWTCallerPrincipal;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipal;
import io.smallrye.jwt.auth.principal.JWTCallerPrincipalFactory;
import io.smallrye.jwt.auth.principal.ParseException;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Alternative;
import jakarta.inject.Inject;

import java.security.Key;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
@Alternative
@Priority(1)
public class K8sJWTCallerPrincipalFactory extends JWTCallerPrincipalFactory {
	@Inject
	@ConfigProperty(name = "dbaas.security.jwt.oidc-provider-url")
	String jwtIssuer;

	@Inject
	@ConfigProperty(name = "dbaas.security.jwt.audience")
	String jwtAudience;

	@Inject
	K8sOidcRestClient k8sOidcRestClient;

	String jwtJwksEndpoint;

	JwtConsumer jwtClaimsParser;

	List<JsonWebKey> jwks = new ArrayList<JsonWebKey>();

	public K8sJWTCallerPrincipalFactory() throws Exception {
		jwtClaimsParser = new JwtConsumerBuilder()
				.setRequireExpirationTime()
				.setRequireSubject()
				.setExpectedIssuer(jwtIssuer)
				.setExpectedAudience(jwtAudience)
				.setSkipSignatureVerification()
				.setJwsAlgorithmConstraints(
						ConstraintType.PERMIT, AlgorithmIdentifiers.RSA_USING_SHA256)
				.build();

		jwtJwksEndpoint = k8sOidcRestClient.getOidcConfiguration(jwtIssuer).jwks_uri;
	}

	@Override
	public JWTCallerPrincipal parse(String token, JWTAuthContextInfo authContextInfo) throws ParseException {
		try {
			JwtClaims claims = jwtClaimsParser.processToClaims(token);

			String keyId = claims.getClaimValueAsString("kid");
			JsonWebKey jsonWebKey = getJwk(keyId);

			if (jsonWebKey == null) {
				refreshJwks();
				if (jsonWebKey == null) {
					throw new ParseException("jwk not found");
				}
			}

			if (!verifySignature(token, jsonWebKey.getKey())) {
				throw new ParseException("invalid jwt signature");
			}

			return new DefaultJWTCallerPrincipal(claims);
		} catch (Exception ex) {
			throw new ParseException(ex.getMessage());
		}
	}

	private boolean verifySignature(String token, Key key) throws JoseException {
		JsonWebSignature jws = new JsonWebSignature();

		jws.setAlgorithmConstraints(
				new AlgorithmConstraints(ConstraintType.PERMIT, AlgorithmIdentifiers.RSA_USING_SHA256));

		jws.setCompactSerialization(token);

		jws.setKey(key);

		return jws.verifySignature();
	}

	public void refreshJwks() throws Exception {
		String jwksJson = k8sOidcRestClient.getJwks(jwtJwksEndpoint);
		JsonWebKeySet jKeys = new JsonWebKeySet(jwksJson);
		jwks = jKeys.getJsonWebKeys();
	}

	public JsonWebKey getJwk(String keyId) throws Exception {
		for (JsonWebKey jwk : jwks) {
			if (jwk.getKeyId() == keyId) {
				return jwk;
			}
		}
		return null;
	}
}
