package org.qubership.cloud.dbaas.rest;

import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import jakarta.ws.rs.core.HttpHeaders;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import static jakarta.ws.rs.Priorities.AUTHENTICATION;

@Priority(AUTHENTICATION)
public class K8sTokenAuthFilter implements ClientRequestFilter {
	@Inject
	@ConfigProperty(name = "dbaas.security.token.netcracker")
	private String authTokenLocation;

	private NumericDate currentExp;

	private String token;

	public K8sTokenAuthFilter() throws Exception {
		refreshToken();
	}

	@Override
	public void filter(ClientRequestContext clientRequestContext) throws IOException {
		if (currentExp.isBefore(NumericDate.now())) {
			try {
				refreshToken();
			} catch (InvalidJwtException | MalformedClaimException e) {
				throw new IOException("Invalid Kubernetes Netcracker token", e);
			}
		}

		clientRequestContext.getHeaders().add(HttpHeaders.AUTHORIZATION, token);
	}

	public void refreshToken() throws IOException, InvalidJwtException, MalformedClaimException {
		String tokenContents = Files.readString(Path.of(authTokenLocation));
		JwtConsumer jwtConsumer = new JwtConsumerBuilder()
				.setSkipAllValidators()
				.setDisableRequireSignature()
				.setSkipSignatureVerification()
				.build();
		JwtClaims claims = jwtConsumer.processToClaims(tokenContents);
		currentExp = claims.getExpirationTime();
		token = tokenContents;
	}
}
