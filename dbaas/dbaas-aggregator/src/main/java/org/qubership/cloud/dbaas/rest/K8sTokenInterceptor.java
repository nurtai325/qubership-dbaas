package org.qubership.cloud.dbaas.rest;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;

public class K8sTokenInterceptor implements Interceptor {
	private NumericDate currentExp;
	private String token;
	private static final String tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token";

	public K8sTokenInterceptor() throws Exception {
		refreshToken();
	}

	public Response intercept(Interceptor.Chain chain) throws IOException {
		if (currentExp.isBefore(NumericDate.now())) {
			try {
				refreshToken();
			} catch (Exception e) {
				throw new IOException("Invalid Kubernetes Service Account token", e);
			}
		}

		Request originalRequest = chain.request();
		Request requestWithUserAgent = originalRequest
				.newBuilder()
				.header("Authorization", "Bearer " + token)
				.build();
		return chain.proceed(requestWithUserAgent);
	}

	public void refreshToken() throws Exception {
		String tokenContents = Files.readString(Path.of(tokenPath));
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
