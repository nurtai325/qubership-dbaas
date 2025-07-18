package org.qubership.cloud.dbaas.rest;

import javax.net.ssl.*;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.qubership.cloud.dbaas.security.OidcConfig;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import okhttp3.OkHttpClient;
import okhttp3.OkHttpClient.Builder;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.Call;
import okhttp3.tls.Certificates;
import okhttp3.tls.HandshakeCertificates;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;

@ApplicationScoped
public class K8sOidcRestClient {
	@Inject
	@ConfigProperty(name = "dbaas.security.jwt.jwks.use-certificate")
	Boolean useCertificate;

	@Inject
	@ConfigProperty(name = "dbaas.security.jwt.jwks.use-token")
	Boolean useToken;

	private OkHttpClient client;

	private static final String caCertPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

	public K8sOidcRestClient() throws Exception {
		Builder builder = new OkHttpClient.Builder();

		if (useCertificate) {
			setSslSocketFactory(builder);
		}

		if (useToken) {
			builder.addInterceptor(new K8sTokenInterceptor());
		}

		client = builder.build();
	}

	public OidcConfig getOidcConfiguration(String oidcProviderUrl) throws Exception {
		Request request = new Request.Builder()
				.url(oidcProviderUrl + "/.well-known/openid-configuration")
				.build();

		Call call = client.newCall(request);
		Response response = call.execute();

		ObjectMapper objectMapper = new ObjectMapper();
		OidcConfig oidcConfiguration = objectMapper.readValue(response.body().string(), OidcConfig.class);

		return oidcConfiguration;
	}

	public String getJwks(String jwksEndpoint) throws Exception {
		Request request = new Request.Builder()
				.url(jwksEndpoint)
				.build();

		Call call = client.newCall(request);
		Response response = call.execute();

		return response.body().string();
	}

	private void setSslSocketFactory(Builder builder) throws Exception {
		X509Certificate caCert = Certificates.decodeCertificatePem(Files.readString(Path.of(caCertPath)));

		HandshakeCertificates certificates = new HandshakeCertificates.Builder()
				.addTrustedCertificate(caCert)
				.build();

		builder.sslSocketFactory(certificates.sslSocketFactory(), (X509TrustManager) certificates.trustManager());
	}
}
