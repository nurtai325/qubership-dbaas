package org.qubership.cloud.dbaas.security;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class OidcConfig {
	@JsonProperty("jwks_uri")
	public String jwks_uri;

	public OidcConfig(String jwks_uri) {
		this.jwks_uri = jwks_uri;
	}

	public OidcConfig() {
	}
}
