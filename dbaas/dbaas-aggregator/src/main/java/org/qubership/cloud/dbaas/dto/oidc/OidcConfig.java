package org.qubership.cloud.dbaas.dto.oidc;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class OidcConfig {
	@JsonProperty("jwks_uri")
	private String jwks_uri;

    public String getJwks_uri() {
        return jwks_uri;
    }

    public void setJwks_uri(String jwks_uri) {
        this.jwks_uri = jwks_uri;
    }

    public OidcConfig(String jwks_uri) {
		this.jwks_uri = jwks_uri;
	}

	public OidcConfig() {
	}
}
