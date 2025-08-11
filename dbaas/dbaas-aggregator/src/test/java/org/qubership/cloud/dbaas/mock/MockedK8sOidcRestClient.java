package org.qubership.cloud.dbaas.mock;

import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Alternative;
import org.qubership.cloud.dbaas.TestJwtUtils;
import org.qubership.cloud.dbaas.dto.oidc.OidcConfig;
import org.qubership.cloud.dbaas.rest.K8sOidcRestClient;

import java.io.IOException;

@ApplicationScoped
@Alternative
@Priority(1)
public class MockedK8sOidcRestClient extends K8sOidcRestClient {
    private final String jwks;

    public MockedK8sOidcRestClient(TestJwtUtils testJwtUtils) throws IOException {
        super(false, false);

        jwks = testJwtUtils.getJwks();
    }

    @Override
    public OidcConfig getOidcConfiguration(String oidcProviderUrl) throws RuntimeException {
        return new OidcConfig("");
    }

    @Override
    public String getJwks(String jwksEndpoint) {
        return jwks;
    }
}
