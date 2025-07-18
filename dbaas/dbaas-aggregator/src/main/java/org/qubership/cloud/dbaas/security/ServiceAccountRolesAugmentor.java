package org.qubership.cloud.dbaas.security;

import org.qubership.cloud.dbaas.Constants;

import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.SecurityIdentityAugmentor;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class ServiceAccountRolesAugmentor implements SecurityIdentityAugmentor {
	@Override
	public Uni<SecurityIdentity> augment(SecurityIdentity identity, AuthenticationRequestContext context) {
		if (identity.isAnonymous()) {
			return Uni.createFrom().item(identity);
		}
		QuarkusSecurityIdentity.Builder builder = QuarkusSecurityIdentity.builder(identity);
		builder.addRole(Constants.DB_CLIENT);
		return Uni.createFrom().item(builder.build());
	}
}
