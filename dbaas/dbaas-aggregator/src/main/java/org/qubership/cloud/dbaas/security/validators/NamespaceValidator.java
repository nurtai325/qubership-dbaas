package org.qubership.cloud.dbaas.security.validators;

import io.smallrye.jwt.auth.principal.DefaultJWTCallerPrincipal;
import jakarta.enterprise.context.RequestScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonString;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.qubership.cloud.dbaas.entity.pg.composite.CompositeStructure;
import org.qubership.cloud.dbaas.service.composite.CompositeNamespaceService;

import java.security.Principal;
import java.util.Map;
import java.util.Optional;

@RequestScoped
@Slf4j
public class NamespaceValidator {
    @Inject
    @ConfigProperty(name = "cloud.microservice.composite.baseline")
    String thisBaseline;

    @Inject
    CompositeNamespaceService compositeNamespaceService;

    @Inject
    SecurityContext securityContext;

    public boolean checkNamespaceIsolation(String namespaceFromPath, String namespaceFromJwt) {
        if(namespaceFromPath.equals(namespaceFromJwt)) {
            return true;
        } else {
            return checkNamespaceInComposite(namespaceFromPath);
        }
    }

    public boolean checkNamespaceFromClassifier(Map<String, Object> classifier) {
        Principal defaultPrincipal = securityContext.getUserPrincipal();

        if(!(defaultPrincipal instanceof DefaultJWTCallerPrincipal principal)) {
            return true;
        }
        String namespaceFromClassifier = (String) classifier.get("namespace");
        if (namespaceFromClassifier == null) {
            return false;
        }

        Map<String, Object> kubernetesClaims = principal.getClaim("kubernetes.io");
        if (kubernetesClaims == null) {
            return false;
        }

        JsonString namespaceFromJwt = (JsonString) kubernetesClaims.get("namespace");
        if (namespaceFromJwt == null) {
            return false;
        }

        return namespaceFromClassifier.equals(namespaceFromJwt.getString()) || checkNamespaceInComposite(namespaceFromClassifier);
    }

    private boolean checkNamespaceInComposite(String namespace) {
        Optional<CompositeStructure> compositeStructureOption = compositeNamespaceService.getCompositeStructure(thisBaseline);

        if(compositeStructureOption.isEmpty()) {
            log.error("Can't get composite structure by baseline %s".formatted(thisBaseline));
            return false;
        }

        CompositeStructure compositeStructure = compositeStructureOption.get();

        return compositeStructure.getNamespaces().contains(namespace);
    }
}
