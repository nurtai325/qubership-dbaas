package org.qubership.cloud.dbaas.utils;

import jakarta.json.JsonObject;
import jakarta.json.JsonString;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.util.Map;

public class JwtUtils {
    public static String getServiceAccountName(JsonWebToken token) {
        Map<String, Object> kubernetesClaims = token.getClaim("kubernetes.io");
        JsonObject serviceAccount = (JsonObject) kubernetesClaims.get("serviceaccount");
        JsonString serviceAccountName = (JsonString) serviceAccount.get("name");
        return serviceAccountName.getString();
    }

    public static String getNamespace(JsonWebToken token) {
        Map<String, Object> kubernetesClaims = token.getClaim("kubernetes.io");
        JsonString namespaceFromJwt = (JsonString) kubernetesClaims.get("namespace");
        return namespaceFromJwt.getString();
    }
}
