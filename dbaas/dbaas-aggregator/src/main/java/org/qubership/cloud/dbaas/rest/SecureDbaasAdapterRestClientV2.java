package org.qubership.cloud.dbaas.rest;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import org.qubership.cloud.dbaas.dto.*;
import org.qubership.cloud.dbaas.dto.v3.CreatedDatabaseV3;
import org.qubership.cloud.dbaas.dto.v3.GetOrCreateUserAdapterRequest;
import org.qubership.cloud.dbaas.dto.v3.UserEnsureRequestV3;
import org.qubership.cloud.dbaas.entity.pg.DbResource;
import org.qubership.cloud.dbaas.entity.pg.backup.TrackedAction;
import org.qubership.cloud.dbaas.monitoring.AdapterHealthStatus;
import org.qubership.cloud.dbaas.security.filters.AuthFilterSelector;
import org.qubership.cloud.dbaas.security.filters.BasicAuthFilter;
import org.qubership.cloud.dbaas.security.filters.K8sTokenAuthFilter;
import org.qubership.cloud.dbaas.service.VarArgsFunction;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

public class SecureDbaasAdapterRestClientV2 implements DbaasAdapterRestClientV2 {
    private final BasicAuthFilter basicAuthFilter;
    private final K8sTokenAuthFilter k8sTokenAuthFilter;

    private final DbaasAdapterRestClientV2 restClient;
    private final AuthFilterSelector authFilterSelector;

    private final AtomicReference<Instant> lastK8sAuthSetTime;

    public SecureDbaasAdapterRestClientV2(DbaasAdapterRestClientV2 restClient, BasicAuthFilter basicAuthFilter, K8sTokenAuthFilter k8sTokenAuthFilter, AuthFilterSelector authFilterSelector) {
        this.restClient = restClient;
        this.basicAuthFilter = basicAuthFilter;
        this.k8sTokenAuthFilter = k8sTokenAuthFilter;
        this.authFilterSelector = authFilterSelector;
        this.lastK8sAuthSetTime = new AtomicReference<>(Instant.now());
    }

    private <R> R executeRequest(VarArgsFunction<R> func, Object... args) {
        try {
            if (authFilterSelector.getAuthFilter() instanceof BasicAuthFilter && Duration.between(lastK8sAuthSetTime.get(), Instant.now()).toMinutes() >= 60) {
                authFilterSelector.selectAuthFilter(k8sTokenAuthFilter);
                lastK8sAuthSetTime.set(Instant.now());
            }

            return func.apply(args);
        } catch (WebApplicationException e) {
            if (e.getResponse().getStatus() == Response.Status.UNAUTHORIZED.getStatusCode() && authFilterSelector.getAuthFilter() instanceof K8sTokenAuthFilter) {
                authFilterSelector.selectAuthFilter(basicAuthFilter);
                return func.apply(args);
            }
            throw e;
        }
    }

    @Override
    public AdapterHealthStatus getHealth() {
        return executeRequest(args -> restClient.getHealth());
    }

    @Override
    public Response handshake(String type) {
        return executeRequest(args -> restClient.handshake((String) args[0]), type);
    }

    @Override
    public Map<String, Boolean> supports(String type) {
        return executeRequest(args -> restClient.supports((String) args[0]), type);
    }

    @Override
    public TrackedAction restoreBackup(String type, String backupId,
                                       RestoreRequest restoreRequest) {
        return executeRequest(args -> restClient.restoreBackup((String) args[0], (String) args[1], (RestoreRequest) args[2]),
                type, backupId, restoreRequest);
    }

    @Override
    public TrackedAction restoreBackup(String type, String backupId,
                                       boolean regenerateNames,
                                       List<String> databases) {
        return executeRequest(args -> restClient.restoreBackup((String) args[0], (String) args[1], (Boolean) args[2], (List<String>) args[3]),
                type, backupId, regenerateNames, databases);
    }

    @Override
    public TrackedAction collectBackup(String type,
                                       Boolean allowEviction,
                                       String keep,
                                       List<String> databases) {
        return executeRequest(args -> restClient.collectBackup((String) args[0], (Boolean) args[1], (String) args[2], (List<String>) args[3]),
                type, allowEviction, keep, databases);
    }

    @Override
    public TrackedAction trackBackup(String type, String action, String track) {
        return executeRequest(args -> restClient.trackBackup((String) args[0], (String) args[1], (String) args[2]),
                type, action, track);
    }

    @Override
    public String deleteBackup(String type, String backupId) {
        return executeRequest(args -> restClient.deleteBackup((String) args[0], (String) args[1]),
                type, backupId);
    }

    @Override
    public Response dropResources(String type, List<DbResource> resources) {
        return executeRequest(args -> restClient.dropResources((String) args[0], (List<DbResource>) args[1]),
                type, resources);
    }

    @Override
    public EnsuredUser ensureUser(String type, String username,
                                  UserEnsureRequest request) {
        return executeRequest(args -> restClient.ensureUser((String) args[0], (String) args[1], (UserEnsureRequest) args[2]),
                type, username, request);
    }

    @Override
    public EnsuredUser ensureUser(String type, String username,
                                  UserEnsureRequestV3 request) {
        return executeRequest(args -> restClient.ensureUser((String) args[0], (String) args[1], (UserEnsureRequestV3) args[2]),
                type, username, request);
    }

    @Override
    public EnsuredUser ensureUser(String type,
                                  UserEnsureRequestV3 request) {
        return executeRequest(args -> restClient.ensureUser((String) args[0], (UserEnsureRequestV3) args[1]),
                type, request);
    }

    @Override
    public EnsuredUser createUser(String type,
                                  GetOrCreateUserAdapterRequest request) {
        return executeRequest(args -> restClient.createUser((String) args[0], (GetOrCreateUserAdapterRequest) args[1]),
                type, request);
    }

    @Override
    public Response restorePassword(String type,
                                    RestorePasswordsAdapterRequest request) {
        return executeRequest(args -> restClient.restorePassword((String) args[0], (RestorePasswordsAdapterRequest) args[1]),
                type, request);
    }

    @Override
    public void changeMetaData(String type, String dbName,
                               Map<String, Object> metadata) {
        executeRequest(args -> {
            restClient.changeMetaData((String) args[0], (String) args[1], (Map<String, Object>) args[2]);
            return null;
        }, type, dbName, metadata);
    }

    @Override
    public Map<String, DescribedDatabase> describeDatabases(String type,
                                                            boolean connectionProperties,
                                                            boolean resources,
                                                            Collection<String> databases) {
        return executeRequest(args -> restClient.describeDatabases((String) args[0], (Boolean) args[1], (Boolean) args[2], (Collection<String>) args[3]),
                type, connectionProperties, resources, databases);
    }

    @Override
    public Set<String> getDatabases(String type) {
        return executeRequest(args -> restClient.getDatabases((String) args[0]), type);
    }

    @Override
    public CreatedDatabaseV3 createDatabase(String type,
                                            AdapterDatabaseCreateRequest createRequest) {
        return executeRequest(args -> restClient.createDatabase((String) args[0], (AdapterDatabaseCreateRequest) args[1]),
                type, createRequest);
    }

    @Override
    public String updateSettings(String type, String dbName,
                                 UpdateSettingsAdapterRequest request) {
        return executeRequest(args -> restClient.updateSettings((String) args[0], (String) args[1], (UpdateSettingsAdapterRequest) args[2]),
                type, dbName, request);
    }

    @Override
    public void close() throws Exception {
        restClient.close();
    }
}
