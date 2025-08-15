package org.qubership.cloud.dbaas.security.interceptors;

import io.quarkus.runtime.Shutdown;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.HttpHeaders;
import lombok.extern.slf4j.Slf4j;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jetbrains.annotations.NotNull;
import org.qubership.cloud.dbaas.security.K8sTokenWatcher;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
public class K8sTokenInterceptor implements Interceptor {
    private final AtomicReference<String> token = new AtomicReference<>();
    private Thread watcherThread;

    @Inject
    @ConfigProperty(name = "dbaas.security.k8s.jwt.enabled")
    private boolean isJwtEnabled;

    @Inject
    @ConfigProperty(name = "dbaas.security.k8s.jwt.token.service-account.path")
    String tokenLocation;

    @Inject
    @ConfigProperty(name = "dbaas.security.k8s.jwt.token.service-account.dir")
    String tokenDir;

    public K8sTokenInterceptor() {
        token.set("");
        if (isJwtEnabled) {
            watcherThread = Thread.startVirtualThread(new K8sTokenWatcher(tokenDir, tokenLocation, token));
        }
    }

    public @NotNull Response intercept(Interceptor.Chain chain) throws IOException {
        Request requestWithUserAgent = chain.request()
                .newBuilder()
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token.get())
                .build();

        return chain.proceed(requestWithUserAgent);
    }

    @Shutdown
    void shutdown() {
        if (watcherThread != null) {
            watcherThread.interrupt();
        }
    }
}
