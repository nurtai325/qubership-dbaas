package org.qubership.cloud.dbaas.security.filters;

import io.quarkus.runtime.Shutdown;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import jakarta.ws.rs.core.HttpHeaders;
import lombok.extern.slf4j.Slf4j;
import org.qubership.cloud.dbaas.security.K8sTokenWatcher;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

@Slf4j
public class K8sTokenAuthFilter implements ClientRequestFilter {
    private final AtomicReference<String> token = new AtomicReference<>();
    private final Thread watcherThread;

    public K8sTokenAuthFilter() {watcherThread=null;}

    public K8sTokenAuthFilter(String tokenDir, String tokenLocation) {
        token.set("");

        watcherThread = Thread.startVirtualThread(new K8sTokenWatcher(tokenDir, tokenLocation, token));
    }

    @Override
    public void filter(ClientRequestContext clientRequestContext) throws IOException {
        clientRequestContext.getHeaders().add(HttpHeaders.AUTHORIZATION, "Bearer " + token.get());
    }

    @Shutdown
    void shutdown() {
        if (watcherThread != null) {
            watcherThread.interrupt();
        }
    }
}
