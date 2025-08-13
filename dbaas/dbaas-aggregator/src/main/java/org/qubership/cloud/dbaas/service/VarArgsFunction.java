package org.qubership.cloud.dbaas.service;

public interface VarArgsFunction<R> {
    R apply(Object... args);
}
