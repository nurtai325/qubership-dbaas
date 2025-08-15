package org.qubership.cloud.dbaas.exceptions;

import org.qubership.cloud.core.error.runtime.ErrorCodeException;

public class InvalidTenantIdException extends ErrorCodeException {
    public InvalidTenantIdException() {
        super(ErrorCodes.CORE_DBAAS_4046, ErrorCodes.CORE_DBAAS_4046.getDetail());
    }
}
