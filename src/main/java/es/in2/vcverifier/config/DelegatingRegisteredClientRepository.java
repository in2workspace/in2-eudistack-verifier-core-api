package es.in2.vcverifier.config;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import java.util.concurrent.atomic.AtomicReference;

@RequiredArgsConstructor
public class DelegatingRegisteredClientRepository implements RegisteredClientRepository {

    private final AtomicReference<RegisteredClientRepository> delegate;

    @Override
    public void save(RegisteredClient registeredClient) {
        delegate.get().save(registeredClient);
    }

    @Override
    public RegisteredClient findById(String id) {
        return delegate.get().findById(id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return delegate.get().findByClientId(clientId);
    }
}
