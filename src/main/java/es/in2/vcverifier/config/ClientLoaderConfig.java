package es.in2.vcverifier.config;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.model.ClientData;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
public class ClientLoaderConfig {

    private final ObjectMapper objectMapper;



    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        List<RegisteredClient> clients = loadClients(); // Cargar los clientes
        return new InMemoryRegisteredClientRepository(clients); // Pasar los clientes al repositorio
    }

    private List<RegisteredClient> loadClients() {
        try {
            // Leer el archivo JSON
            InputStream inputStream = getClass().getClassLoader().getResourceAsStream("clients.json");
            List<ClientData> clientsData = objectMapper.readValue(inputStream, new TypeReference<>() {
            });

            List<RegisteredClient> registeredClients = new ArrayList<>();

            // Convertir cada ClientData a RegisteredClient y agregarlo a la lista
            for (ClientData clientData : clientsData) {
                RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId(clientData.getClientId())
                        .clientAuthenticationMethods(authMethods -> clientData.getClientAuthenticationMethods().forEach(method ->
                                authMethods.add(new ClientAuthenticationMethod(method))))
                        .authorizationGrantTypes(grantTypes -> clientData.getAuthorizationGrantTypes().forEach(grantType ->
                                grantTypes.add(new AuthorizationGrantType(grantType))))
                        .redirectUris(uris -> uris.addAll(clientData.getRedirectUris()))
                        .postLogoutRedirectUris(uris -> uris.addAll(clientData.getPostLogoutRedirectUris()))
                        .scopes(scopes -> scopes.addAll(clientData.getScopes()))
                        .clientSettings(ClientSettings.builder()
                                .requireAuthorizationConsent(clientData.isRequireAuthorizationConsent())
                                .build())
                        .build();

                registeredClients.add(registeredClient);
            }
            return registeredClients;
        } catch (Exception e) {
            throw new RuntimeException("Error loading clients from JSON", e);
        }
    }
}


