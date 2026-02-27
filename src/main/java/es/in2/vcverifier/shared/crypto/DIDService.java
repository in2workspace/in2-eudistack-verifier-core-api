package es.in2.vcverifier.shared.crypto;

import java.security.PublicKey;

public interface DIDService {
    PublicKey getPublicKeyFromDid(String did);
}
