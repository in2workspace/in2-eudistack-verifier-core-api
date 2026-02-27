package es.in2.vcverifier.shared.config;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.HashSet;

@Getter
@Component
@RequiredArgsConstructor
public class JtiTokenCache {

    private final HashSet<String> jtiTokenHashSet;

    public void addJti(String jti) {
        jtiTokenHashSet.add(jti);
    }

    public boolean isJtiPresent(String jti) {
        return jtiTokenHashSet.contains(jti);
    }

}
