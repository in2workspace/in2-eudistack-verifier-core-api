package es.in2.vcverifier;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableConfigurationProperties
@ConfigurationPropertiesScan
@EnableScheduling
public class VCVerifierApplication {

    private static final ObjectMapper OBJECT_MAPPER =
            JsonMapper.builder()
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
                    .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
                    .serializationInclusion(JsonInclude.Include.NON_NULL)
                    .build();
    public static void main(String[] args) {
        SpringApplication.run(VCVerifierApplication.class, args);
    }

    @Bean
    public ObjectMapper objectMapper() {
        return OBJECT_MAPPER;
    }
}
