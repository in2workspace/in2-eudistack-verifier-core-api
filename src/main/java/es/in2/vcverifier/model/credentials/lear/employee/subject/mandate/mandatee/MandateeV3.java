package es.in2.vcverifier.model.credentials.lear.employee.subject.mandate.mandatee;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public record MandateeV3(
        @JsonProperty("id") String id,
        @JsonProperty("employeeId") String employeeId,
        @JsonProperty("email") String email,
        @JsonProperty("firstName") String firstName,
        @JsonProperty("lastName") String lastName
//        // FIXME: Those fields are here to avoid some components failure due the incompatibility for Lear V3
//        @JsonProperty("first_name") String firstNameV1,
//        @JsonProperty("last_name") String lastNameV1
) {}

