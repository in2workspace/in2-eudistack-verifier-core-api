package es.in2.vcverifier.architecture;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.library.GeneralCodingRules.*;

class ArchitectureRulesTest {

    private static JavaClasses importedClasses;

    @BeforeAll
    static void setup() {
        importedClasses = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("es.in2.vcverifier");
    }

    // --- Hexagonal architecture rules ---

    @Nested
    @DisplayName("Hexagonal architecture")
    class HexagonalRules {

        @Test
        @DisplayName("Domain must not depend on infrastructure")
        void domainMustNotDependOnInfrastructure() {
            noClasses()
                    .that().resideInAPackage("..domain..")
                    .should().dependOnClassesThat().resideInAPackage("..infrastructure..")
                    .because("Domain layer is the innermost hexagonal ring")
                    .check(importedClasses);
        }

        @Test
        @DisplayName("Domain must not depend on application")
        void domainMustNotDependOnApplication() {
            noClasses()
                    .that().resideInAPackage("..domain..")
                    .should().dependOnClassesThat().resideInAPackage("..application..")
                    .because("Domain is independent of application orchestration")
                    .check(importedClasses);
        }

        @Test
        @DisplayName("Model classes should not depend on controller layer")
        void modelShouldNotDependOnController() {
            noClasses()
                    .that().resideInAPackage("..model..")
                    .should().dependOnClassesThat().resideInAPackage("..controller..")
                    .because("Model classes should be independent of the controller layer")
                    .check(importedClasses);
        }

        @Test
        @DisplayName("Exception classes should not depend on service layer")
        void exceptionsShouldNotDependOnService() {
            noClasses()
                    .that().resideInAPackage("..exception..")
                    .should().dependOnClassesThat().resideInAPackage("..service..")
                    .because("Exceptions should be standalone and not depend on services")
                    .check(importedClasses);
        }
    }

    // --- Naming conventions ---

    @Nested
    @DisplayName("Naming conventions")
    class NamingConventions {

        @Test
        @DisplayName("Service implementations should be in adapter or impl package")
        void serviceImplsShouldBeInAdapterOrImplPackage() {
            classes()
                    .that().haveSimpleNameEndingWith("ServiceImpl")
                    .should().resideInAnyPackage("..adapter..", "..service.impl..", "..crypto..")
                    .because("Service implementations belong in adapter, impl, or crypto packages")
                    .check(importedClasses);
        }

        @Test
        @DisplayName("Classes annotated with @Controller should reside in controller package")
        void controllerClassesShouldBeInControllerPackage() {
            classes()
                    .that().areAnnotatedWith(org.springframework.stereotype.Controller.class)
                    .or().areAnnotatedWith(org.springframework.web.bind.annotation.RestController.class)
                    .should().resideInAPackage("..controller..")
                    .because("Controllers should be in the controller package")
                    .check(importedClasses);
        }

        @Test
        @DisplayName("Classes annotated with @Configuration should reside in config, security, or infrastructure package")
        void configClassesShouldBeInConfigPackage() {
            classes()
                    .that().areAnnotatedWith(org.springframework.context.annotation.Configuration.class)
                    .should().resideInAnyPackage("..config..", "..security..", "..infrastructure..", "..crypto..")
                    .because("Configuration classes should be in config, security, or infrastructure packages")
                    .check(importedClasses);
        }
    }

    // --- Dependency rules ---

    @Nested
    @DisplayName("Dependency rules")
    class DependencyRules {

        @Test
        @DisplayName("No classes should use java.util.logging")
        void noJavaUtilLogging() {
            NO_CLASSES_SHOULD_USE_JAVA_UTIL_LOGGING.check(importedClasses);
        }

        @Test
        @DisplayName("No classes should throw generic exceptions")
        void noGenericExceptions() {
            NO_CLASSES_SHOULD_THROW_GENERIC_EXCEPTIONS.check(importedClasses);
        }

        @Test
        @DisplayName("No classes should access System.out or System.err directly")
        void noStandardStreams() {
            NO_CLASSES_SHOULD_ACCESS_STANDARD_STREAMS.check(importedClasses);
        }

        @Test
        @DisplayName("Util classes should not depend on service layer")
        void utilShouldNotDependOnService() {
            noClasses()
                    .that().resideInAPackage("..util..")
                    .should().dependOnClassesThat().resideInAPackage("..service..")
                    .because("Utility classes should not depend on the service layer")
                    .check(importedClasses);
        }

        @Test
        @DisplayName("Util classes should not depend on controller layer")
        void utilShouldNotDependOnController() {
            noClasses()
                    .that().resideInAPackage("..util..")
                    .should().dependOnClassesThat().resideInAPackage("..controller..")
                    .because("Utility classes should not depend on the controller layer")
                    .check(importedClasses);
        }
    }
}
