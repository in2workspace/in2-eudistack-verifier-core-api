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
import static com.tngtech.archunit.library.Architectures.layeredArchitecture;
import static com.tngtech.archunit.library.GeneralCodingRules.*;

class ArchitectureRulesTest {

    private static JavaClasses importedClasses;

    @BeforeAll
    static void setup() {
        importedClasses = new ClassFileImporter()
                .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
                .importPackages("es.in2.vcverifier");
    }

    // --- Layer rules ---

    @Nested
    @DisplayName("Layer separation")
    class LayerRules {

        @Test
        @DisplayName("Layered architecture: controller -> service -> (config|model|exception|util)")
        void layeredArchitectureIsRespected() {
            layeredArchitecture()
                    .consideringOnlyDependenciesInLayers()
                    .layer("Controller").definedBy("..controller..")
                    .layer("Security").definedBy("..security..")
                    .layer("Service").definedBy("..service..")
                    .layer("Config").definedBy("..config..", "..component..")
                    .layer("Model").definedBy("..model..")
                    .layer("Exception").definedBy("..exception..")
                    .layer("Util").definedBy("..util..")

                    .whereLayer("Controller").mayNotBeAccessedByAnyLayer()
                    .whereLayer("Model").mayOnlyBeAccessedByLayers(
                            "Controller", "Service", "Security", "Config", "Exception")
                    .whereLayer("Exception").mayOnlyBeAccessedByLayers(
                            "Controller", "Service", "Security", "Config")
                    .whereLayer("Util").mayOnlyBeAccessedByLayers(
                            "Controller", "Service", "Security", "Config")

                    .check(importedClasses);
        }

        @Test
        @DisplayName("Controllers should not depend on service implementations directly")
        void controllersShouldNotDependOnServiceImpl() {
            noClasses()
                    .that().resideInAPackage("..controller..")
                    .should().dependOnClassesThat().resideInAPackage("..service.impl..")
                    .because("Controllers should depend on service interfaces, not implementations")
                    .check(importedClasses);
        }

        @Test
        @DisplayName("Model classes should not depend on service layer")
        void modelShouldNotDependOnService() {
            noClasses()
                    .that().resideInAPackage("..model..")
                    .should().dependOnClassesThat().resideInAPackage("..service..")
                    .because("Model classes should be independent of the service layer")
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
        @DisplayName("Service implementations should be in ..service.impl.. package")
        void serviceImplsShouldBeInImplPackage() {
            classes()
                    .that().haveSimpleNameEndingWith("ServiceImpl")
                    .should().resideInAPackage("..service.impl..")
                    .because("Service implementations belong in the impl subpackage")
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
        @DisplayName("Classes annotated with @Configuration should reside in config, security, or component package")
        void configClassesShouldBeInConfigPackage() {
            classes()
                    .that().areAnnotatedWith(org.springframework.context.annotation.Configuration.class)
                    .should().resideInAnyPackage("..config..", "..security..", "..component..")
                    .because("Configuration classes should be in config, security, or component packages")
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
