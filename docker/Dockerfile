# Stage 1
FROM docker.io/gradle:8.4.0 AS temp_build
ARG SKIP_TESTS=false
WORKDIR /home/gradle/src
# Copy the project files
COPY build.gradle settings.gradle /home/gradle/src/
COPY src /home/gradle/src/src
COPY gradle /home/gradle/src/gradle
COPY checkstyle /home/gradle/src/checkstyle
# Build the project
RUN if [ "$SKIP_TESTS" = "true" ]; then \
    gradle build --no-daemon -x test; \
  else \
    gradle build --no-daemon; \
  fi

# Stage 2
FROM bellsoft/liberica-openjdk-alpine-musl:17
RUN addgroup -S nonroot \
    && adduser -S nonroot -G nonroot
USER nonroot
WORKDIR /app
COPY --from=temp_build /home/gradle/src/build/libs/*.jar /app/vc-verifier.jar
ENTRYPOINT ["java", "-jar", "/app/vc-verifier.jar"]