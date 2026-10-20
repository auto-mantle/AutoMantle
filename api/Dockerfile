FROM eclipse-temurin:25-jdk AS build
WORKDIR /build/api
COPY api/.mvn/ .mvn/
COPY api/mvnw api/pom.xml ./
RUN chmod +x mvnw
COPY api/src/ src/
RUN --mount=type=cache,target=/root/.m2 ./mvnw -B clean package -DskipTests

FROM eclipse-temurin:25-jre
RUN groupadd --system automantle \
    && useradd --system --gid automantle --no-create-home automantle
WORKDIR /app
COPY --from=build /build/api/target/api-0.0.1-SNAPSHOT.jar app.jar
USER automantle
EXPOSE 8082
ENTRYPOINT ["java", "--enable-native-access=ALL-UNNAMED", "-jar", "app.jar"]
