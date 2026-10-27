# ==============================================================================
# Multi-stage Dockerfile for Dynamic RBAC Authorization Engine
# ==============================================================================

# Stage 1: Build & Package
FROM maven:3.9.9-eclipse-temurin-21-alpine AS builder
WORKDIR /build

# Cache dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source and build jar
COPY src ./src
RUN mvn clean package -DskipTests -B

# Stage 2: Minimal Production JRE Runtime
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Create non-root application user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy compiled executable JAR
COPY --from=builder /build/target/rbac-authorization-engine-1.0.0.jar app.jar

# Ensure directory for file-based H2 database exists and is writable
RUN mkdir -p /app/data && chown -R appuser:appgroup /app

USER appuser

EXPOSE 8080

ENV PORT=8080 \
    JAVA_OPTS="-Xms256m -Xmx512m -XX:+UseG1GC -XX:+ExitOnOutOfMemoryError"

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Dserver.port=${PORT:-8080} -jar app.jar"]
