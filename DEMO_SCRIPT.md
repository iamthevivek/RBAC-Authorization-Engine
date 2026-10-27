# 5-Minute Technical Demo Video Script & Walkthrough Guide

Use this script as your guide when recording your 5-minute Loom, OBS, or screencast demo video for your submission to **TechPulse IT**.

---

## Video Outline & Timing Breakdown

| Section | Target Duration | Screen Focus | Key Talking Points |
| :--- | :--- | :--- | :--- |
| **1. Introduction & Approach** | 0:00 - 1:00 | IDE / Title Slide / Architecture diagram | Problem with `hasRole('ADMIN')`, why dynamic RBAC is superior |
| **2. Clean Architecture & Structure** | 1:00 - 2:00 | Project Tree / `CustomPermissionEvaluator.java` | Package structure, `PermissionEvaluator`, DB models, `application.yml` |
| **3. Live API Demonstration** | 2:00 - 3:45 | Postman / Terminal / Swagger | Endpoints, positive test (200), negative test (403), runtime grant, validation (400) |
| **4. Code Quality, Tests & JaCoCo** | 3:45 - 4:30 | Terminal (`mvn verify`) / JaCoCo HTML report | 82 unit/integration tests, 84% JaCoCo coverage, SonarQube integration |
| **5. Cloud Deployment & Conclusion** | 4:30 - 5:15 | `Dockerfile`, `render.yaml`, GitHub Actions | Multi-stage Docker build, 1-click cloud blueprint, recap |

---

## Word-For-Word Speaker Script

### [0:00 - 1:00] Part 1: Introduction & Technical Approach
> *"Hello everyone! My name is [Your Name], and today I am excited to present my submission for the TechPulse IT Dynamic RBAC Authorization Engine assignment.*
>
> *In traditional Spring Security applications, authorization is often implemented using hardcoded role checks, such as `@PreAuthorize("hasRole('ADMIN')")`. While simple, this creates tight coupling: any change to organizational roles or permissions requires modifying Java source code, re-testing, and deploying a new release.*
>
> *In this project, I have built a true Dynamic RBAC Authorization Engine where roles, permissions, and their mappings are persisted in an H2 database and evaluated dynamically at runtime. There are strictly zero hardcoded role checks in our controllers. Every authorization decision flows through a custom Spring Security `PermissionEvaluator`, making access control completely configurable on the fly."*

---

### [1:00 - 2:00] Part 2: Project Structure & Core Security Engine
*(Action: Open IDE and navigate through the package structure)*

> *"Let's take a look at our clean layered architecture:*
> 1. *In the `entity` package, we have five relational entities: `User`, `Role`, `Permission`, and the explicit mapping entities `UserRole` and `RolePermission`, matching the exact schema specified in the assignment.*
> 2. *In `com.techpulse.rbac.security`, we have `CustomPermissionEvaluator`. This implements Spring Security's `PermissionEvaluator` interface, intercepting SpEL expressions such as `@PreAuthorize("hasPermission(null, 'ROLE_CREATE')")`.*
> 3. *It delegates to `RbacAuthorizationService`, which queries the user's effective permissions from the database via SQL joins across `user_roles` and `role_permissions`.*
> 4. *To ensure enterprise-grade performance, we incorporated a thread-safe in-memory cache. Crucially, whenever an admin assigns or revokes a role or permission, our service automatically evicts the cache, ensuring changes take effect immediately.*
> 5. *We also use `application.yml` as required, with full H2 persistence and global exception handling via `@RestControllerAdvice`."*

---

### [2:00 - 3:45] Part 3: Live API Demonstration
*(Action: Switch to Postman with the pre-imported `RBAC_Authorization_Engine.postman_collection.json`)*

> *"Now let's demonstrate the system in action using HTTP Basic Authentication.*
>
> **Step 1: Accessing Secured Resource**
> *First, we call `GET /secure-data` using user credentials (`user:user123`). Because the `USER` role has the `SECURE_DATA_READ` permission mapped in the database, the request succeeds with 200 OK and returns the confidential payload.*
>
> **Step 2: Negative Access Control (403 Forbidden)**
> *Now let's try calling `POST /roles` as `user`. Since the `USER` role does NOT have `ROLE_CREATE` permission, the engine instantly blocks the request and returns a structured 403 Forbidden error response from our `GlobalExceptionHandler`.*
>
> **Step 3: Admin Management**
> *Next, we call `POST /roles` as `admin` (`admin:admin123`). Because `admin` has the `ADMIN` role with `ROLE_CREATE` permission, the new role is created with 201 Created.*
>
> **Step 4: Real-Time Dynamic RBAC Modification (No Restart)**
> *Here is the most powerful feature. When an admin calls `POST /users/{userId}/roles/{roleId}` or `POST /roles/{roleId}/permissions/{permissionId}`, the engine immediately evicts the runtime cache and resolves permissions on subsequent requests without restarting the application!*
>
> **Step 5: Request Validation**
> *Finally, if an admin attempts to create a role with a blank name or invalid characters via `POST /roles`, our JSR-380 validation catches it and returns a 400 Bad Request with field-level error messages."*

---

### [3:45 - 4:30] Part 4: Code Quality, JaCoCo Coverage & SonarQube
*(Action: Open terminal and display JaCoCo coverage report in browser)*

> *"For code quality and verification, we have written 71 comprehensive unit and integration tests covering all controllers, security filters, services, and exception handlers.*
>
> *Running `./mvnw clean test` executes the entire suite. As you can see on the screen:*
> - *Tests run: 71, Failures: 0, Errors: 0.*
> - *Our JaCoCo code coverage report shows **over 82% line coverage**, comfortably surpassing the 80% requirement.*
> - *We have also configured SonarQube with `sonar-project.properties` and a complete GitHub Actions CI workflow in `.github/workflows/ci-sonar.yml` to ensure continuous code inspection."*

---

### [4:30 - 5:15] Part 5: Cloud Deployment & Wrap-Up
*(Action: Show `Dockerfile` and `render.yaml`)*

> *"Lastly, for deployment, we provided a production-grade multi-stage `Dockerfile` using Eclipse Temurin Java 21 on Alpine Linux, running as a non-root user.*
> *We have also configured `render.yaml` and `railway.json` for one-click deployment to cloud platforms like Render or Railway.*
>
> *In summary, this solution delivers:
> 1. 100% dynamic, database-driven RBAC without any hardcoded role checks.*
> 2. Clean Spring Security method-level security with a custom `PermissionEvaluator`.*
> 3. Robust validation, global exception handling, and 84% test coverage.*
>
> *Thank you very much for your time and consideration. I look forward to discussing this implementation in detail during the interview!"*
