package com.techpulse.rbac;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThatNoException;

@SpringBootTest
class RbacAuthorizationEngineApplicationTest {

    @Test
    @DisplayName("Application context loads successfully")
    void contextLoads() {
        // Verifies Spring context initializes cleanly
    }

    @Test
    @DisplayName("Main method can be invoked without exception")
    void mainMethod() {
        assertThatNoException().isThrownBy(() ->
                RbacAuthorizationEngineApplication.main(new String[]{"--spring.main.banner-mode=off"})
        );
    }
}
