package com.techpulse.rbac;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThatNoException;

@SpringBootTest
class RbacAuthorizationEngineApplicationTest {

    @Test
    void contextLoads() {
    }

    @Test
    void mainMethod() {
        assertThatNoException().isThrownBy(() ->
                RbacAuthorizationEngineApplication.main(new String[]{"--spring.main.banner-mode=off"})
        );
    }
}
