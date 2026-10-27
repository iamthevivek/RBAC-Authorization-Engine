package com.techpulse.rbac.dto.response;

import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthResponse {

    private String token;
    @Builder.Default
    private String tokenType = "Bearer";
    private String username;
    @Builder.Default
    private Set<String> roles = new HashSet<>();
    @Builder.Default
    private Set<String> permissions = new HashSet<>();
    private long expiresInMs;
}
