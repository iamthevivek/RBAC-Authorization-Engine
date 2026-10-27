package com.techpulse.rbac.dto.response;

import lombok.*;

import java.time.LocalDateTime;
import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecureDataResponse {

    private String message;
    private String accessedBy;
    private String requiredPermission;
    @Builder.Default
    private LocalDateTime timestamp = LocalDateTime.now();
    private Map<String, Object> payload;
}
