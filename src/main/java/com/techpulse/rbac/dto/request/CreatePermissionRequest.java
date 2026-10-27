package com.techpulse.rbac.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CreatePermissionRequest {

    @NotBlank(message = "Permission name is required and cannot be blank")
    @Size(min = 2, max = 100, message = "Permission name must be between 2 and 100 characters")
    @Pattern(regexp = "^[A-Za-z0-9_:]+$", message = "Permission name must only contain alphanumeric characters, underscores, and colons")
    private String name;

    @Size(max = 255, message = "Description cannot exceed 255 characters")
    private String description;
}
