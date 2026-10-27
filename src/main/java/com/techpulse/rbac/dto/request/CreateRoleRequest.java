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
public class CreateRoleRequest {

    @NotBlank(message = "Role name is required and cannot be blank")
    @Size(min = 2, max = 50, message = "Role name must be between 2 and 50 characters")
    @Pattern(regexp = "^[A-Za-z0-9_]+$", message = "Role name must only contain alphanumeric characters and underscores")
    private String name;

    @Size(max = 255, message = "Description cannot exceed 255 characters")
    private String description;
}
