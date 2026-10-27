package com.techpulse.rbac.dto.response;

import com.techpulse.rbac.entity.Permission;
import com.techpulse.rbac.entity.Role;
import lombok.*;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RoleResponse {

    private Long id;
    private String name;
    @Builder.Default
    private Set<PermissionResponse> permissions = new HashSet<>();

    public static RoleResponse fromEntity(Role role, Collection<Permission> permissions) {
        if (role == null) return null;
        Set<PermissionResponse> permissionResponses = permissions == null ? new HashSet<>() :
                permissions.stream()
                        .map(PermissionResponse::fromEntity)
                        .collect(Collectors.toSet());

        return RoleResponse.builder()
                .id(role.getId())
                .name(role.getName())
                .permissions(permissionResponses)
                .build();
    }
}
