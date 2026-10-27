package com.techpulse.rbac.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Objects;

@Entity
@Table(name = "role_permissions", uniqueConstraints = {
        @UniqueConstraint(name = "uk_role_permissions_role_perm", columnNames = {"role_id", "permission_id"})
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RolePermission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "permission_id", nullable = false)
    private Permission permission;

    public RolePermission(Role role, Permission permission) {
        this.role = role;
        this.permission = permission;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RolePermission that = (RolePermission) o;
        return Objects.equals(role != null ? role.getId() : null, that.role != null ? that.role.getId() : null) &&
                Objects.equals(permission != null ? permission.getId() : null, that.permission != null ? that.permission.getId() : null);
    }

    @Override
    public int hashCode() {
        return Objects.hash(role != null ? role.getId() : null, permission != null ? permission.getId() : null);
    }
}
