package com.techpulse.rbac.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.Objects;

@Entity
@Table(name = "user_roles", uniqueConstraints = {
        @UniqueConstraint(name = "uk_user_roles_user_role", columnNames = {"user_id", "role_id"})
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserRole {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;

    public UserRole(User user, Role role) {
        this.user = user;
        this.role = role;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserRole userRole = (UserRole) o;
        return Objects.equals(user != null ? user.getId() : null, userRole.user != null ? userRole.user.getId() : null) &&
                Objects.equals(role != null ? role.getId() : null, userRole.role != null ? userRole.role.getId() : null);
    }

    @Override
    public int hashCode() {
        return Objects.hash(user != null ? user.getId() : null, role != null ? role.getId() : null);
    }
}
