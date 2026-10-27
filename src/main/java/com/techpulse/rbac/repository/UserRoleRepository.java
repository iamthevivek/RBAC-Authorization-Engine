package com.techpulse.rbac.repository;

import com.techpulse.rbac.entity.Role;
import com.techpulse.rbac.entity.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

@Repository
public interface UserRoleRepository extends JpaRepository<UserRole, Long> {

    List<UserRole> findByUserId(Long userId);

    Optional<UserRole> findByUserIdAndRoleId(Long userId, Long roleId);

    boolean existsByUserIdAndRoleId(Long userId, Long roleId);

    void deleteByUserIdAndRoleId(Long userId, Long roleId);

    @Query("SELECT ur.role FROM UserRole ur WHERE ur.user.id = :userId")
    List<Role> findRolesByUserId(@Param("userId") Long userId);

    @Query("SELECT DISTINCT p.name FROM UserRole ur " +
            "JOIN RolePermission rp ON ur.role.id = rp.role.id " +
            "JOIN Permission p ON rp.permission.id = p.id " +
            "WHERE ur.user.id = :userId AND ur.user.enabled = true")
    Set<String> findPermissionNamesByUserId(@Param("userId") Long userId);

    @Query("SELECT DISTINCT p.name FROM UserRole ur " +
            "JOIN RolePermission rp ON ur.role.id = rp.role.id " +
            "JOIN Permission p ON rp.permission.id = p.id " +
            "WHERE LOWER(ur.user.username) = LOWER(:username) AND ur.user.enabled = true")
    Set<String> findPermissionNamesByUsername(@Param("username") String username);
}
