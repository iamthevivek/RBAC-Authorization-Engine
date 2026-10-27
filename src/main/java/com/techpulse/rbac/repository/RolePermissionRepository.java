package com.techpulse.rbac.repository;

import com.techpulse.rbac.entity.Permission;
import com.techpulse.rbac.entity.RolePermission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface RolePermissionRepository extends JpaRepository<RolePermission, Long> {

    List<RolePermission> findByRoleId(Long roleId);

    Optional<RolePermission> findByRoleIdAndPermissionId(Long roleId, Long permissionId);

    boolean existsByRoleIdAndPermissionId(Long roleId, Long permissionId);

    void deleteByRoleIdAndPermissionId(Long roleId, Long permissionId);

    void deleteByRoleId(Long roleId);

    void deleteByPermissionId(Long permissionId);

    @Query("SELECT rp.permission FROM RolePermission rp WHERE rp.role.id = :roleId")
    List<Permission> findPermissionsByRoleId(@Param("roleId") Long roleId);

    @Query("SELECT DISTINCT rp.permission FROM RolePermission rp WHERE rp.role.id IN :roleIds")
    List<Permission> findPermissionsByRoleIds(@Param("roleIds") Collection<Long> roleIds);
}
