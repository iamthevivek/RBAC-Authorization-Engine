package com.techpulse.rbac.repository;

import com.techpulse.rbac.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Collection;
import java.util.List;
import java.util.Optional;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {

    Optional<Permission> findByName(String name);

    Optional<Permission> findByNameIgnoreCase(String name);

    boolean existsByNameIgnoreCase(String name);

    List<Permission> findByNameIn(Collection<String> names);
}
