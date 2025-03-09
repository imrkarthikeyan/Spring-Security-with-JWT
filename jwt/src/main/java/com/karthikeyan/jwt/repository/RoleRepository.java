package com.karthikeyan.jwt.repository;

import com.karthikeyan.jwt.model.ERole;
import com.karthikeyan.jwt.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
