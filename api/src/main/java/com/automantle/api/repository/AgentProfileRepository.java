package com.automantle.api.repository;

import com.automantle.api.entity.AgentProfileEntity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface AgentProfileRepository extends JpaRepository<AgentProfileEntity, UUID> {
    boolean existsByName(String name);
}
