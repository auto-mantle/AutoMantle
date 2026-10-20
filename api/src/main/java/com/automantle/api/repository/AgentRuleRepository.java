package com.automantle.api.repository;

import com.automantle.api.entity.AgentRuleEntity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface AgentRuleRepository extends JpaRepository<AgentRuleEntity, UUID> {

    List<AgentRuleEntity> findByAgentProfileId(UUID agentProfileId);
}
