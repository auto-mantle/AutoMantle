package com.automantle.api.repository;

import com.automantle.api.entity.RequestHistoryEntity;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RequestHistoryRepository extends JpaRepository<RequestHistoryEntity, Long> {
    Optional<RequestHistoryEntity> findByRequestId(UUID requestId);

    @Query(
            "select h from RequestHistoryEntity h where (:before is null or h.id < :before) "
                    + "and (:profile is null or h.agentProfileId = :profile) order by h.id desc")
    List<RequestHistoryEntity> recent(
            @Param("before") Long before, @Param("profile") UUID profile, Pageable page);

    @Modifying
    @Query("delete from RequestHistoryEntity h where h.createdAt < :cutoff")
    int deleteExpired(@Param("cutoff") Instant cutoff);

    @Modifying
    @Query("delete from RequestHistoryEntity h where h.id <= :cutoff")
    int deleteThrough(@Param("cutoff") Long cutoff);
}
