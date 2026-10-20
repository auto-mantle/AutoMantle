package com.automantle.api.repository;

import com.automantle.api.entity.ApprovalExpirationReason;
import com.automantle.api.entity.ApprovalRequestEntity;
import com.automantle.api.entity.ApprovalRequestStatus;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface ApprovalRequestRepository extends JpaRepository<ApprovalRequestEntity, UUID> {

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            "UPDATE ApprovalRequestEntity ar SET ar.status = :decision, ar.resolvedBy ="
                + " :resolvedBy, ar.resolvedAt = :now, ar.updatedAt = :now WHERE ar.id = :id AND"
                + " ar.status = com.automantle.api.entity.ApprovalRequestStatus.PENDING")
    int resolvePendingRequest(
            @Param("id") UUID id,
            @Param("decision") ApprovalRequestStatus decision,
            @Param("resolvedBy") UUID resolvedBy,
            @Param("now") Instant now);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            """
            UPDATE ApprovalRequestEntity ar SET
                ar.status = com.automantle.api.entity.ApprovalRequestStatus.EXPIRED,
                ar.expirationReason = :reason, ar.resolvedAt = :now, ar.updatedAt = :now
            WHERE ar.id = :id AND ar.agentProfileId = :profileId
                AND ar.status IN (com.automantle.api.entity.ApprovalRequestStatus.PENDING,
                                  com.automantle.api.entity.ApprovalRequestStatus.APPROVED)
            """)
    int expireUnexecutedRequest(
            @Param("id") UUID id,
            @Param("profileId") UUID profileId,
            @Param("reason") ApprovalExpirationReason reason,
            @Param("now") Instant now);

    List<ApprovalRequestEntity> findAllByOrderByCreatedAtDescIdDesc(Pageable pageable);

    @Query(
            "SELECT ar FROM ApprovalRequestEntity ar WHERE ar.status ="
                    + " com.automantle.api.entity.ApprovalRequestStatus.PENDING"
                    + " AND (:setupOnly = false OR function('json_extract', ar.actionMetadata,"
                    + " '$.type') = 'SETUP') ORDER BY ar.createdAt ASC, ar.id ASC")
    List<ApprovalRequestEntity> findPending(
            @Param("setupOnly") boolean setupOnly, Pageable pageable);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query(
            "UPDATE ApprovalRequestEntity ar SET ar.status ="
                + " com.automantle.api.entity.ApprovalRequestStatus.EXPIRED, ar.updatedAt = :now,"
                + " ar.resolvedAt = :now, ar.expirationReason ="
                + " com.automantle.api.entity.ApprovalExpirationReason.SETUP_SESSION_ENDED WHERE"
                + " ar.status = com.automantle.api.entity.ApprovalRequestStatus.PENDING AND"
                + " function('json_extract', ar.actionMetadata, '$.setupSessionId') = :sessionId")
    int expireSetupSession(@Param("sessionId") String sessionId, @Param("now") Instant now);
}
