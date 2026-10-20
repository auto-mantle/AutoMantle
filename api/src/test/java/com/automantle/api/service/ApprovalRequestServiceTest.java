package com.automantle.api.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.automantle.api.entity.ApprovalRequestEntity;
import com.automantle.api.entity.ApprovalRequestStatus;
import com.automantle.api.exception.ApprovalConflictException;
import com.automantle.api.exception.ResourceNotFoundException;
import com.automantle.api.policy.HttpPolicyFixtures;
import com.automantle.api.repository.ApprovalRequestRepository;

import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

class ApprovalRequestServiceTest {
    private final ApprovalRequestRepository repository = mock(ApprovalRequestRepository.class);
    private final ApprovalRequestService service =
            new ApprovalRequestService(
                    repository, mock(AgentRuleService.class), mock(AgentProfileService.class),
                    HttpPolicyFixtures.engine(), HttpPolicyFixtures.contract());
    private final UUID id = UUID.randomUUID();
    private final UUID user = UUID.randomUUID();

    private ApprovalRequestEntity request(ApprovalRequestStatus status) {
        var request =
                new ApprovalRequestEntity(
                        UUID.randomUUID(), UUID.randomUUID(), "POST example.com/action", Map.of());
        ReflectionTestUtils.setField(request, "id", id);
        ReflectionTestUtils.setField(request, "createdAt", Instant.now().minusSeconds(172800));
        request.setStatus(status);
        return request;
    }

    @Test
    void oldPendingRequestCanBeResolvedAndReturnsThePersistedResolver() {
        var resolved = request(ApprovalRequestStatus.APPROVED);
        resolved.setResolvedBy(user);
        when(repository.resolvePendingRequest(
                        eq(id), eq(ApprovalRequestStatus.APPROVED), eq(user), any()))
                .thenReturn(1);
        when(repository.findById(id))
                .thenReturn(
                        Optional.of(request(ApprovalRequestStatus.PENDING)), Optional.of(resolved));
        var result = service.resolveRequest(id, ApprovalRequestStatus.APPROVED, user);
        assertEquals(ApprovalRequestStatus.APPROVED, result.status());
        assertEquals(user, result.resolvedBy());
        verify(repository, never()).save(any());
    }

    @Test
    void losingDecisionReportsConflictWithoutOverwritingWinner() {
        var winner = request(ApprovalRequestStatus.REJECTED);
        when(repository.findById(id)).thenReturn(Optional.of(winner));
        assertThrows(
                ApprovalConflictException.class,
                () -> service.resolveRequest(id, ApprovalRequestStatus.APPROVED, user));
        assertEquals(ApprovalRequestStatus.REJECTED, winner.getStatus());
        verify(repository, never()).save(any());
    }

    @Test
    void endedSetupCannotBeResolvedAndMissingRequestReportsNotFound() {
        when(repository.findById(id))
                .thenReturn(Optional.of(request(ApprovalRequestStatus.EXPIRED)));
        assertThrows(
                ApprovalConflictException.class,
                () -> service.resolveRequest(id, ApprovalRequestStatus.APPROVED, user));
        when(repository.findById(id)).thenReturn(Optional.empty());
        assertThrows(
                ResourceNotFoundException.class,
                () -> service.resolveRequest(id, ApprovalRequestStatus.APPROVED, user));
    }

    @Test
    void readingOldPendingRequestDoesNotChangeItsStatus() {
        when(repository.findById(id))
                .thenReturn(Optional.of(request(ApprovalRequestStatus.PENDING)));
        assertEquals(ApprovalRequestStatus.PENDING, service.getRequest(id).status());
        verify(repository).findById(id);
        verifyNoMoreInteractions(repository);
    }

    @Test
    void historyReturnsPendingAndResolvedRequestsWithoutClockBasedChanges() {
        when(repository.findAllByOrderByCreatedAtDescIdDesc(any()))
                .thenReturn(
                        List.of(
                                request(ApprovalRequestStatus.PENDING),
                                request(ApprovalRequestStatus.APPROVED)));
        assertEquals(
                List.of(ApprovalRequestStatus.PENDING, ApprovalRequestStatus.APPROVED),
                service.getRequests().stream().map(response -> response.status()).toList());
        verify(repository).findAllByOrderByCreatedAtDescIdDesc(any());
        verifyNoMoreInteractions(repository);
    }

    @Test
    void invalidDecisionNeverTouchesTheDatabase() {
        assertThrows(
                IllegalArgumentException.class,
                () -> service.resolveRequest(id, ApprovalRequestStatus.PENDING, user));
        verifyNoInteractions(repository);
    }
}
