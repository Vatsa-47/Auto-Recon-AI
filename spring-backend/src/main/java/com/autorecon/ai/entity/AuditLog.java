package com.autorecon.ai.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_log", indexes = {
    @Index(name = "idx_audit_event", columnList = "event_id"),
    @Index(name = "idx_audit_evidence", columnList = "evidence_id"),
    @Index(name = "idx_audit_timestamp", columnList = "timestamp"),
    @Index(name = "idx_audit_evidence_time", columnList = "evidence_id, timestamp")
})
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "event_id", length = 64, nullable = false, unique = true)
    private String eventId;

    @Column(name = "evidence_id", length = 64, nullable = false)
    private String evidenceId;

    @Column(name = "event_type", length = 64, nullable = false)
    private String eventType;

    @Column(name = "timestamp", nullable = false)
    private Instant timestamp;

    @Column(name = "actor_id", length = 128, nullable = false)
    private String actorId;

    @Column(name = "details", columnDefinition = "TEXT")
    private String details;

    @Column(name = "verification_result", length = 32)
    private String verificationResult;

    @Column(name = "previous_hash", length = 64, nullable = false)
    private String previousHash;

    @Column(name = "record_hash", length = 64, nullable = false)
    private String recordHash;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "evidence_id", insertable = false, updatable = false)
    private Evidence evidence;

    public AuditLog() {
    }

    public AuditLog(String eventId, String evidenceId, String eventType, Instant timestamp,
                    String actorId, String details, String verificationResult,
                    String previousHash, String recordHash) {
        this.eventId = eventId;
        this.evidenceId = evidenceId;
        this.eventType = eventType;
        this.timestamp = timestamp;
        this.actorId = actorId;
        this.details = details;
        this.verificationResult = verificationResult;
        this.previousHash = previousHash;
        this.recordHash = recordHash;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEventId() {
        return eventId;
    }

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }

    public String getEvidenceId() {
        return evidenceId;
    }

    public void setEvidenceId(String evidenceId) {
        this.evidenceId = evidenceId;
    }

    public String getEventType() {
        return eventType;
    }

    public void setEventType(String eventType) {
        this.eventType = eventType;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public String getActorId() {
        return actorId;
    }

    public void setActorId(String actorId) {
        this.actorId = actorId;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public String getVerificationResult() {
        return verificationResult;
    }

    public void setVerificationResult(String verificationResult) {
        this.verificationResult = verificationResult;
    }

    public String getPreviousHash() {
        return previousHash;
    }

    public void setPreviousHash(String previousHash) {
        this.previousHash = previousHash;
    }

    public String getRecordHash() {
        return recordHash;
    }

    public void setRecordHash(String recordHash) {
        this.recordHash = recordHash;
    }

    public Evidence getEvidence() {
        return evidence;
    }

    public void setEvidence(Evidence evidence) {
        this.evidence = evidence;
    }
}
