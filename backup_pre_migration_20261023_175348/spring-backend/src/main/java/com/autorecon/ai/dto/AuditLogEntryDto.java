package com.autorecon.ai.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AuditLogEntryDto {

    private Long id;

    @JsonProperty("event_id")
    private String eventId;

    @JsonProperty("evidence_id")
    private String evidenceId;

    @JsonProperty("event_type")
    private String eventType;

    private String timestamp;

    @JsonProperty("actor_id")
    private String actorId;

    private String details;

    @JsonProperty("verification_result")
    private String verificationResult;

    @JsonProperty("previous_hash")
    private String previousHash;

    @JsonProperty("record_hash")
    private String recordHash;

    public AuditLogEntryDto() {
    }

    public AuditLogEntryDto(Long id, String eventId, String evidenceId, String eventType,
                            String timestamp, String actorId, String details,
                            String verificationResult, String previousHash, String recordHash) {
        this.id = id;
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

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
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
}
