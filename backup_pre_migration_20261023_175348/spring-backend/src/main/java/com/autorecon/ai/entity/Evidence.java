package com.autorecon.ai.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "evidence", indexes = {
    @Index(name = "idx_evidence_case", columnList = "case_id"),
    @Index(name = "idx_evidence_sha256", columnList = "sha256"),
    @Index(name = "idx_evidence_uploaded", columnList = "uploaded_at")
})
public class Evidence {

    @Id
    @Column(name = "id", length = 64, nullable = false)
    private String id;

    @Column(name = "case_id", length = 64, nullable = false)
    private String caseId;

    @Column(name = "filename", length = 255, nullable = false)
    private String filename;

    @Column(name = "storage_filename", length = 255, nullable = false, unique = true)
    private String storageFilename;

    @Column(name = "file_size", nullable = false)
    private Long fileSize;

    @Column(name = "mime_type", length = 128)
    private String mimeType;

    @Column(name = "evidence_type", length = 64)
    private String evidenceType;

    @Column(name = "sha256", length = 64, nullable = false)
    private String sha256;

    @Column(name = "trusted_reference", length = 64)
    private String trustedReference;

    @Column(name = "status", length = 32, nullable = false)
    private String status;

    @Column(name = "investigator_id", length = 128)
    private String investigatorId;

    @Column(name = "uploaded_at", nullable = false)
    private Instant uploadedAt;

    @Column(name = "last_verified_at")
    private Instant lastVerifiedAt;

    @OneToMany(mappedBy = "evidence", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @OrderBy("id ASC")
    private List<AuditLog> auditEvents = new ArrayList<>();

    public Evidence() {
    }

    public Evidence(String id, String caseId, String filename, String storageFilename, Long fileSize,
                    String mimeType, String evidenceType, String sha256, String trustedReference,
                    String status, String investigatorId, Instant uploadedAt, Instant lastVerifiedAt) {
        this.id = id;
        this.caseId = caseId;
        this.filename = filename;
        this.storageFilename = storageFilename;
        this.fileSize = fileSize;
        this.mimeType = mimeType;
        this.evidenceType = evidenceType;
        this.sha256 = sha256;
        this.trustedReference = trustedReference;
        this.status = status;
        this.investigatorId = investigatorId;
        this.uploadedAt = uploadedAt;
        this.lastVerifiedAt = lastVerifiedAt;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getCaseId() {
        return caseId;
    }

    public void setCaseId(String caseId) {
        this.caseId = caseId;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public String getStorageFilename() {
        return storageFilename;
    }

    public void setStorageFilename(String storageFilename) {
        this.storageFilename = storageFilename;
    }

    public Long getFileSize() {
        return fileSize;
    }

    public void setFileSize(Long fileSize) {
        this.fileSize = fileSize;
    }

    public String getMimeType() {
        return mimeType;
    }

    public void setMimeType(String mimeType) {
        this.mimeType = mimeType;
    }

    public String getEvidenceType() {
        return evidenceType;
    }

    public void setEvidenceType(String evidenceType) {
        this.evidenceType = evidenceType;
    }

    public String getSha256() {
        return sha256;
    }

    public void setSha256(String sha256) {
        this.sha256 = sha256;
    }

    public String getTrustedReference() {
        return trustedReference;
    }

    public void setTrustedReference(String trustedReference) {
        this.trustedReference = trustedReference;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getInvestigatorId() {
        return investigatorId;
    }

    public void setInvestigatorId(String investigatorId) {
        this.investigatorId = investigatorId;
    }

    public Instant getUploadedAt() {
        return uploadedAt;
    }

    public void setUploadedAt(Instant uploadedAt) {
        this.uploadedAt = uploadedAt;
    }

    public Instant getLastVerifiedAt() {
        return lastVerifiedAt;
    }

    public void setLastVerifiedAt(Instant lastVerifiedAt) {
        this.lastVerifiedAt = lastVerifiedAt;
    }

    public List<AuditLog> getAuditEvents() {
        return auditEvents;
    }

    public void setAuditEvents(List<AuditLog> auditEvents) {
        this.auditEvents = auditEvents;
    }
}
