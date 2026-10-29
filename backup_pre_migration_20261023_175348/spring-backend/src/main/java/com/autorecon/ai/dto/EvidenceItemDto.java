package com.autorecon.ai.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

public class EvidenceItemDto {

    private String id;

    @JsonProperty("case_id")
    private String caseId;

    private String filename;

    @JsonProperty("file_size")
    private Long fileSize;

    @JsonProperty("mime_type")
    private String mimeType;

    @JsonProperty("evidence_type")
    private String evidenceType;

    private String sha256;

    @JsonProperty("trusted_reference")
    private String trustedReference;

    private String status;

    @JsonProperty("investigator_id")
    private String investigatorId;

    @JsonProperty("uploaded_at")
    private String uploadedAt;

    @JsonProperty("last_verified_at")
    private String lastVerifiedAt;

    public EvidenceItemDto() {
    }

    public EvidenceItemDto(String id, String caseId, String filename, Long fileSize,
                           String mimeType, String evidenceType, String sha256,
                           String trustedReference, String status, String investigatorId,
                           String uploadedAt, String lastVerifiedAt) {
        this.id = id;
        this.caseId = caseId;
        this.filename = filename;
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

    public String getUploadedAt() {
        return uploadedAt;
    }

    public void setUploadedAt(String uploadedAt) {
        this.uploadedAt = uploadedAt;
    }

    public String getLastVerifiedAt() {
        return lastVerifiedAt;
    }

    public void setLastVerifiedAt(String lastVerifiedAt) {
        this.lastVerifiedAt = lastVerifiedAt;
    }
}
