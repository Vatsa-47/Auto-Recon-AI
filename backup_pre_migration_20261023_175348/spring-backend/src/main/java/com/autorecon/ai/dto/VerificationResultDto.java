package com.autorecon.ai.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class VerificationResultDto {

    @JsonProperty("evidence_id")
    private String evidenceId;

    private String filename;

    @JsonProperty("current_sha256")
    private String currentSha256;

    @JsonProperty("trusted_reference")
    private String trustedReference;

    private String status;

    private boolean match;

    private String message;

    private String timestamp;

    public VerificationResultDto() {
    }

    public VerificationResultDto(String evidenceId, String filename, String currentSha256,
                                 String trustedReference, String status, boolean match,
                                 String message, String timestamp) {
        this.evidenceId = evidenceId;
        this.filename = filename;
        this.currentSha256 = currentSha256;
        this.trustedReference = trustedReference;
        this.status = status;
        this.match = match;
        this.message = message;
        this.timestamp = timestamp;
    }

    public String getEvidenceId() {
        return evidenceId;
    }

    public void setEvidenceId(String evidenceId) {
        this.evidenceId = evidenceId;
    }

    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public String getCurrentSha256() {
        return currentSha256;
    }

    public void setCurrentSha256(String currentSha256) {
        this.currentSha256 = currentSha256;
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

    public boolean isMatch() {
        return match;
    }

    public void setMatch(boolean match) {
        this.match = match;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }
}
