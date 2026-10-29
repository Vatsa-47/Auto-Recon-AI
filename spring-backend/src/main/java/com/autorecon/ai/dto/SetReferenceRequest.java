package com.autorecon.ai.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public class SetReferenceRequest {

    @NotBlank(message = "Reference hash cannot be blank")
    @Pattern(regexp = "^[a-fA-F0-9]{64}$", message = "Reference hash must be a valid 64-character hexadecimal SHA-256 string")
    @JsonProperty("reference_hash")
    private String referenceHash;

    @JsonProperty("actor_id")
    private String actorId = "Forensic_Investigator";

    public SetReferenceRequest() {
    }

    public SetReferenceRequest(String referenceHash, String actorId) {
        this.referenceHash = referenceHash;
        if (actorId != null && !actorId.trim().isEmpty()) {
            this.actorId = actorId;
        }
    }

    public String getReferenceHash() {
        return referenceHash;
    }

    public void setReferenceHash(String referenceHash) {
        this.referenceHash = referenceHash;
    }

    public String getActorId() {
        return actorId;
    }

    public void setActorId(String actorId) {
        this.actorId = actorId;
    }
}
