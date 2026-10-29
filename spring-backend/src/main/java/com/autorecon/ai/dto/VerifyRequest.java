package com.autorecon.ai.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class VerifyRequest {

    @JsonProperty("actor_id")
    private String actorId = "Forensic_Investigator";

    public VerifyRequest() {
    }

    public VerifyRequest(String actorId) {
        if (actorId != null && !actorId.trim().isEmpty()) {
            this.actorId = actorId;
        }
    }

    public String getActorId() {
        return actorId;
    }

    public void setActorId(String actorId) {
        this.actorId = actorId;
    }
}
