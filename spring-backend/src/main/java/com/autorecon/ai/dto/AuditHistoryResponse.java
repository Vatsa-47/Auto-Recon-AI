package com.autorecon.ai.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class AuditHistoryResponse {

    @JsonProperty("evidence_id")
    private String evidenceId;

    @JsonProperty("chain_valid")
    private boolean chainValid;

    @JsonProperty("total_events")
    private int totalEvents;

    private List<AuditLogEntryDto> history;

    public AuditHistoryResponse() {
    }

    public AuditHistoryResponse(String evidenceId, boolean chainValid, int totalEvents, List<AuditLogEntryDto> history) {
        this.evidenceId = evidenceId;
        this.chainValid = chainValid;
        this.totalEvents = totalEvents;
        this.history = history;
    }

    public String getEvidenceId() {
        return evidenceId;
    }

    public void setEvidenceId(String evidenceId) {
        this.evidenceId = evidenceId;
    }

    public boolean isChainValid() {
        return chainValid;
    }

    public void setChainValid(boolean chainValid) {
        this.chainValid = chainValid;
    }

    public int getTotalEvents() {
        return totalEvents;
    }

    public void setTotalEvents(int totalEvents) {
        this.totalEvents = totalEvents;
    }

    public List<AuditLogEntryDto> getHistory() {
        return history;
    }

    public void setHistory(List<AuditLogEntryDto> history) {
        this.history = history;
    }
}
