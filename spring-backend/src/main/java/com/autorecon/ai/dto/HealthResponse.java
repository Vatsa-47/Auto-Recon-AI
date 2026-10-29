package com.autorecon.ai.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class HealthResponse {

    private String status;

    private String backend;

    @JsonProperty("storage_accessible")
    private boolean storageAccessible;

    @JsonProperty("db_accessible")
    private boolean dbAccessible;

    @JsonProperty("db_type")
    private String dbType;

    @JsonProperty("db_host")
    private String dbHost;

    @JsonProperty("db_error")
    private String dbError;

    private String timestamp;

    public HealthResponse() {
    }

    public HealthResponse(String status, String backend, boolean storageAccessible,
                          boolean dbAccessible, String dbType, String dbHost,
                          String dbError, String timestamp) {
        this.status = status;
        this.backend = backend;
        this.storageAccessible = storageAccessible;
        this.dbAccessible = dbAccessible;
        this.dbType = dbType;
        this.dbHost = dbHost;
        this.dbError = dbError;
        this.timestamp = timestamp;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getBackend() {
        return backend;
    }

    public void setBackend(String backend) {
        this.backend = backend;
    }

    public boolean isStorageAccessible() {
        return storageAccessible;
    }

    public void setStorageAccessible(boolean storageAccessible) {
        this.storageAccessible = storageAccessible;
    }

    public boolean isDbAccessible() {
        return dbAccessible;
    }

    public void setDbAccessible(boolean dbAccessible) {
        this.dbAccessible = dbAccessible;
    }

    public String getDbType() {
        return dbType;
    }

    public void setDbType(String dbType) {
        this.dbType = dbType;
    }

    public String getDbHost() {
        return dbHost;
    }

    public void setDbHost(String dbHost) {
        this.dbHost = dbHost;
    }

    public String getDbError() {
        return dbError;
    }

    public void setDbError(String dbError) {
        this.dbError = dbError;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }
}
