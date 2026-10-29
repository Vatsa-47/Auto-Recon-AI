package com.autorecon.ai.exception;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ErrorResponse {

    @JsonProperty("detail")
    private Object detail;

    public ErrorResponse() {
    }

    public ErrorResponse(Object detail) {
        this.detail = detail;
    }

    public Object getDetail() {
        return detail;
    }

    public void setDetail(Object detail) {
        this.detail = detail;
    }
}
