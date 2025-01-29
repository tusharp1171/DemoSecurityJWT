package com.example.demosecurityjwt.payload.responce;
import java.time.Instant;

public class ErrorResponse {
    private Instant timestamp;
    private int status;
    private String message;
    private String errorCode;

    public ErrorResponse(int status, String message, String errorCode) {
        this.timestamp = Instant.now();
        this.status = status;
        this.message = message;
        this.errorCode = errorCode;
    }

    // Getters and setters

    public Instant getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }
}