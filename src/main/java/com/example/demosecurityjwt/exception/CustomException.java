package com.example.demosecurityjwt.exception;

import org.springframework.http.HttpStatus;

public class CustomException extends RuntimeException {
	 private final HttpStatus status;
	    private final String message;

	    public CustomException(String message) {
	        super(message);
	        this.status = HttpStatus.BAD_REQUEST; // Default status
	        this.message = message;
	    }

	    public CustomException(String message, HttpStatus status) {
	        super(message);
	        this.status = status;
	        this.message = message;
	    }

	    public HttpStatus getStatus() {
	        return status;
	    }

	    public String getMessage() {
	        return message;
	    }	
}