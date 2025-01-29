package com.example.demosecurityjwt.exception;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.example.demosecurityjwt.payload.responce.ErrorResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import jakarta.servlet.http.HttpServletRequest;

@RestControllerAdvice
public class GlobalExceptionHandler {

	@ExceptionHandler(CustomException.class)
	public ResponseEntity<ErrorResponse> handleCustomException(CustomException e) {
		ErrorResponse errorResponse = new ErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(), e.getMessage(),
				"INTERNAL_ERROR");
		return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
	}

	@ExceptionHandler(UsernameAlreadyTakenException.class)
	public void handleUsernameAlreadyTakenException(UsernameAlreadyTakenException ex, HttpServletRequest request,
			jakarta.servlet.http.HttpServletResponse response) throws java.io.IOException {
		// Log the exception message
		System.err.println(ex.getMessage());

		// Set response content type and status
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setStatus(HttpStatus.BAD_REQUEST.value()); // 400 Bad Request

		// Prepare the error response body
		Map<String, Object> body = new HashMap<>();
		body.put("timestamp", Instant.now());
		body.put("status", HttpStatus.BAD_REQUEST.value());
		body.put("error", HttpStatus.BAD_REQUEST.getReasonPhrase());
		body.put("message", ex.getMessage()); // Custom message from the exception
		body.put("path", request.getRequestURI());

		// Create ObjectMapper and register the JavaTimeModule to handle Java 8
		// date/time types
		ObjectMapper mapper = new ObjectMapper();
		mapper.registerModule(new JavaTimeModule());

		// Write the error details to the response output stream
		mapper.writeValue(response.getOutputStream(), body);
	}

	// Handle generic exceptions
	@ExceptionHandler(Exception.class)
	public void handleGenericException(Exception ex, HttpServletRequest request,
			jakarta.servlet.http.HttpServletResponse response) throws java.io.IOException {
		// Log the exception message
		System.err.println(ex.getMessage());

		// Set response content type and status
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setStatus(HttpStatus.INTERNAL_SERVER_ERROR.value()); // 500 Internal Server Error

		// Prepare the error response body
		Map<String, Object> body = new HashMap<>();
		body.put("timestamp", Instant.now());
		body.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
		body.put("error", HttpStatus.INTERNAL_SERVER_ERROR.getReasonPhrase());
		body.put("message", "An unexpected error occurred."); // General error message
		body.put("path", request.getRequestURI());

		// Create ObjectMapper and register the JavaTimeModule to handle Java 8
		// date/time types
		ObjectMapper mapper = new ObjectMapper();
		mapper.registerModule(new JavaTimeModule());

		// Write the error details to the response output stream
		mapper.writeValue(response.getOutputStream(), body);
	}

	// Handle other custom exceptions (e.g., ResourceNotFoundException,
	// InvalidDataException, etc.)
	@ExceptionHandler({ ResourceNotFoundException.class, InvalidDataException.class })
	public void handleCustomExceptions(Exception ex, HttpServletRequest request,
			jakarta.servlet.http.HttpServletResponse response) throws java.io.IOException {
		// Log the exception message
		System.err.println(ex.getMessage());

		// Set response content type and status
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setStatus(HttpStatus.NOT_FOUND.value()); // 404 Not Found for custom exceptions

		// Prepare the error response body
		Map<String, Object> body = new HashMap<>();
		body.put("timestamp", Instant.now());
		body.put("status", HttpStatus.NOT_FOUND.value());
		body.put("error", HttpStatus.NOT_FOUND.getReasonPhrase());
		body.put("message", ex.getMessage()); // Custom message from the exception
		body.put("path", request.getRequestURI());

		// Create ObjectMapper and register the JavaTimeModule to handle Java 8
		// date/time types
		ObjectMapper mapper = new ObjectMapper();
		mapper.registerModule(new JavaTimeModule());

		// Write the error details to the response output stream
		mapper.writeValue(response.getOutputStream(), body);
	}
}
