package com.example.demosecurityjwt.security.jwt;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class AuthEntryPointJwt implements AuthenticationEntryPoint {

    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJwt.class);

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {

        // Logging the authentication error
        logger.error("Unauthorized error: {}", authException.getMessage());

        // Set the response content type and status
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        // Prepare the response body with structured error information
        Map<String, Object> body = new HashMap<>();
        
        body.put("timestamp", Instant.now());  // Current timestamp of the error
        body.put("status", HttpStatus.UNAUTHORIZED.value());  // HTTP Status code (401)
        body.put("error", HttpStatus.UNAUTHORIZED.getReasonPhrase());  // HTTP Status phrase (Unauthorized)
        body.put("message", "Full authentication is required to access this resource");  // Detailed error message
        body.put("path", request.getRequestURI());  // URI that triggered the error

        // Create ObjectMapper and register the JavaTimeModule to handle Java 8 date/time types
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule()); // Register the JavaTimeModule

        // Write the response body as JSON
        mapper.writeValue(response.getOutputStream(), body);
    }

    // General exception handler for custom exceptions
    public void handleCustomException(HttpServletRequest request, HttpServletResponse response, Exception exception)
            throws IOException {
        
        logger.error("Error occurred: {}", exception.getMessage());

        // Set the response content type and status for custom exception
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_BAD_REQUEST);

        // Prepare the response body for custom exception
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", Instant.now());  // Timestamp of the error
        body.put("status", HttpStatus.BAD_REQUEST.value());  // Status code for bad request (400)
        body.put("error", HttpStatus.BAD_REQUEST.getReasonPhrase());  // Error phrase (Bad Request)
        body.put("message", exception.getMessage());  // Exception message
        body.put("path", request.getRequestURI());  // URI that triggered the error

        // Create ObjectMapper and register the JavaTimeModule to handle Java 8 date/time types
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        mapper.writeValue(response.getOutputStream(), body);
    }
}
