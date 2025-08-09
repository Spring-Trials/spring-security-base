package com.example.spring_security.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Map;


@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        String errorMessage;
        if (authException.getCause() instanceof ExpiredJwtException) {
            errorMessage = "JWT token expired";
        } else if (authException.getCause() instanceof BadCredentialsException) {
            errorMessage = "Invalid credentials";
        } else if (authException.getCause() instanceof JwtException) {
            errorMessage = "Invalid JWT token";
        } else {
            errorMessage = "Authentication failed";
        }
        new ObjectMapper().writeValue(response.getWriter(), Map.of(
                "status", HttpServletResponse.SC_UNAUTHORIZED,
                "error", "Unauthorized",
                "message", errorMessage,
                "path", request.getRequestURI()
        ));
    }

}
