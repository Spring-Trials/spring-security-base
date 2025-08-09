package com.example.spring_security.dtos.requestDTOs;

public record RegisterRequest (
    String username,
    String email,
    String password,
    String role // Optional, can be null or empty if not provided
){}
