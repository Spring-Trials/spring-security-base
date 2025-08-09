package com.example.spring_security.dtos.requestDTOs;

public record AuthRequest (
        String username,
        String password
) {}
