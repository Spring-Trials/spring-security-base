package com.example.spring_security.controllers;

import com.example.spring_security.dtos.requestDTOs.AuthRequest;
import com.example.spring_security.dtos.requestDTOs.RegisterRequest;
import com.example.spring_security.dtos.responseDTOs.AuthResponse;
import com.example.spring_security.entities.User;
import com.example.spring_security.enums.Roles;
import com.example.spring_security.repository.UserRepository;
import com.example.spring_security.services.CustomUserDetailsService;
import com.example.spring_security.utilities.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final CustomUserDetailsService userDetailsService;


    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            return ResponseEntity.badRequest().body("Username already taken!");
        }
        if (userRepository.existsByEmail(request.email())) {
            return ResponseEntity.badRequest().body("Email already in use!");
        }

        var user = new User();
        user.setUsername(request.username());
        user.setEmail(request.email());
        user.setPassword(passwordEncoder.encode(request.password()));

        if (request.role() != null && !request.role().isEmpty()) {
            try {
                user.setRole(Roles.valueOf(request.role().toUpperCase()));
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().body("Invalid role specified!");
            }
        }

        try {
            userRepository.save(user);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error registering user: " + e.getMessage());
        }

        return ResponseEntity.ok("User registered successfully!");
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest request) {
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );

        final UserDetails user = userDetailsService.loadUserByUsername(request.username());
        final String jwt = jwtUtil.generateToken(user);

        return ResponseEntity.ok(new AuthResponse(jwt));
    }
}
