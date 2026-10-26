package com.rikkei.identity.controller;

import com.rikkei.identity.dto.LoginRequest;
import com.rikkei.identity.dto.RegisterRequest;
import com.rikkei.identity.dto.TokenResponseDTO;
import com.rikkei.identity.dto.UserResponse;
import com.rikkei.identity.service.AuthenticationService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationService authenticationService;

    public AuthController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    /**
     * Registers a new user account.
     *
     * @param request the registration payload
     * @return 201 Created with the new user's info
     */
    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegisterRequest request) {
        UserResponse response = authenticationService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Authenticates a user and returns access + refresh tokens.
     *
     * @param request the login payload
     * @return 200 OK with TokenResponseDTO containing both tokens
     */
    @PostMapping("/login")
    public ResponseEntity<TokenResponseDTO> login(@Valid @RequestBody LoginRequest request) {
        TokenResponseDTO response = authenticationService.login(request);
        return ResponseEntity.ok(response);
    }
}
