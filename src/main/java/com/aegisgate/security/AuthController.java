package com.aegisgate.security;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private static final String HARDCODED_USERNAME = "auditor";
    private static final String HARDCODED_PASSWORD = "secure2026";

    private final JwtService jwtService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        if (HARDCODED_USERNAME.equals(request.username())
                && HARDCODED_PASSWORD.equals(request.password())) {
            String token = jwtService.generateToken(request.username());
            return ResponseEntity.ok(new TokenResponse(token));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(java.util.Map.of("error", "Invalid credentials"));
    }
}
