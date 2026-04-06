package com.shieldclaw.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private static final String COOKIE_NAME = "jwt";
    private static final int MAX_AGE_SECONDS = 8 * 60 * 60; // 8 hours

    private final String adminUsername;
    private final String adminPassword;
    private final JwtService jwtService;

    public AuthController(
            JwtService jwtService,
            @Value("${SHIELDCLAW_ADMIN_USERNAME}") String adminUsername,
            @Value("${SHIELDCLAW_ADMIN_PASSWORD}") String adminPassword) {
        this.jwtService = jwtService;
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(
            @RequestBody LoginRequest request,
            HttpServletResponse response) {
        if (adminUsername.equals(request.username())
                && adminPassword.equals(request.password())) {
            String token = jwtService.generateToken(request.username());

            Cookie cookie = new Cookie(COOKIE_NAME, token);
            cookie.setHttpOnly(true);
            cookie.setSecure(false); // set to true in production
            cookie.setPath("/");
            cookie.setMaxAge(MAX_AGE_SECONDS);
            response.addCookie(cookie);

            return ResponseEntity.ok(Map.of("message", "Authenticated"));
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid credentials"));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletResponse response) {
        Cookie cookie = new Cookie(COOKIE_NAME, "");
        cookie.setHttpOnly(true);
        cookie.setSecure(false);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);

        return ResponseEntity.ok(Map.of("message", "Logged out"));
    }

    @GetMapping("/me")
    public ResponseEntity<?> me() {
        return ResponseEntity.ok(Map.of("message", "Authenticated"));
    }
}
