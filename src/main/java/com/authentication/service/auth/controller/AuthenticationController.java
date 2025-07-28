package com.authentication.service.auth.controller;

import com.authentication.service.auth.dto.AuthenticationRequest;
import com.authentication.service.auth.dto.AuthenticationResponse;
import com.authentication.service.auth.dto.RegisterRequest;
import com.authentication.service.auth.entity.User;
import com.authentication.service.auth.service.AuthenticationService;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.authentication.service.auth.service.UserService;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @Autowired
    UserService userService;

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody User request) {
        userService.saveUser(request);
        return ResponseEntity.ok("User registered successfully");
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }
}
