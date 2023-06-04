package com.example.demooauth2.security.controller;

import com.example.demooauth2.dto.ApiResponse;
import com.example.demooauth2.enums.AuthProvider;
import com.example.demooauth2.exception.BadRequestException;
import com.example.demooauth2.model.User;
import com.example.demooauth2.repository.UserRepository;
import com.example.demooauth2.security.dto.LoginRequest;
import com.example.demooauth2.security.dto.LoginResponse;
import com.example.demooauth2.security.dto.RegisterRequest;
import com.example.demooauth2.security.util.JwtUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtUtils.createToken(authentication);
//        return ResponseEntity.ok(new JwtResponse(jwt));
        return new ResponseEntity<>(new LoginResponse(token), HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest registerRequest) {
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new BadRequestException("Username already in use");
        }
//        if (userRepository.existsByEmail(registerRequest.getEmail())) {
//            throw new BadRequestException("Email already in use");
//        }
        User user = new User();
        user.setUsername(registerRequest.getUsername());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
//        user.setEmail(registerRequest.getEmail());
        user.setAuthProvider(AuthProvider.local);
        User savedUser =  userRepository.save(user);
        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath()
                .path("/user/me")
                .buildAndExpand(savedUser.getId())
                .toUri();
        return ResponseEntity
                .created(location)
                .body(new ApiResponse(true, "User registered successfully"));
    }
}
