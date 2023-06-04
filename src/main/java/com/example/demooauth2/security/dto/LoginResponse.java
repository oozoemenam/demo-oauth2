package com.example.demooauth2.security.dto;

import lombok.*;

@Data
@NoArgsConstructor
@RequiredArgsConstructor
@AllArgsConstructor
public class LoginResponse {
    @NonNull
    private String accessToken;

    private String tokenType = "Bearer";
}
