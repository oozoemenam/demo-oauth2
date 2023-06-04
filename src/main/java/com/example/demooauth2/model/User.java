package com.example.demooauth2.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.example.demooauth2.enums.AuthProvider;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import lombok.*;

@Entity
@Table(name = "Users")
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String username;

    @JsonIgnore
    private String password;

    private String name;

    @Email
    private String email;

    private String imageUrl;

    @Column(nullable = false)
    private boolean emailVerified = false;

    @NotNull
    @Enumerated(EnumType.STRING)
    private AuthProvider authProvider;

    private String providerId;
}
