package com.example.demooauth2.service;

import com.example.demooauth2.exception.ResourceNotFoundException;
import com.example.demooauth2.model.User;
import com.example.demooauth2.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public User getCurrentUser(Long id) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User", "id", id));
        return user;
    }
}
