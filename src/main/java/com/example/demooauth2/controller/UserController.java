package com.example.demooauth2.controller;

import com.example.demooauth2.model.User;
import com.example.demooauth2.security.model.CurrentUser;
import com.example.demooauth2.security.model.UserPrincipal;
import com.example.demooauth2.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {
    private final UserService userService;

    @GetMapping("/me")
    @PreAuthorize("hasRole('USER')")
    public User getCurrentUser(@CurrentUser UserPrincipal userPrincipal) {
        return userService.getCurrentUser(userPrincipal.getId());
    }

//    @GetMapping("/users")
//    public List<User> getUsers() {
//        return userService.getUsers();
//    }
//
//    @PostMapping("/users")
//    public User createUser(@RequestBody User user) {
//        return userService.createUser(user);
//    }
//
//    @GetMapping("/users/{id}")
//    public User getUser(@PathVariable Long id) {
//        return userService.getUser(id);
//    }
//
//    @PutMapping("/users/{id}")
//    public User updateUser(@PathVariable Long id, @RequestBody User user) {
//        return userService.updateUser(id, user);
//    }
//
//    @DeleteMapping("/users/{id}")
//    public void deleteUser(@PathVariable Long id) {
//        userService.deleteUser(id);
//    }
//
//    @GetMapping("/users/search")
//    public List<User> searchUsers(@RequestParam String name) {
//        return userService.searchUsers(name);
//    }
}
