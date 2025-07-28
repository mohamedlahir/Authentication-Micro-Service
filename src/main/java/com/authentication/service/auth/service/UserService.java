package com.authentication.service.auth.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import com.authentication.service.auth.entity.User;
import com.authentication.service.auth.repository.UserRepository;
@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

public User saveUser(User user) {
    user.setPassword(passwordEncoder().encode(user.getPassword()));
    return userRepository.save(user);
}

}
