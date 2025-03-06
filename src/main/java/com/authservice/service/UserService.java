package com.authservice.service;

import com.authservice.entity.User;
import com.authservice.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public Optional<User> findByUsername(String userId) {
        return userRepository.findByUserId(userId);
    }

    // 추가적인 사용자 등록, 수정, 삭제 로직을 구현할 수 있습니다.
}

