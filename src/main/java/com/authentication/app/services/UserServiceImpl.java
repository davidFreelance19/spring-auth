package com.authentication.app.services;

import java.util.Map;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.authentication.app.domain.entities.UserEntity;
import com.authentication.app.domain.repositories.CredentialsRepository;
import com.authentication.app.domain.services.IUserService;

@Service
public class UserServiceImpl implements IUserService {

    private final CredentialsRepository credentialsRepository;

    UserServiceImpl(CredentialsRepository credentialsRepository){
        this.credentialsRepository = credentialsRepository;
    }

    @Override
    public Map<String, UserEntity> welcome() {
        String email = SecurityContextHolder.getContext().getAuthentication().getPrincipal().toString();
        UserEntity userAuthenticated = credentialsRepository.findByEmail(email).getUser();
        return Map.of("user", userAuthenticated);
    }
    
}
