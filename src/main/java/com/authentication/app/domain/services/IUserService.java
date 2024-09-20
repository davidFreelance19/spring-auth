package com.authentication.app.domain.services;

import java.util.Map;

import com.authentication.app.domain.entities.UserEntity;

public interface IUserService {
    public Map<String, UserEntity> welcome();
}
