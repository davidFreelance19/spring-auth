package com.authentication.app.domain.services;

import java.util.Map;

import com.authentication.app.domain.dtos.request.CodeOtpDto;
import com.authentication.app.domain.dtos.request.LoginDto;
import com.authentication.app.domain.dtos.request.RegisterUserDto;
import com.authentication.app.domain.entities.UserEntity;
import com.authentication.app.presentation.validation.exceptions.custom.UserNotEnableException;

import jakarta.mail.MessagingException;

public interface IAuthService {
    public Map<String, UserEntity> registerUser(RegisterUserDto dto) throws MessagingException;

    public Map<String, String> login(LoginDto dto) throws UserNotEnableException;

    public Map<String, String> verifyAccount(String token, CodeOtpDto dto);

    public Map<String, String> sendNewCodeByVerifyAccount(String token)throws MessagingException;

    public Map<String, String> recupereAccount(String email) throws MessagingException, UserNotEnableException;

    public Map<String, String> changePassword(String token, String newPassword);
}
