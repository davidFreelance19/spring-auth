package com.authentication.app.domain.services;

import jakarta.mail.MessagingException;

public interface IEmailService {
    public void sendEmailVerifyAccount(String email, String token) throws MessagingException;

    public void sendEmailRecupereAccount(String email, String token) throws MessagingException;
}
