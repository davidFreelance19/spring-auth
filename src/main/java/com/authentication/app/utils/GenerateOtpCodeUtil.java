package com.authentication.app.utils;

import java.security.SecureRandom;

import org.springframework.stereotype.Component;

@Component
public class GenerateOtpCodeUtil {
    private static final String CHARACTERS = "0123456789";
    private static final int CODE_LENGTH = 5;
    private static final SecureRandom random = new SecureRandom();

    public String generateOtp() {
        StringBuilder otp = new StringBuilder(CODE_LENGTH);
        for (int i = 0; i < CODE_LENGTH; i++) {
            otp.append(CHARACTERS.charAt(random.nextInt(CHARACTERS.length())));
        }
        return otp.toString();
    }
}
