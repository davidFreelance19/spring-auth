package com.authentication.app.presentation.validation.validator;

import org.springframework.stereotype.Component;

import com.authentication.app.domain.repositories.CredentialsRepository;
import com.authentication.app.presentation.validation.annotations.ExistUserByEmail;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

@Component
public class ExistsUserByEmailValidator implements ConstraintValidator<ExistUserByEmail, String> {

    private final CredentialsRepository credentialsRepository;

    ExistsUserByEmailValidator(CredentialsRepository credentialsRepository){
        this.credentialsRepository = credentialsRepository;
    }

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        return this.credentialsRepository.findByEmail(value) == null;
    }
    
}
