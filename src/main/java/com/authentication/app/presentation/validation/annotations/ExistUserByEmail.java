package com.authentication.app.presentation.validation.annotations;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.authentication.app.presentation.validation.validator.ExistsUserByEmailValidator;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

@Target(ElementType.FIELD)
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = ExistsUserByEmailValidator.class)
public @interface ExistUserByEmail {
    
    String message() default "User with this email already exists";

	Class<?>[] groups() default { };

	Class<? extends Payload>[] payload() default { };
}
