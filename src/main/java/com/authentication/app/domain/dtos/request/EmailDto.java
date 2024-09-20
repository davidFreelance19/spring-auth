package com.authentication.app.domain.dtos.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class EmailDto {
    @NotNull(message = "{NotNull.user.email}") 
    @NotBlank(message = "{Blank.user.email}") 
    @Email(message = "{InvalidEmail.user.email}")
    private String email;
}