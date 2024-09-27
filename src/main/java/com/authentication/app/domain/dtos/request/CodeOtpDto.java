package com.authentication.app.domain.dtos.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CodeOtpDto {
    @NotNull(message = "{NotNull.user.codeOtp}") 
    @NotBlank(message = "{Blank.user.codeOtp}") 
    private String code;
}
