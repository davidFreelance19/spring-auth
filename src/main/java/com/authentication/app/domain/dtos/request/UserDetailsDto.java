package com.authentication.app.domain.dtos.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserDetailsDto {
    @NotNull(message = "{NotNull.user.name}")
    @NotBlank(message = "{Blank.user.name}")
    @Size(min = 2, max = 50, message = "{Length.user.name}")
    @Pattern(regexp = "^[A-Z].*$", message = "{InitCapitalLetter.user.name}")
    @Pattern(regexp = "^[a-zA-ZÀ-ÿ]+$", message = "{OnlyLetters.user.name}")
    @Pattern(regexp = "^\\S+$", message = "{NotSpacesBlank.user.name}")
    private String name;

    @NotNull(message = "{NotNull.user.lastname}")
    @NotBlank(message = "{Blank.user.lastname}")
    @Size(min = 2, max = 50, message = "{Length.user.lastname}")
    @Pattern(regexp = "^[A-Z].*$", message = "{InitCapitalLetter.user.lastname}")
    @Pattern(regexp = "^[a-zA-ZÀ-ÿ]+$", message = "{OnlyLetters.user.lastname}")
    @Pattern(regexp = "^\\S+$", message = "{NotSpacesBlank.user.lastname}")
    private String lastname;
}
