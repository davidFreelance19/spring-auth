package com.authentication.app.domain.dtos.request;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PasswordDto{
    @NotNull
    @NotBlank
    @Size(min = 6, max = 20, message = "La contraseña debe tener entre 6 y 20 caracteres")
    @Pattern(
        regexp = "^(?=.*[A-Z])(?=.*\\d).+$", 
        message = "La contraseña debe contener al menos una letra mayúscula y un número"
    )
    private String password;
}