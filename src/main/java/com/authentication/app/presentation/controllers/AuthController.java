package com.authentication.app.presentation.controllers;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.authentication.app.domain.dtos.request.CodeOtpDto;
import com.authentication.app.domain.dtos.request.EmailDto;
import com.authentication.app.domain.dtos.request.LoginDto;
import com.authentication.app.domain.dtos.request.PasswordDto;
import com.authentication.app.domain.dtos.request.RegisterUserDto;
import com.authentication.app.domain.entities.UserEntity;
import com.authentication.app.domain.services.IAuthService;
import com.authentication.app.presentation.validation.exceptions.custom.UserNotEnableException;

import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final String MESSAGE_KEY = "message";
    
    private final IAuthService authService;

    AuthController(IAuthService authService){
        this.authService = authService;
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, UserEntity>> registerUser(
        @RequestBody @Valid RegisterUserDto dto
    ) throws MessagingException{
        return new ResponseEntity<>(this.authService.registerUser(dto), HttpStatus.CREATED);
    }
    
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> loginUser(
        @RequestBody @Valid LoginDto dto
    ) throws UserNotEnableException{
        return new ResponseEntity<>(this.authService.login(dto), HttpStatus.OK);
    }

    @GetMapping("/view/verify-account/{token}")
    public ResponseEntity<Map<String, String>> viewVerifyAccount(
        @PathVariable String token
    ){
        return new ResponseEntity<>(Map.of(MESSAGE_KEY, "ok"), HttpStatus.OK);
    }

    @PatchMapping("/verify-account/{token}")
    public ResponseEntity<Map<String, String>> verifyAccount(
        @PathVariable String token,
        @RequestBody @Valid CodeOtpDto dto
    ){
        return new ResponseEntity<>(this.authService.verifyAccount(token, dto), HttpStatus.OK);
    }

    @GetMapping("/new-code/{token}")
    public ResponseEntity<Map<String, String>> newCode(
        @PathVariable String token
    ) throws MessagingException{
        return new ResponseEntity<>(this.authService.sendNewCodeByVerifyAccount(token), HttpStatus.OK);
    }

    @PostMapping("/recupere-account")
    public ResponseEntity<Map<String, String>> recupereAccount(
        @RequestBody @Valid EmailDto dto
    ) throws MessagingException, UserNotEnableException{
        return new ResponseEntity<>(this.authService.recupereAccount(dto.getEmail()), HttpStatus.OK);
    }

    @GetMapping("/view/change-password/{token}")
    public ResponseEntity<Map<String, String>> viewChangePassword(
        @PathVariable String token
    ){
        return new ResponseEntity<>(Map.of(MESSAGE_KEY, "ok"), HttpStatus.OK);
    }

    @GetMapping("/change-password/{token}")
    public ResponseEntity<Map<String, String>> changePasswordFirstStep(
        @PathVariable String token,
        @RequestParam @NotNull(message = "The query param 'code' is required") String code
    ){
        return new ResponseEntity<>(Map.of(MESSAGE_KEY, "ok"), HttpStatus.OK);
    }

    @PatchMapping("/change-password/{token}")
    public ResponseEntity<Map<String, String>> changePassword(
        @PathVariable String token,
        @RequestParam @NotNull(message = "The query param 'code' is required") String code,
        @RequestBody @Valid PasswordDto dto
    ){
        return new ResponseEntity<>(this.authService.changePassword(token, dto.getPassword()), HttpStatus.OK);
    }
}
