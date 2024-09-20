package com.authentication.app.presentation.controllers;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.authentication.app.domain.entities.UserEntity;
import com.authentication.app.domain.services.IUserService;

@RestController
@RequestMapping("/api/app")
public class UserController {
    
    private final IUserService userService;

    UserController(IUserService userService){
        this.userService = userService;
    }

    @GetMapping("/welcome")
    public ResponseEntity<Map<String, UserEntity>> welcome(){
        return new ResponseEntity<>(this.userService.welcome(), HttpStatus.OK);
    }
}
