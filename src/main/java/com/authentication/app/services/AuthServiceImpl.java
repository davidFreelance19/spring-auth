package com.authentication.app.services;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.authentication.app.domain.dtos.request.LoginDto;
import com.authentication.app.domain.dtos.request.RegisterUserDto;
import com.authentication.app.domain.entities.CredentialEntity;
import com.authentication.app.domain.entities.UserEntity;
import com.authentication.app.domain.repositories.CredentialsRepository;
import com.authentication.app.domain.repositories.UserRepository;
import com.authentication.app.domain.services.IAuthService;
import com.authentication.app.domain.services.IEmailService;
import com.authentication.app.presentation.validation.exceptions.custom.UserNotEnableException;
import com.authentication.app.utils.JwtUtil;

import jakarta.mail.MessagingException;
import jakarta.persistence.NoResultException;

@Service
public class AuthServiceImpl implements IAuthService, UserDetailsService{
    
    private static final String MESSAGE = "message";

    private final CredentialsRepository credentialRepository;
    private final UserRepository userRepository;
    private final IEmailService emailService;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    AuthServiceImpl(
        CredentialsRepository credentialRepository, 
        UserRepository userRepository, 
        IEmailService emailService,
        JwtUtil jwtUtil, 
        PasswordEncoder passwordEncoder
    ){
        this.credentialRepository = credentialRepository;
        this.userRepository = userRepository;
        this.emailService = emailService;
        this.jwtUtil = jwtUtil;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public final Map<String, UserEntity> registerUser(RegisterUserDto dto) throws MessagingException {
        try {
            UserEntity newUser = this.userRepository.save(generateUser(dto));

            this.credentialRepository.save(generateCredential(dto, newUser));
            
            String token = this.jwtUtil.genereteTokenBySendEmail(dto.getEmail());
            emailService.sendEmailVerifyAccount(dto.getEmail(), token);

            return Map.of("user", this.userRepository.save(newUser));
        } catch (MessagingException e) {
            throw new MessagingException(e.getMessage());
        }
    }

    @Override
    public final Map<String, String> login(LoginDto loginRequest) throws UserNotEnableException {
        String email = loginRequest.getEmail();
        String password = loginRequest.getPassword();

        Authentication authentication = this.authenticate(email, password);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String accessToken = jwtUtil.generateToken(authentication);

        return Map.of("token", accessToken);
    }

    private Authentication authenticate(String email, String password) throws UserNotEnableException {
        UserDetails userDetails = this.loadUserByUsername(email);

        try {
            if (!passwordEncoder.matches(password, userDetails.getPassword()))
                throw new BadCredentialsException("Invalid email or password");

            if(!userDetails.isEnabled())
                throw new UserNotEnableException("Account is not verified");

            return new UsernamePasswordAuthenticationToken(
                    email,
                    userDetails.getPassword(),
                    userDetails.getAuthorities()
                );
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException(e.getMessage());
        } catch (UserNotEnableException e) {
            throw new UserNotEnableException(e.getMessage());
        }
    }

    @Override
    public final UserDetails loadUserByUsername(String email){
        try {
          CredentialEntity credential = userExist(email);
                  
          List<SimpleGrantedAuthority> autorityList = List.of( new SimpleGrantedAuthority("ROLE_USER") );
          
          return new User(
                  credential.getEmail(),
                  credential.getPassword(),
                  credential.isEnabled(),
                  true,
                  true,
                  true,
                  autorityList
        );
        
        } catch(NoResultException e){
                throw new NoResultException(e.getMessage());
        }
    }

    @Override
    public final Map<String, String> verifyAccount(String token) {
        try {
            String email = jwtUtil.extractUser(jwtUtil.validateToken(token));

            CredentialEntity credential = this.credentialRepository.findByEmail(email);
            credential.setEnabled(true);
            this.credentialRepository.save(credential);

            return Map.of(MESSAGE, "Account verified");
        } catch (JWTVerificationException e) {
            throw new JWTVerificationException("Invalid token");
        }
    }

    @Override
    public final Map<String, String> recupereAccount(String email) throws MessagingException, UserNotEnableException {
        try {
            CredentialEntity credential = userExist(email);
            
            if(!credential.isEnabled())
                  throw new UserNotEnableException("Account is not verified");

            String token = jwtUtil.genereteTokenBySendEmail(email);
            emailService.sendEmailRecupereAccount(email, token);

            return Map.of(MESSAGE, "Email sent, check your inbox and follow the instructions");
        } catch(NoResultException e){
            throw new NoResultException(e.getMessage());
        } catch (UserNotEnableException e) {
            throw new UserNotEnableException(e.getMessage());
        } catch (MessagingException e) {
            throw new MessagingException(e.getMessage());
        }
    }

    @Override
    public final Map<String, String> changePassword(String token, String newPassword) {
        try {
            String email = jwtUtil.extractUser(jwtUtil.validateToken(token));

            CredentialEntity credential = userExist(email);
            credential.setPassword(passwordEncoder.encode(newPassword));
            this.credentialRepository.save(credential);

            return Map.of(MESSAGE, "Password changed successfully");
        } catch (JWTVerificationException e) {
            throw new JWTVerificationException(e.getMessage());
        } 
    }

    private CredentialEntity userExist(String email) throws NoResultException {
        return Optional.ofNullable(this.credentialRepository.findByEmail(email))
                  .orElseThrow(() -> new NoResultException("User not exist"));
    }

    private CredentialEntity generateCredential(RegisterUserDto dto, UserEntity newUser){
        String passwordHash = passwordEncoder.encode(dto.getPassword());

        return CredentialEntity.builder()
                .email(dto.getEmail())
                .password(passwordHash)
                .isEnabled(false)
                .user(newUser)
                .build();
    }

    private UserEntity generateUser(RegisterUserDto dto){
        return UserEntity.builder()
                .name(dto.getName())
                .lastname(dto.getLastname())
                .build();
    }
}
