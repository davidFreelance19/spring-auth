package com.authentication.app.presentation.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.authentication.app.presentation.security.filter.JwtTokenFilter;
import com.authentication.app.utils.JwtUtil;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    
    private static final String PUBLIC_ROUTE = "api/auth/**";
    private static final String PRIVATE_ROUTE = "api/app/**";
    
    private static final String ROLE = "USER";

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtUtil jwtUtil;

    SecurityConfig(JwtUtil jwtUtil, AuthenticationConfiguration authenticationConfiguration){
        this.jwtUtil = jwtUtil;
        this.authenticationConfiguration = authenticationConfiguration;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(http -> {
                    // Enpoints publicos
                    http.requestMatchers(HttpMethod.POST, PUBLIC_ROUTE).permitAll();
                    http.requestMatchers(HttpMethod.GET, PUBLIC_ROUTE).permitAll();
                    http.requestMatchers(HttpMethod.PATCH, PUBLIC_ROUTE).permitAll();

                    // Enpoints privados
                    http.requestMatchers(HttpMethod.POST, PRIVATE_ROUTE).hasRole(ROLE);
                    http.requestMatchers(HttpMethod.GET, PRIVATE_ROUTE).hasRole(ROLE);
                    http.requestMatchers(HttpMethod.PATCH, PRIVATE_ROUTE).hasRole(ROLE);
                    http.requestMatchers(HttpMethod.DELETE, PRIVATE_ROUTE).hasRole(ROLE);
                    http.requestMatchers(HttpMethod.PUT, PRIVATE_ROUTE).hasRole(ROLE);
                })
                .addFilterBefore(new JwtTokenFilter(jwtUtil), BasicAuthenticationFilter.class)
                .build();
    }


    @Bean
    AuthenticationManager authenticationManager() throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}