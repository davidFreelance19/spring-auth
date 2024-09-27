package com.authentication.app.presentation.security.filter;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.exceptions.JWTVerificationException;
import com.authentication.app.domain.entities.CredentialEntity;
import com.authentication.app.domain.repositories.CodeOtpRepository;
import com.authentication.app.domain.repositories.CredentialsRepository;
import com.authentication.app.utils.JwtUtil;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.constraints.NotNull;

public class IndentityVerificationByChangePasswordFilter extends OncePerRequestFilter{
    
    private final JwtUtil jwtUtil;
    private final CredentialsRepository credentialsRepository;
    private final CodeOtpRepository codeOtpRepository;

    public IndentityVerificationByChangePasswordFilter(
        JwtUtil jwtUtil,
        CredentialsRepository credentialsRepository,
        CodeOtpRepository codeOtpRepository 
    ) {
        this.jwtUtil = jwtUtil;
        this.credentialsRepository = credentialsRepository;
        this.codeOtpRepository = codeOtpRepository;
    }

    @Override
    protected void doFilterInternal(
            @NotNull HttpServletRequest request,
            @NotNull HttpServletResponse response,
            @NotNull FilterChain filterChain
    ) throws ServletException, IOException {

        String requestURI = request.getRequestURI();
        
        if (requestURI.startsWith("/api/auth/change-password/")) {
            String[] pathVariables = requestURI.split("/");
            String token = pathVariables[pathVariables.length - 1]; // Token al final del path
            String code = request.getParameter("code");


            if (code == null || code.isEmpty()) {
                handleError(response, "Code parameter is required");
                return; // Detenemos la cadena de filtros
            }

            try {
                String email = jwtUtil.extractUser(jwtUtil.validateToken(token));
                CredentialEntity credential = credentialsRepository.findByEmail(email);
                
                if (credential == null) {
                    handleError(response, "Invalid token");
                    return; 
                }

                if(codeOtpRepository.findByUser(credential.getUser()) == null){
                    handleError(response, "Invalid token");
                    return; 
                }

                if (this.codeOtpRepository.findByUserAndCode(credential.getUser(), code) == null) {
                    handleError(response, "Invalid code");
                    return; 
                }

            } catch (JWTVerificationException ex) {
                handleError(response, ex.getMessage());
                return; // Detenemos la cadena de filtros
            }
        }

        filterChain.doFilter(request, response);
    }
    private void handleError(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json");
        response.getWriter().write("{\"error\": \"" + message + "\"}");
    }
}
