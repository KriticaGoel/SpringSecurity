package com.kritica.securitydemo.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;


    public Authentication authenticate(LoginRequest request) {
        try {
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );
        } catch (DisabledException e) {
            throw new RuntimeException("Account is disabled", e);
        } catch (LockedException e) {
            throw new RuntimeException("Account is locked", e);
        } catch (BadCredentialsException e) {
            throw new RuntimeException("Invalid credentials", e);
        } catch (AuthenticationException e) {
            throw new RuntimeException("Authentication failed", e);
        }
    }
}
