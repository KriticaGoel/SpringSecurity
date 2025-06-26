package com.kritica.securitydemo;

import com.kritica.securitydemo.jwt.AuthService;
import com.kritica.securitydemo.jwt.JwtUtils;
import com.kritica.securitydemo.jwt.LoginRequest;
import com.kritica.securitydemo.jwt.LoginResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequiredArgsConstructor
public class GreetingController {

    private AuthService authService;
    private JwtUtils jwtUtils;
    private AuthenticationManager authenticationManager;



    @GetMapping("/greeting")
    public String greeting() {
        return "Hello World!";
    }

    @GetMapping("kritica/greeting")
    public String kgreeting() {
        return "Hello World!";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String helloAdmin() {
        return "Hello Admin!";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String helloUser() {
        return "Hello User!";
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authnticateUser(@RequestBody LoginRequest loginRequest){

        try {
            Authentication authentication = authService.authenticate(loginRequest);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String token = jwtUtils.generateJwtToken(userDetails);
            List<String> roles= userDetails.getAuthorities().stream()
                    .map(item->item.getAuthority()).toList();

            LoginResponse response = new LoginResponse();
            response.setToken(token);
            response.setRoles(roles);
            response.setUsername(userDetails.getUsername());
            return ResponseEntity.ok(response);

        } catch (AuthenticationServiceException e) {
            Map<String, Object> map = new HashMap<>();
            map.put("message","Bad credentials");
            map.put("status",false);
            return new ResponseEntity<>(map, HttpStatus.NOT_FOUND);
        }

    }
}
