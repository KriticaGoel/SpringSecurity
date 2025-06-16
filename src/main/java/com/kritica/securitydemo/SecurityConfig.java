package com.kritica.securitydemo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        //this bypass the url from authentication
        http.authorizeHttpRequests((requests) ->
                requests.requestMatchers("/kritica/**").permitAll()
                        .anyRequest().authenticated());
        //Diable cookies to prevent session fixation attacks
        http.sessionManagement((session)
               -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // http.formLogin(withDefaults());
        http.httpBasic(withDefaults());
        return http.build();
    }
    
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.withUsername("user1")
                .password("{noop}password1")
                .roles("USER")
                .build();
        UserDetails user2 = User.withUsername("admin1")
                .password("{noop}password1")
                .roles("ADMIN")
                .build();
        UserDetails user3 = User.withUsername("user3")
                .password("{noop}password3")
                .roles("user")
                .build();

        return new InMemoryUserDetailsManager(user1, user2, user3);
    }
}
