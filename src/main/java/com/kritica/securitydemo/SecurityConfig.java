package com.kritica.securitydemo;

import com.kritica.securitydemo.jwt.AuthEntryPointJwt;
import com.kritica.securitydemo.jwt.AuthTokenFilter;
import com.kritica.securitydemo.jwt.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    //Configures the spring security filters and rules for the application
    //Sets up the security filter chain, permitting or denying access based on the paths and roles.
    //It also configures session management to stateless, which is crucial for JWT usage.

    @Autowired
    DataSource dataSource;


    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter(){
        return new AuthTokenFilter(new JwtUtils(), userDetailsService());
    }

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        //this bypass the url from authentication
        http.authorizeHttpRequests((requests) ->
                requests.requestMatchers("/kritica/**").permitAll()
                        .requestMatchers("/api/sigin").permitAll()
                        .anyRequest().authenticated());
        //Diable cookies to prevent session fixation attacks
        http.sessionManagement((session)
               -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        // http.formLogin(withDefaults());
        //http.httpBasic(withDefaults());

        //handling exception using custom Handler
        http.exceptionHandling(exception->
                exception.authenticationEntryPoint(unauthorizedHandler()));

        //our custom filter called at which points in filter
        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
    
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.withUsername("admin")
                .password(passwordEncoder().encode("admin"))
                .roles("ADMIN")
                .build();
        UserDetails user2 = User.withUsername("user")
                .password(passwordEncoder().encode("user"))
                .roles("USER")
                .build();
//        UserDetails user3 = User.withUsername("user3")
//                .password("{noop}password3")
//                .roles("user")
//                .build();

//        return new InMemoryUserDetailsManager(user1, user2, user3);
        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(user2);
        return userDetailsManager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception {
        return builder.getAuthenticationManager();
    }
    @Bean
    public AuthEntryPointJwt unauthorizedHandler() {
        return new AuthEntryPointJwt();
    }

}
