package com.example.userservice.security;

import com.example.userservice.jpa.UserRepository;
import com.example.userservice.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebSecurity{
    private final UserService userService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public WebSecurity(UserService userService, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userService = userService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Bean
    protected SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
        http.authorizeHttpRequests((authz) -> authz
                .requestMatchers(new AntPathRequestMatcher("/users/**")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/h2-console/**")).permitAll()
                .requestMatchers(new AntPathRequestMatcher("/actuator/**")).permitAll());

        // request h2-console frame
        http.headers((headers) -> headers.frameOptions((frameOption) -> frameOption.sameOrigin()));
        return http.build();
    }
}
