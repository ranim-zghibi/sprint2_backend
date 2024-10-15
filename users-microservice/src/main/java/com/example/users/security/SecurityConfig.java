package com.example.users.security;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    AuthenticationManager authMgr;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.csrf().disable()  // Désactive CSRF car l’API utilise JWT.
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
            .cors().configurationSource(new CorsConfigurationSource() {
                @Override
                public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(Collections.singletonList("http://localhost:4200")); // Frontend autorisé
                    config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS")); // Méthodes HTTP permises
                    config.setAllowCredentials(true); // Autorise l’envoi de cookies
                    config.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "Accept")); // Headers autorisés
                    config.setExposedHeaders(Arrays.asList("Authorization")); // Headers visibles dans la réponse
                    config.setMaxAge(3600L); // Cache la config CORS pendant 1 heure
                    return config;
                }
            }).and()
            .authorizeHttpRequests((requests) -> requests
                .requestMatchers("/login").permitAll()  // Accès public au login
                .requestMatchers("/all").hasAuthority("ADMIN")  // ADMIN requis pour accéder à /all
                .anyRequest().authenticated())  // Toutes les autres routes nécessitent une authentification
            .addFilterBefore(new JWTAuthenticationFilter(authMgr), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(new JWTAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
