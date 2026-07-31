package com.soham.ccshareapp.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfiguration {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                // Picks up the CorsConfigurationSource bean below. Spring Security's
                // CorsFilter runs ahead of authorization, so preflight OPTIONS is
                // answered there and never reaches the denyAll() at the bottom.
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST, "/create", "/fetch").permitAll()
                        .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**").permitAll()
                        .anyRequest().denyAll())
                .build();
    }

    /**
     * LLD §8.1 puts the SPA on a different origin from this API by design, which
     * makes every browser call cross-origin and therefore subject to CORS. The
     * allowlist is a single exact origin from configuration — never a wildcard,
     * and never reflected from the request's own {@code Origin} header, which
     * would make the allowlist decorative.
     *
     * <p>Note the value is scheme + host only. A GitHub Pages project site lives
     * under a path ({@code /credit-card-details-sharer/}), but paths are not part
     * of an origin and including one here silently matches nothing.
     *
     * <p>{@code allowCredentials} stays false to match the frontend's
     * {@code credentials: "omit"} — the backend is stateless and no cookie should
     * ever ride along.
     */
    @Bean
    CorsConfigurationSource corsConfigurationSource(
            @Value("${app.cors.allowed-origin}") String allowedOrigin) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of(allowedOrigin));
        config.setAllowedMethods(List.of("POST", "OPTIONS"));
        config.setAllowedHeaders(List.of("Content-Type"));
        config.setAllowCredentials(false);
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/create", config);
        source.registerCorsConfiguration("/fetch", config);
        return source;
    }
}
