package com.example.demooauth2.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableConfigurationProperties(ApplicationConfig.class)
public class CorsConfig {
    private final long MAX_AGE_SEC = 3600;

    @Value("${app.cors.allowed-origins}")
    private String[] allowedOrigins;

    @Bean
    CorsFilter corsFilter() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setAllowedOrigins(
                Arrays.asList(allowedOrigins)
        );
        corsConfiguration.setAllowedHeaders(
                Arrays.asList(
                        "Origin",
                        "Access-Control-Allow-Origin",
                        "Content-Type",
                        "Accept",
                        "Authorization",
                        "Origin, Accept",
                        "X-Requested-With",
                        "Access-Control-Request-Method",
                        "Access-Control-Request-Headers"
                )
        );
        corsConfiguration.setExposedHeaders(
                Arrays.asList(
                        "Origin",
                        "Content-Type",
                        "Accept",
                        "Authorization",
                        "Access-Control-Allow-Origin",
                        "Access-Control-Allow-Credentials"
                )
        );
        corsConfiguration.setAllowedMethods(
                Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS")
        );
        corsConfiguration.setMaxAge(MAX_AGE_SEC);

        var urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);

        return new CorsFilter(urlBasedCorsConfigurationSource);
    }
}