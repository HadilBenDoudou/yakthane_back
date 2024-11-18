package com.example.demo;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")  // Permettre CORS pour tous les endpoints
                .allowedOrigins("http://10.0.2.2:9991")  // Autoriser ces origines
                .allowedMethods("GET", "POST", "PUT", "DELETE")  // Méthodes HTTP autorisées
                .allowedHeaders("*")  // Autoriser tous les headers
                .allowCredentials(true);  // Autoriser l'envoi de cookies
    }
}
