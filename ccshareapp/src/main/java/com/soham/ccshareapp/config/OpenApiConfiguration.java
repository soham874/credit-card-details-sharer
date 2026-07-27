package com.soham.ccshareapp.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfiguration {

    @Bean
    OpenAPI ccShareOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("CC Share API")
                        .version("v1")
                        .description("Anonymous encrypted credit-card storage and sharing API"));
    }
}
