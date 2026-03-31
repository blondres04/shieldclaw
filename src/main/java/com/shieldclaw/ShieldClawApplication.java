package com.shieldclaw;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class ShieldClawApplication {

    public static void main(String[] args) {
        SpringApplication.run(ShieldClawApplication.class, args);
    }
}
