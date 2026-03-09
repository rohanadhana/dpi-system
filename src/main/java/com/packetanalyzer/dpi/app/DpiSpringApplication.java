
package com.packetanalyzer.dpi.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.packetanalyzer.dpi")
public class DpiSpringApplication {
    public static void main(String[] args) {
        SpringApplication.run(DpiSpringApplication.class, args);
    }
}
