package com.autorecon.ai.controller;

import com.autorecon.ai.config.StorageProperties;
import com.autorecon.ai.dto.HealthResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.time.format.DateTimeFormatter;

@RestController
@RequestMapping("/api")
public class HealthController {

    private final DataSource dataSource;
    private final StorageProperties storageProperties;

    @Value("${spring.datasource.url:}")
    private String datasourceUrl;

    public HealthController(DataSource dataSource, StorageProperties storageProperties) {
        this.dataSource = dataSource;
        this.storageProperties = storageProperties;
    }

    @GetMapping("/health")
    public HealthResponse checkHealth() {
        boolean storageOk = false;
        try {
            Path storagePath = storageProperties.getStoragePath();
            Files.createDirectories(storagePath);
            storageOk = Files.isWritable(storagePath);
        } catch (Exception ignored) {
        }

        boolean dbOk = false;
        String dbError = null;
        String dbType = "MySQL 8.0+ (Spring Data JPA)";
        String dbHost = "127.0.0.1";

        if (datasourceUrl.contains("h2")) {
            dbType = "H2 Database (Isolated Test Mode)";
            dbHost = "in-memory";
        } else if (datasourceUrl.contains("://")) {
            try {
                String clean = datasourceUrl.substring(datasourceUrl.indexOf("://") + 3);
                if (clean.contains(":")) {
                    dbHost = clean.substring(0, clean.indexOf(":"));
                } else if (clean.contains("/")) {
                    dbHost = clean.substring(0, clean.indexOf("/"));
                }
            } catch (Exception ignored) {
            }
        }

        try (Connection conn = dataSource.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT 1")) {
            if (rs.next()) {
                dbOk = true;
            }
        } catch (Exception e) {
            dbOk = false;
            dbError = e.getMessage();
        }

        String appStatus = (storageOk && dbOk) ? "healthy" : "degraded";

        return new HealthResponse(
                appStatus,
                "Spring Boot Forensic Verification Engine",
                storageOk,
                dbOk,
                dbType,
                dbHost,
                dbError,
                DateTimeFormatter.ISO_INSTANT.format(Instant.now())
        );
    }
}
