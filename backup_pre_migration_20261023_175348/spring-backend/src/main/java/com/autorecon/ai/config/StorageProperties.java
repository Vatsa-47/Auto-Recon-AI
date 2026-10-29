package com.autorecon.ai.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.nio.file.Paths;

@Component
public class StorageProperties {

    @Value("${autorecon.storage.dir:storage}")
    private String storageDir;

    public Path getStoragePath() {
        return Paths.get(storageDir).toAbsolutePath().normalize();
    }

    public String getStorageDir() {
        return storageDir;
    }

    public void setStorageDir(String storageDir) {
        this.storageDir = storageDir;
    }
}
