import os
import shutil
import hashlib
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, BinaryIO

class StorageProvider(ABC):
    """Abstract storage interface supporting local filesystem and future cloud backends (AWS S3, Azure Blob)."""

    @abstractmethod
    def save(self, destination_filename: str, file_bytes: bytes) -> Path:
        pass

    @abstractmethod
    def read(self, filename: str) -> bytes:
        pass

    @abstractmethod
    def compute_sha256(self, filename: str) -> str:
        pass

    @abstractmethod
    def exists(self, filename: str) -> bool:
        pass

    @abstractmethod
    def get_path(self, filename: str) -> Path:
        pass

class LocalFilesystemStorage(StorageProvider):
    """Secure local filesystem storage provider with path-traversal prevention and 64KB chunk SHA-256."""

    BUFFER_SIZE = 65536

    def __init__(self, base_directory: Path):
        self.base_dir = Path(base_directory).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_safe(self, filename: str) -> Path:
        # Sanitize against path traversal attacks (e.g. ../../etc/passwd)
        clean_name = Path(filename).name
        target = (self.base_dir / clean_name).resolve()
        if not str(target).startswith(str(self.base_dir)):
            raise ValueError(f"Path traversal security exception for filename: '{filename}'")
        return target

    def save(self, destination_filename: str, file_bytes: bytes) -> Path:
        target_path = self._resolve_safe(destination_filename)
        with open(target_path, "wb") as f:
            f.write(file_bytes)
        return target_path

    def read(self, filename: str) -> bytes:
        target_path = self._resolve_safe(filename)
        if not target_path.exists():
            raise FileNotFoundError(f"Stored evidence file '{filename}' does not exist on disk.")
        with open(target_path, "rb") as f:
            return f.read()

    def compute_sha256(self, filename: str) -> str:
        target_path = self._resolve_safe(filename)
        if not target_path.exists():
            raise FileNotFoundError(f"Cannot compute hash: file '{filename}' not found.")
        sha = hashlib.sha256()
        with open(target_path, "rb") as f:
            while chunk := f.read(self.BUFFER_SIZE):
                sha.update(chunk)
        return sha.hexdigest().lower()

    def exists(self, filename: str) -> bool:
        target_path = self._resolve_safe(filename)
        return target_path.exists() and target_path.is_file()

    def get_path(self, filename: str) -> Path:
        return self._resolve_safe(filename)

class CloudStorageStub(StorageProvider):
    """Extension point for enterprise cloud storage (AWS S3 or Azure Blob Storage)."""

    def __init__(self, bucket_name: str, region: str = "us-east-1"):
        self.bucket_name = bucket_name
        self.region = region

    def save(self, destination_filename: str, file_bytes: bytes) -> Path:
        raise NotImplementedError("Cloud storage provider is configured as an extension point. Set ACTIVE_STORAGE=local.")

    def read(self, filename: str) -> bytes:
        raise NotImplementedError("Cloud storage read is an extension stub.")

    def compute_sha256(self, filename: str) -> str:
        raise NotImplementedError("Cloud storage hashing is an extension stub.")

    def exists(self, filename: str) -> bool:
        return False

    def get_path(self, filename: str) -> Path:
        return Path(f"s3://{self.bucket_name}/{filename}")
