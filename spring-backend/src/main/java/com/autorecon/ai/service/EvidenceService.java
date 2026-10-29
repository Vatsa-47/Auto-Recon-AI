package com.autorecon.ai.service;

import com.autorecon.ai.config.StorageProperties;
import com.autorecon.ai.dto.*;
import com.autorecon.ai.entity.AuditLog;
import com.autorecon.ai.entity.Evidence;
import com.autorecon.ai.exception.InvalidHashException;
import com.autorecon.ai.exception.ResourceNotFoundException;
import com.autorecon.ai.exception.StorageException;
import com.autorecon.ai.repository.AuditLogRepository;
import com.autorecon.ai.repository.EvidenceRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class EvidenceService {

    private static final Pattern HEX64_REGEX = Pattern.compile("^[a-fA-F0-9]{64}$");
    private static final String GENESIS_HASH = "0".repeat(64);
    private static final int BUFFER_SIZE = 65536;

    private final EvidenceRepository evidenceRepository;
    private final AuditLogRepository auditLogRepository;
    private final StorageProperties storageProperties;

    public EvidenceService(EvidenceRepository evidenceRepository,
                           AuditLogRepository auditLogRepository,
                           StorageProperties storageProperties) {
        this.evidenceRepository = evidenceRepository;
        this.auditLogRepository = auditLogRepository;
        this.storageProperties = storageProperties;
    }

    public Path getStorageDir() {
        Path path = storageProperties.getStoragePath();
        try {
            Files.createDirectories(path);
        } catch (IOException e) {
            throw new StorageException("Failed to initialize evidence storage directory: " + path, e);
        }
        return path;
    }

    public String sanitizeFilename(String filename) {
        if (filename == null || filename.trim().isEmpty()) {
            return "unnamed_evidence.bin";
        }
        String clean = Paths.get(filename).getFileName().toString();
        clean = clean.replaceAll("[^\\w\\-.]", "_");
        return clean.isEmpty() ? "unnamed_evidence.bin" : clean;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static String computeSha256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return bytesToHex(digest.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    public static String computeFileSha256(Path filePath) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream is = Files.newInputStream(filePath)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int read;
                while ((read = is.read(buffer)) != -1) {
                    digest.update(buffer, 0, read);
                }
            }
            return bytesToHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }

    public String formatTimestamp(Instant instant) {
        if (instant == null) return null;
        return DateTimeFormatter.ISO_INSTANT.format(instant);
    }

    public String computeRecordHash(String eventId, String evidenceId, String eventType,
                                    String timestampStr, String actorId, String details,
                                    String verificationResult, String previousHash) {
        String content = eventId + "|" + evidenceId + "|" + eventType + "|" + timestampStr + "|" + actorId + "|"
                + (details != null ? details : "") + "|"
                + (verificationResult != null ? verificationResult : "") + "|"
                + previousHash;
        return computeSha256(content.getBytes(StandardCharsets.UTF_8));
    }

    public String getLatestAuditHash(String evidenceId) {
        if (evidenceId != null) {
            Optional<AuditLog> latest = auditLogRepository.findTopByEvidenceIdOrderByIdDesc(evidenceId);
            if (latest.isPresent()) {
                return latest.get().getRecordHash();
            }
        }
        return GENESIS_HASH;
    }

    @Transactional
    public AuditLog logAuditEvent(String evidenceId, String eventType, String actorId,
                                  String details, String verificationResult) {
        String eventId = UUID.randomUUID().toString();
        Instant now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
        String timestampStr = formatTimestamp(now);
        String previousHash = getLatestAuditHash(evidenceId);

        String recordHash = computeRecordHash(
                eventId, evidenceId, eventType, timestampStr, actorId, details, verificationResult, previousHash
        );

        AuditLog log = new AuditLog(
                eventId, evidenceId, eventType, now, actorId, details, verificationResult, previousHash, recordHash
        );
        return auditLogRepository.save(log);
    }

    @Transactional
    public EvidenceItemDto saveUploadedEvidence(byte[] fileBytes, String originalFilename,
                                                String caseId, String evidenceType,
                                                String investigatorId, String trustedReference,
                                                String mimeType) {
        if (caseId == null || caseId.trim().isEmpty()) {
            throw new IllegalArgumentException("Field 'case_id' is required.");
        }

        Path storageDir = getStorageDir();
        String cleanName = sanitizeFilename(originalFilename);
        String evidenceId = "ev-" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String storageFilename = evidenceId + "_" + cleanName;
        Path storagePath = storageDir.resolve(storageFilename);

        String computedSha256 = computeSha256(fileBytes);
        long fileSize = fileBytes.length;

        try {
            Files.write(storagePath, fileBytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        } catch (IOException e) {
            throw new StorageException("Failed to write evidence file to disk: " + storageFilename, e);
        }

        String normalizedRef = null;
        if (trustedReference != null && !trustedReference.trim().isEmpty()) {
            String candidate = trustedReference.trim().toLowerCase();
            if (HEX64_REGEX.matcher(candidate).matches()) {
                normalizedRef = candidate;
            }
        }

        String status;
        if (normalizedRef != null) {
            if (computedSha256.equalsIgnoreCase(normalizedRef)) {
                status = "VERIFIED";
            } else {
                status = "MISMATCH";
            }
        } else {
            status = "UNVERIFIED";
        }

        Instant now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
        Instant lastVerified = ("VERIFIED".equals(status) || "MISMATCH".equals(status)) ? now : null;

        Evidence evidence = new Evidence(
                evidenceId,
                caseId,
                cleanName,
                storageFilename,
                fileSize,
                mimeType != null ? mimeType : "application/octet-stream",
                evidenceType != null ? evidenceType : "GENERIC_BINARY",
                computedSha256,
                normalizedRef,
                status,
                investigatorId != null ? investigatorId : "Forensic_Investigator",
                now,
                lastVerified
        );

        Evidence saved = evidenceRepository.save(evidence);

        logAuditEvent(
                evidenceId,
                "INGESTION",
                saved.getInvestigatorId(),
                "Secure ingestion of forensic artifact '" + cleanName + "' (" + fileSize + " bytes). Initial SHA-256 computed: " + computedSha256,
                null
        );

        if (normalizedRef != null) {
            logAuditEvent(
                    evidenceId,
                    "REFERENCE_ADDED",
                    saved.getInvestigatorId(),
                    "Trusted acquisition reference registered: " + normalizedRef,
                    null
            );

            logAuditEvent(
                    evidenceId,
                    "INTEGRITY_VERIFICATION",
                    saved.getInvestigatorId(),
                    "Initial integrity check: " + ("VERIFIED".equals(status) ? "MATCH" : "MISMATCH"),
                    status
            );
        }

        return toDto(saved);
    }

    public List<EvidenceItemDto> listEvidence(String caseId) {
        List<Evidence> list;
        if (caseId != null && !caseId.trim().isEmpty()) {
            list = evidenceRepository.findByCaseIdOrderByUploadedAtDesc(caseId.trim());
        } else {
            list = evidenceRepository.findAllByOrderByUploadedAtDesc();
        }
        return list.stream().map(this::toDto).collect(Collectors.toList());
    }

    public EvidenceItemDto getEvidenceById(String evidenceId) {
        Evidence ev = evidenceRepository.findById(evidenceId)
                .orElseThrow(() -> new ResourceNotFoundException("Evidence artifact '" + evidenceId + "' not found."));
        return toDto(ev);
    }

    @Transactional
    public EvidenceItemDto setTrustedReference(String evidenceId, String referenceHash, String actorId) {
        if (referenceHash == null || !HEX64_REGEX.matcher(referenceHash.trim()).matches()) {
            throw new InvalidHashException("Invalid SHA-256 hash format. Must be 64 hexadecimal characters.");
        }
        String cleanRef = referenceHash.trim().toLowerCase();
        String effectiveActor = (actorId != null && !actorId.trim().isEmpty()) ? actorId : "Forensic_Investigator";

        Evidence ev = evidenceRepository.findById(evidenceId)
                .orElseThrow(() -> new ResourceNotFoundException("Evidence artifact '" + evidenceId + "' not found."));

        ev.setTrustedReference(cleanRef);
        evidenceRepository.save(ev);

        logAuditEvent(
                evidenceId,
                "REFERENCE_ADDED",
                effectiveActor,
                "Trusted reference hash updated to: " + cleanRef,
                null
        );

        verifyEvidence(evidenceId, effectiveActor);

        Evidence refreshed = evidenceRepository.findById(evidenceId)
                .orElseThrow(() -> new ResourceNotFoundException("Evidence artifact '" + evidenceId + "' not found."));
        return toDto(refreshed);
    }

    @Transactional
    public VerificationResultDto verifyEvidence(String evidenceId, String actorId) {
        Evidence ev = evidenceRepository.findById(evidenceId)
                .orElseThrow(() -> new ResourceNotFoundException("Evidence record '" + evidenceId + "' not found."));

        String effectiveActor = (actorId != null && !actorId.trim().isEmpty()) ? actorId : "Forensic_Investigator";
        Path storageDir = getStorageDir();
        Path storagePath = storageDir.resolve(ev.getStorageFilename());
        Instant now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
        String trustedRef = ev.getTrustedReference();
        String filename = ev.getFilename();

        String newStatus;
        boolean match;
        String message;
        String currentSha256 = null;

        if (!Files.exists(storagePath)) {
            newStatus = "ERROR";
            match = false;
            message = "Forensic storage file missing or deleted on disk.";
        } else {
            try {
                currentSha256 = computeFileSha256(storagePath);
                if (trustedRef == null || trustedRef.trim().isEmpty()) {
                    newStatus = "UNVERIFIED";
                    match = false;
                    message = "File hash computed from disk, but no trusted reference has been configured.";
                } else if (currentSha256.equalsIgnoreCase(trustedRef)) {
                    newStatus = "VERIFIED";
                    match = true;
                    message = "Cryptographic integrity verified: Disk SHA-256 matches trusted acquisition reference.";
                } else {
                    newStatus = "MISMATCH";
                    match = false;
                    message = "INTEGRITY VIOLATION: Current file SHA-256 (" + currentSha256 + ") differs from trusted reference (" + trustedRef + ").";
                }
            } catch (Exception e) {
                newStatus = "ERROR";
                match = false;
                message = "Disk I/O error during hash calculation: " + e.getMessage();
            }
        }

        ev.setStatus(newStatus);
        ev.setLastVerifiedAt(now);
        evidenceRepository.save(ev);

        logAuditEvent(
                evidenceId,
                "INTEGRITY_VERIFICATION",
                effectiveActor,
                "Integrity check performed. Computed: " + (currentSha256 != null ? currentSha256 : "N/A") + ". Reference: " + (trustedRef != null ? trustedRef : "None") + ". " + message,
                newStatus
        );

        return new VerificationResultDto(
                evidenceId,
                filename,
                currentSha256,
                trustedRef,
                newStatus,
                match,
                message,
                formatTimestamp(now)
        );
    }

    @Transactional
    public List<VerificationResultDto> verifyAllEvidence(String caseId, String actorId) {
        List<Evidence> targetList;
        if (caseId != null && !caseId.trim().isEmpty()) {
            targetList = evidenceRepository.findByCaseIdOrderByUploadedAtDesc(caseId.trim());
        } else {
            targetList = evidenceRepository.findAllByOrderByUploadedAtDesc();
        }

        List<VerificationResultDto> results = new ArrayList<>();
        for (Evidence ev : targetList) {
            results.add(verifyEvidence(ev.getId(), actorId));
        }
        return results;
    }

    public AuditHistoryResponse getAuditHistory(String evidenceId) {
        if (!evidenceRepository.existsById(evidenceId)) {
            throw new ResourceNotFoundException("Evidence artifact '" + evidenceId + "' not found.");
        }

        List<AuditLog> logs = auditLogRepository.findByEvidenceIdOrderByIdAsc(evidenceId);
        List<AuditLogEntryDto> dtoList = logs.stream().map(this::toAuditDto).collect(Collectors.toList());

        boolean chainValid = true;
        for (AuditLog log : logs) {
            String tsStr = formatTimestamp(log.getTimestamp());
            String recomputed = computeRecordHash(
                    log.getEventId(),
                    log.getEvidenceId(),
                    log.getEventType(),
                    tsStr,
                    log.getActorId(),
                    log.getDetails(),
                    log.getVerificationResult(),
                    log.getPreviousHash()
            );
            if (!recomputed.equalsIgnoreCase(log.getRecordHash())) {
                chainValid = false;
                break;
            }
        }

        return new AuditHistoryResponse(evidenceId, chainValid, dtoList.size(), dtoList);
    }

    public EvidenceItemDto toDto(Evidence e) {
        return new EvidenceItemDto(
                e.getId(),
                e.getCaseId(),
                e.getFilename(),
                e.getFileSize(),
                e.getMimeType(),
                e.getEvidenceType(),
                e.getSha256(),
                e.getTrustedReference(),
                e.getStatus(),
                e.getInvestigatorId(),
                formatTimestamp(e.getUploadedAt()),
                formatTimestamp(e.getLastVerifiedAt())
        );
    }

    public AuditLogEntryDto toAuditDto(AuditLog a) {
        return new AuditLogEntryDto(
                a.getId(),
                a.getEventId(),
                a.getEvidenceId(),
                a.getEventType(),
                formatTimestamp(a.getTimestamp()),
                a.getActorId(),
                a.getDetails(),
                a.getVerificationResult(),
                a.getPreviousHash(),
                a.getRecordHash()
        );
    }
}
