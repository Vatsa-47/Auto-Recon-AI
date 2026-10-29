package com.autorecon.ai;

import com.autorecon.ai.config.StorageProperties;
import com.autorecon.ai.entity.Evidence;
import com.autorecon.ai.repository.AuditLogRepository;
import com.autorecon.ai.repository.EvidenceRepository;
import com.autorecon.ai.service.EvidenceService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Comparator;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class EvidenceApiTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private EvidenceRepository evidenceRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private StorageProperties storageProperties;

    @BeforeEach
    public void setup() throws IOException {
        auditLogRepository.deleteAll();
        evidenceRepository.deleteAll();

        Path storageDir = storageProperties.getStoragePath();
        if (Files.exists(storageDir)) {
            try (var stream = Files.walk(storageDir)) {
                stream.sorted(Comparator.reverseOrder())
                        .filter(p -> !p.equals(storageDir))
                        .forEach(p -> {
                            try {
                                Files.deleteIfExists(p);
                            } catch (IOException ignored) {
                            }
                        });
            }
        }
        Files.createDirectories(storageDir);
    }

    // 1. Health endpoint test
    @Test
    @DisplayName("Test 1: Health endpoint reports healthy status and storage/db accessibility")
    public void testHealthCheck() throws Exception {
        mockMvc.perform(get("/api/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("healthy"))
                .andExpect(jsonPath("$.storage_accessible").value(true))
                .andExpect(jsonPath("$.db_accessible").value(true))
                .andExpect(jsonPath("$.backend").value("Spring Boot Forensic Verification Engine"));
    }

    // 2. Upload without a trusted reference (must be UNVERIFIED by default)
    @Test
    @DisplayName("Test 2: Evidence upload without reference defaults strictly to UNVERIFIED")
    public void testEvidenceUploadUnverifiedByDefault() throws Exception {
        byte[] fileBytes = "CAN_BUS_DUMP_AF01_RAW_FRAME_DATA_12345".getBytes(StandardCharsets.UTF_8);
        String expectedHash = EvidenceService.computeSha256(fileBytes);

        MockMultipartFile file = new MockMultipartFile(
                "file", "can_test.log", "text/plain", fileBytes
        );

        mockMvc.perform(multipart("/api/evidence")
                        .file(file)
                        .param("case_id", "CASE_AF_01")
                        .param("evidence_type", "CAN_BUS_DUMP"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.case_id").value("CASE_AF_01"))
                .andExpect(jsonPath("$.filename").value("can_test.log"))
                .andExpect(jsonPath("$.sha256").value(expectedHash))
                .andExpect(jsonPath("$.trusted_reference").doesNotExist())
                .andExpect(jsonPath("$.status").value("UNVERIFIED"));
    }

    // 3. Upload with matching trusted reference
    @Test
    @DisplayName("Test 3: Evidence upload with matching reference verifies immediately")
    public void testEvidenceUploadWithMatchingReference() throws Exception {
        byte[] fileBytes = "EDR_CRASH_DATA_BINARY_STREAM_OCTET".getBytes(StandardCharsets.UTF_8);
        String expectedHash = EvidenceService.computeSha256(fileBytes);

        MockMultipartFile file = new MockMultipartFile(
                "file", "edr_test.bin", "application/octet-stream", fileBytes
        );

        mockMvc.perform(multipart("/api/evidence")
                        .file(file)
                        .param("case_id", "CASE_AF_01")
                        .param("evidence_type", "EDR_BINARY")
                        .param("trusted_reference", expectedHash))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.sha256").value(expectedHash))
                .andExpect(jsonPath("$.trusted_reference").value(expectedHash))
                .andExpect(jsonPath("$.status").value("VERIFIED"));
    }

    // 4. Upload with mismatching trusted reference
    @Test
    @DisplayName("Test 4: Evidence upload with mismatched reference reports MISMATCH")
    public void testEvidenceUploadWithMismatchingReference() throws Exception {
        byte[] fileBytes = "AUTHENTIC_DASHCAM_FOOTAGE_BYTES".getBytes(StandardCharsets.UTF_8);
        String fakeHash = "0".repeat(64);

        MockMultipartFile file = new MockMultipartFile(
                "file", "dashcam.mp4", "video/mp4", fileBytes
        );

        mockMvc.perform(multipart("/api/evidence")
                        .file(file)
                        .param("case_id", "CASE_AF_01")
                        .param("evidence_type", "DASHCAM_VIDEO")
                        .param("trusted_reference", fakeHash))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("MISMATCH"));
    }

    // 5. Registering a reference hash
    @Test
    @DisplayName("Test 5: Registering trusted reference updates artifact and triggers verification")
    public void testSetReferenceAndVerify() throws Exception {
        byte[] fileBytes = "TELEMETRY_SAMPLE_FILE_DATA".getBytes(StandardCharsets.UTF_8);
        String realHash = EvidenceService.computeSha256(fileBytes);

        MockMultipartFile file = new MockMultipartFile(
                "file", "telemetry.csv", "text/csv", fileBytes
        );

        MvcResult uploadResult = mockMvc.perform(multipart("/api/evidence")
                        .file(file)
                        .param("case_id", "CASE_AF_02"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("UNVERIFIED"))
                .andReturn();

        JsonNode json = objectMapper.readTree(uploadResult.getResponse().getContentAsString());
        String evId = json.get("id").asText();

        String refPayload = "{\"reference_hash\": \"" + realHash + "\", \"actor_id\": \"Forensic_Examiner\"}";
        mockMvc.perform(post("/api/evidence/" + evId + "/reference")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.trusted_reference").value(realHash))
                .andExpect(jsonPath("$.status").value("VERIFIED"));
    }

    // 6. Detecting disk tampering
    @Test
    @DisplayName("Test 6: Detecting disk tampering reports MISMATCH and updates evidence record")
    public void testTamperDetectionOnDisk() throws Exception {
        byte[] fileBytes = "ORIGINAL_BRAKE_PRESSURE_RECORD".getBytes(StandardCharsets.UTF_8);
        String realHash = EvidenceService.computeSha256(fileBytes);

        MockMultipartFile file = new MockMultipartFile(
                "file", "brake_sensor.dat", "application/octet-stream", fileBytes
        );

        MvcResult uploadResult = mockMvc.perform(multipart("/api/evidence")
                        .file(file)
                        .param("case_id", "CASE_AF_01")
                        .param("trusted_reference", realHash))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("VERIFIED"))
                .andReturn();

        JsonNode json = objectMapper.readTree(uploadResult.getResponse().getContentAsString());
        String evId = json.get("id").asText();

        // Tamper with the file in storage!
        Evidence ev = evidenceRepository.findById(evId).orElseThrow();
        Path storageFile = storageProperties.getStoragePath().resolve(ev.getStorageFilename());
        assertTrue(Files.exists(storageFile));
        Files.write(storageFile, "TAMPERED_INJECTED_CORRUPTED_BYTES".getBytes(StandardCharsets.UTF_8),
                StandardOpenOption.TRUNCATE_EXISTING);

        // Run verification endpoint
        mockMvc.perform(post("/api/evidence/" + evId + "/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"actor_id\": \"Auditor\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("MISMATCH"))
                .andExpect(jsonPath("$.match").value(false))
                .andExpect(jsonPath("$.message", containsString("VIOLATION")));

        // Verify status in DB was updated to MISMATCH
        mockMvc.perform(get("/api/evidence/" + evId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("MISMATCH"));
    }

    // 7. Missing file handling
    @Test
    @DisplayName("Test 7: Verification reports ERROR when evidence file is deleted on disk")
    public void testMissingFileReportsError() throws Exception {
        byte[] fileBytes = "SOME_DATA_TO_DELETE".getBytes(StandardCharsets.UTF_8);

        MockMultipartFile file = new MockMultipartFile(
                "file", "to_delete.bin", "application/octet-stream", fileBytes
        );

        MvcResult uploadResult = mockMvc.perform(multipart("/api/evidence")
                        .file(file)
                        .param("case_id", "CASE_AF_03"))
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode json = objectMapper.readTree(uploadResult.getResponse().getContentAsString());
        String evId = json.get("id").asText();

        // Delete storage file
        Evidence ev = evidenceRepository.findById(evId).orElseThrow();
        Path storageFile = storageProperties.getStoragePath().resolve(ev.getStorageFilename());
        Files.deleteIfExists(storageFile);

        // Verify
        mockMvc.perform(post("/api/evidence/" + evId + "/verify"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ERROR"))
                .andExpect(jsonPath("$.match").value(false));
    }

    // 8. Audit hash-chain integrity
    @Test
    @DisplayName("Test 8: Audit log hash chain validates cryptographic continuity across events")
    public void testAuditLogHashChainIntegrity() throws Exception {
        byte[] fileBytes = "CHAIN_TEST_DATA".getBytes(StandardCharsets.UTF_8);
        String realHash = EvidenceService.computeSha256(fileBytes);

        MockMultipartFile file = new MockMultipartFile(
                "file", "chain_doc.log", "text/plain", fileBytes
        );

        MvcResult uploadResult = mockMvc.perform(multipart("/api/evidence")
                        .file(file)
                        .param("case_id", "CASE_AF_04"))
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode json = objectMapper.readTree(uploadResult.getResponse().getContentAsString());
        String evId = json.get("id").asText();

        // Add reference
        mockMvc.perform(post("/api/evidence/" + evId + "/reference")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reference_hash\": \"" + realHash + "\"}"))
                .andExpect(status().isOk());

        // Verify
        mockMvc.perform(post("/api/evidence/" + evId + "/verify"))
                .andExpect(status().isOk());

        // Fetch audit history
        MvcResult historyResult = mockMvc.perform(get("/api/evidence/" + evId + "/history"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.chain_valid").value(true))
                .andExpect(jsonPath("$.total_events", greaterThanOrEqualTo(3)))
                .andReturn();

        JsonNode historyJson = objectMapper.readTree(historyResult.getResponse().getContentAsString());
        JsonNode historyArray = historyJson.get("history");
        boolean hasIngestion = false;
        boolean hasRefAdded = false;
        boolean hasIntegrity = false;

        for (JsonNode entry : historyArray) {
            String eventType = entry.get("event_type").asText();
            if ("INGESTION".equals(eventType)) hasIngestion = true;
            if ("REFERENCE_ADDED".equals(eventType)) hasRefAdded = true;
            if ("INTEGRITY_VERIFICATION".equals(eventType)) hasIntegrity = true;
        }

        assertTrue(hasIngestion);
        assertTrue(hasRefAdded);
        assertTrue(hasIntegrity);
    }

    // 9. Invalid hash validation
    @Test
    @DisplayName("Test 9: Invalid SHA-256 hash yields 422 Unprocessable Entity")
    public void testInvalidHashValidation() throws Exception {
        MockMultipartFile file = new MockMultipartFile(
                "file", "invalid_hash_test.log", "text/plain", "12345".getBytes(StandardCharsets.UTF_8)
        );

        MvcResult uploadResult = mockMvc.perform(multipart("/api/evidence")
                        .file(file)
                        .param("case_id", "CASE_AF_05"))
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode json = objectMapper.readTree(uploadResult.getResponse().getContentAsString());
        String evId = json.get("id").asText();

        // Send non-64 hex character hash
        mockMvc.perform(post("/api/evidence/" + evId + "/reference")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"reference_hash\": \"not_a_valid_hex_hash\"}"))
                .andExpect(status().isUnprocessableEntity());
    }

    // 10. Case filtering and verify-all
    @Test
    @DisplayName("Test 10: Case filtering and batch verify-all endpoints execute successfully")
    public void testCaseEvidenceFilterAndVerifyAll() throws Exception {
        MockMultipartFile f1 = new MockMultipartFile(
                "file", "f1.dat", "application/octet-stream", "111".getBytes(StandardCharsets.UTF_8)
        );
        MockMultipartFile f2 = new MockMultipartFile(
                "file", "f2.dat", "application/octet-stream", "222".getBytes(StandardCharsets.UTF_8)
        );

        mockMvc.perform(multipart("/api/evidence").file(f1).param("case_id", "CASE_AF_01"))
                .andExpect(status().isCreated());

        mockMvc.perform(multipart("/api/evidence").file(f2).param("case_id", "CASE_AF_02"))
                .andExpect(status().isCreated());

        // Filter by case
        MvcResult filterResult = mockMvc.perform(get("/api/cases/CASE_AF_01/evidence"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].case_id").value("CASE_AF_01"))
                .andReturn();

        // Verify all for case
        mockMvc.perform(post("/api/evidence/verify-all").param("case_id", "CASE_AF_01"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(greaterThanOrEqualTo(1))));
    }

    // 11. Not-found handling
    @Test
    @DisplayName("Test 11: Non-existent evidence requests return 404 Not Found")
    public void testNotFoundHandling() throws Exception {
        mockMvc.perform(get("/api/evidence/ev-non-existent-999"))
                .andExpect(status().isNotFound());

        mockMvc.perform(get("/api/evidence/ev-non-existent-999/history"))
                .andExpect(status().isNotFound());
    }
}
