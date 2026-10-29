package com.autorecon.ai.config;

import com.autorecon.ai.entity.Evidence;
import com.autorecon.ai.repository.AuditLogRepository;
import com.autorecon.ai.repository.EvidenceRepository;
import com.autorecon.ai.service.EvidenceService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;

@Component
public class DataInitializer implements CommandLineRunner {

    private static final Logger logger = LoggerFactory.getLogger(DataInitializer.class);

    private final EvidenceRepository evidenceRepository;
    private final EvidenceService evidenceService;

    public DataInitializer(EvidenceRepository evidenceRepository, EvidenceService evidenceService) {
        this.evidenceRepository = evidenceRepository;
        this.evidenceService = evidenceService;
    }

    @Override
    public void run(String... args) {
        try {
            seedSampleEvidenceIfEmpty();
        } catch (Exception e) {
            logger.warn("Could not complete sample data initialization: {}", e.getMessage());
        }
    }

    public void seedSampleEvidenceIfEmpty() {
        if (evidenceRepository.count() > 0) {
            return;
        }

        logger.info("Initializing baseline forensic sample evidence in database...");
        Path storageDir = evidenceService.getStorageDir();

        SampleItem[] items = new SampleItem[]{
                new SampleItem(
                        "ev-can-urban-01",
                        "CASE_AF_01",
                        "can_bus_traffic_intersection_AF01.log",
                        "TIMESTAMP,ID,DATA\n1710921000.100,0x0284,B1 2A 00 00\n1710921000.120,0x0312,01 FF 4C 88\n1710921001.000,0x01A0,BRAKE_CMD_APPLIED\n".getBytes(StandardCharsets.UTF_8),
                        "CAN_BUS_DUMP",
                        "Forensic_Lead_Det_Smith",
                        true
                ),
                new SampleItem(
                        "ev-edr-urban-01",
                        "CASE_AF_01",
                        "edr_event_record_AF01.bin",
                        "EDR_CRASH_DATA_BLOCK_HEADER_REV3.2_AF01_DELTA_V_-24.8KPH_SEATBELT_LATCHED".getBytes(StandardCharsets.UTF_8),
                        "EDR_BINARY",
                        "Forensic_Lead_Det_Smith",
                        true
                ),
                new SampleItem(
                        "ev-dashcam-urban-01",
                        "CASE_AF_01",
                        "front_dashcam_telemetry_AF01.mp4.meta",
                        "DASHCAM_METADATA_GPS_LAT_37.7749_LON_-122.4194_FRAME_RATE_60FPS_LENS_FRONT".getBytes(StandardCharsets.UTF_8),
                        "DASHCAM_VIDEO",
                        "Forensic_Lead_Det_Smith",
                        false
                ),
                new SampleItem(
                        "ev-radar-highway-02",
                        "CASE_AF_02",
                        "radar_point_cloud_highway_AF02.dat",
                        "RADAR_FRAME_AF02_RANGE_45M_VELOCITY_REL_-12MS_TARGET_REAR_VEHICLE".getBytes(StandardCharsets.UTF_8),
                        "RADAR_POINTCLOUD",
                        "Officer_Rodriguez",
                        true
                ),
                new SampleItem(
                        "ev-can-overtake-03",
                        "CASE_AF_03",
                        "can_bus_blindspot_AF03.log",
                        "CAN_AF03_LANE_CHANGE_INDICATOR_LEFT_BLIND_SPOT_WARN_HIGH".getBytes(StandardCharsets.UTF_8),
                        "CAN_BUS_DUMP",
                        "Investigator_Chen",
                        true
                )
        };

        Instant now = Instant.now();
        for (SampleItem item : items) {
            try {
                byte[] data = item.content;
                String fileHash = EvidenceService.computeSha256(data);
                String storageName = item.id + "_" + item.filename;
                Path filePath = storageDir.resolve(storageName);

                Files.write(filePath, data, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

                String trustedRef = item.trustedMatch ? fileHash : null;
                String status = item.trustedMatch ? "VERIFIED" : "UNVERIFIED";

                Evidence ev = new Evidence(
                        item.id,
                        item.caseId,
                        item.filename,
                        storageName,
                        (long) data.length,
                        "application/octet-stream",
                        item.evidenceType,
                        fileHash,
                        trustedRef,
                        status,
                        item.investigatorId,
                        now,
                        item.trustedMatch ? now : null
                );
                evidenceRepository.save(ev);

                evidenceService.logAuditEvent(
                        item.id,
                        "INGESTION",
                        item.investigatorId,
                        "Secure ingestion of sample artifact " + item.filename + " (Size: " + data.length + " bytes). Initial SHA-256 computed.",
                        null
                );

                if (trustedRef != null) {
                    evidenceService.logAuditEvent(
                            item.id,
                            "REFERENCE_ADDED",
                            item.investigatorId,
                            "Trusted acquisition reference registered from verified field property sheet.",
                            null
                    );

                    evidenceService.logAuditEvent(
                            item.id,
                            "INTEGRITY_VERIFICATION",
                            "System_Automated_Verifier",
                            "Baseline disk integrity check: Computed hash matches trusted reference exactly.",
                            "VERIFIED"
                    );
                }
            } catch (IOException e) {
                logger.error("Failed to seed file for sample evidence {}: {}", item.id, e.getMessage());
            }
        }
        logger.info("Successfully seeded baseline forensic demonstration evidence.");
    }

    private static class SampleItem {
        final String id;
        final String caseId;
        final String filename;
        final byte[] content;
        final String evidenceType;
        final String investigatorId;
        final boolean trustedMatch;

        SampleItem(String id, String caseId, String filename, byte[] content,
                   String evidenceType, String investigatorId, boolean trustedMatch) {
            this.id = id;
            this.caseId = caseId;
            this.filename = filename;
            this.content = content;
            this.evidenceType = evidenceType;
            this.investigatorId = investigatorId;
            this.trustedMatch = trustedMatch;
        }
    }
}
