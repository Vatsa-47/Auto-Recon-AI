package com.autorecon.ai.controller;

import com.autorecon.ai.dto.*;
import com.autorecon.ai.service.EvidenceService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/api")
public class EvidenceController {

    private final EvidenceService evidenceService;

    public EvidenceController(EvidenceService evidenceService) {
        this.evidenceService = evidenceService;
    }

    @PostMapping(value = "/evidence", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<EvidenceItemDto> uploadEvidence(
            @RequestParam("file") MultipartFile file,
            @RequestParam("case_id") String caseId,
            @RequestParam(value = "evidence_type", defaultValue = "GENERIC_BINARY") String evidenceType,
            @RequestParam(value = "investigator_id", defaultValue = "Forensic_Investigator") String investigatorId,
            @RequestParam(value = "trusted_reference", required = false) String trustedReference
    ) throws IOException {
        byte[] bytes = file.getBytes();
        String originalFilename = file.getOriginalFilename() != null ? file.getOriginalFilename() : "unknown.dat";
        String contentType = file.getContentType();

        EvidenceItemDto created = evidenceService.saveUploadedEvidence(
                bytes,
                originalFilename,
                caseId,
                evidenceType,
                investigatorId,
                trustedReference,
                contentType
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @GetMapping("/evidence")
    public List<EvidenceItemDto> getAllEvidence(@RequestParam(value = "case_id", required = false) String caseId) {
        return evidenceService.listEvidence(caseId);
    }

    @GetMapping("/cases/{caseId}/evidence")
    public List<EvidenceItemDto> getEvidenceForCase(@PathVariable("caseId") String caseId) {
        return evidenceService.listEvidence(caseId);
    }

    @GetMapping("/evidence/{evidenceId}")
    public EvidenceItemDto getSingleEvidence(@PathVariable("evidenceId") String evidenceId) {
        return evidenceService.getEvidenceById(evidenceId);
    }

    @PostMapping("/evidence/{evidenceId}/reference")
    public EvidenceItemDto updateReferenceHash(
            @PathVariable("evidenceId") String evidenceId,
            @Valid @RequestBody SetReferenceRequest payload
    ) {
        return evidenceService.setTrustedReference(evidenceId, payload.getReferenceHash(), payload.getActorId());
    }

    @PostMapping("/evidence/{evidenceId}/verify")
    public VerificationResultDto verifySingleEvidence(
            @PathVariable("evidenceId") String evidenceId,
            @RequestBody(required = false) VerifyRequest payload
    ) {
        String actor = (payload != null && payload.getActorId() != null) ? payload.getActorId() : "Forensic_Investigator";
        return evidenceService.verifyEvidence(evidenceId, actor);
    }

    @PostMapping("/evidence/verify-all")
    public List<VerificationResultDto> verifyAll(
            @RequestParam(value = "case_id", required = false) String caseId,
            @RequestParam(value = "actor_id", defaultValue = "Forensic_Investigator") String actorId
    ) {
        return evidenceService.verifyAllEvidence(caseId, actorId);
    }

    @GetMapping("/evidence/{evidenceId}/history")
    public AuditHistoryResponse getEvidenceAuditHistory(@PathVariable("evidenceId") String evidenceId) {
        return evidenceService.getAuditHistory(evidenceId);
    }
}
