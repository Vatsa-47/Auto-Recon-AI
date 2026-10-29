package com.autorecon.ai.repository;

import com.autorecon.ai.entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    List<AuditLog> findByEvidenceIdOrderByIdAsc(String evidenceId);

    Optional<AuditLog> findTopByEvidenceIdOrderByIdDesc(String evidenceId);

    Optional<AuditLog> findTopByOrderByIdDesc();
}
