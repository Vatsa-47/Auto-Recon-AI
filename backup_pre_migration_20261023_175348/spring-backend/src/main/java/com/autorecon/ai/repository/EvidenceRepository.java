package com.autorecon.ai.repository;

import com.autorecon.ai.entity.Evidence;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface EvidenceRepository extends JpaRepository<Evidence, String> {

    List<Evidence> findAllByOrderByUploadedAtDesc();

    List<Evidence> findByCaseIdOrderByUploadedAtDesc(String caseId);
}
