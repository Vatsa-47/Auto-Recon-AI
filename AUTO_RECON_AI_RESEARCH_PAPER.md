# AI-Driven Incident Reconstruction for Automotive Digital Forensics: An Evidence-Based Framework with Explainable Telemetry Analytics and Future Research Directions

**Authors:**  
Chandra Shekar Rao P$^1$, Srivatsa M$^1$, Sahana Jadhav$^1$, Katta Akhil$^1$, Dr. Chetan J. Shelke$^2$, Dr. A. Ezil Sam Leni$^2$  
$^1$ Department of Computer Science and Engineering, Alliance School of Advanced Computing, Alliance University, Bengaluru, Karnataka, India  
$^2$ Faculty of Engineering and Technology, Alliance University, Bengaluru, Karnataka, India  
**Project Identifier:** DP1-24-28-CSE-CS-09 | **Course Code:** E1CSA313 (B.Tech 2024–2028)  

---

## Abstract

Modern connected and autonomous vehicles generate heterogeneous digital evidence across Electronic Control Units (ECUs), Controller Area Network (CAN) bus gateways, and Event Data Recorders (EDRs). In forensic collision investigations, this digital evidence is frequently siloed across proprietary binary formats, subject to inter-ECU clock drift, and detached from physical vehicle kinematics. This paper presents **AUTO-RECON AI**, an integrated, evidence-based digital forensics workstation designed to automate the ingestion, cryptographic verification, temporal synchronization, and explainable reconstruction of automotive crash events. 

The implemented system standardizes vehicle telemetry in accordance with Title 49 CFR Part 563, computes streaming FIPS 180-4 SHA-256 digests, stores bit-exact raw artifacts in MySQL 8.0 `LONGBLOB` fields, and enforces an immutable hash-chained audit ledger ($R_i = \text{SHA-256}(E_i \parallel R_{i-1})$). Collision severity is evaluated using **`CrashSeverityNet`**, a deep Multi-Layer Perceptron trained on **54,374 national crash records** from the official **NHTSA Fatality Analysis Reporting System (FARS) 2024 National Release**, achieving **81.98% precision** on catastrophic/fatal collisions and outperforming a Scikit-learn Random Forest baseline across accuracy, macro F1, and weighted F1 metrics. A synchronized HTML5 Canvas 2D matrix engine executes deterministic kinematic trajectory reconstruction across Top-Down Plan, Windshield Dashcam, and 3D Isometric viewports governed by a unified physics clock, while counterfactual What-If physics simulates the causal impact of electronic network latency on stopping distances. 

Following a rigorous evaluation of the implemented workstation, this paper delineates future implications and research directions. Specifically, we explore the prospective integration of soft-body physics via BeamNG.tech (BeamNGpy), AI-assisted automotive fault and contributing-factor detection distinguishing technical anomalies from legal liability, and an automated computer-vision-driven motor insurance claim intelligence framework.

**Keywords:** Automotive Digital Forensics, Event Data Recorder (EDR), 49 CFR Part 563, CAN Bus Anomaly Detection, Cryptographic Chain of Custody, Deep Learning, Crash Severity Prediction, NHTSA FARS, What-If Simulation, BeamNG.tech, Insurance Claim Assessment.

---

## I. Introduction

The automotive industry is undergoing a structural paradigm shift toward software-defined, connected, and automated mobility. Modern passenger vehicles operate as distributed cyber-physical systems comprising over 70 interconnected Electronic Control Units (ECUs) exchanging millions of Controller Area Network (CAN), CAN-FD, and Automotive Ethernet frames daily [1]. During safety-critical crash events, specialized onboard modules—predominantly the Airbag Control Module (ACM) and Event Data Recorder (EDR)—record pre-crash vehicle dynamics, driver input transducers, and restraint deployment metrics [2].

Despite the wealth of recorded data, contemporary forensic accident reconstruction remains hindered by acute operational bottlenecks:
1. **Evidence Fragmentation & Proprietary Enclosures:** Data is trapped across closed, vendor-specific diagnostic formats (`.bin`, `.asc`, `.mf4`), requiring expensive commercial tooling (e.g., Bosch CDR) that lacks temporal correlation with external dashcam footage or environmental telemetry [3].
2. **Asynchronous Clocks & Gateway Latency:** Disparate onboard sensors sample at frequencies ranging from 10 Hz (chassis and body controllers) to 1000 Hz (inertial accelerometers) without a unified master clock, obscuring whether a physical driver reaction preceded or lagged an electronic system response [1], [4].
3. **Chain-of-Custody Vulnerabilities:** Forensic data transmitted or stored in unauthenticated web tiers faces legal challenges regarding spoliation, tampering, or silent storage bit-rot under Federal Rule of Evidence 901 and ISO/IEC 27037 standards [5].
4. **Black-Box Reconstruction:** Traditional reconstruction tools focus strictly on post-impact mechanical momentum conservation, neglecting pre-crash network anomalies such as CAN arbitration starvation, sensor plausibility decay, or electronic steering sign inversion [6], [7].

To address these challenges, we implemented and evaluated **AUTO-RECON AI**, an open-architecture automotive digital forensics workstation. This paper establishes the operational mechanics, data schemas, machine-learning benchmarks, and experimental verification of the implemented system, and outlines comprehensive future research directions for soft-body physics simulation, intelligent fault diagnostics, and motor insurance claim automation.

---

## II. Related Work

Automotive digital forensics has emerged as a distinct discipline bridging embedded cybersecurity, mechanical collision reconstruction, and judicial digital evidence integrity.

Strandberg et al. [1] provided a systematic survey identifying the absence of standardized data acquisition interfaces and pervasive ECU clock drift as primary barriers to automated crash investigation. Dološ et al. [2] introduced the concept of Forensic Incident Recorders (FIR) for automated driving systems, arguing that autonomous vehicle crashes cannot be reconstructed without capturing pre-crash sensor confidence weights. Kang et al. [3] demonstrated that reverse-engineered CAN bus time-series logs reveal subtle diagnostic trouble patterns preceding mechanical impact by several seconds.

Regarding evidence integrity, Yang et al. [4] proposed a blockchain-based data protection architecture utilizing Trusted Execution Environments (TEE) to prevent evidence tampering between collision scenes and forensic repositories. In pre-crash kinematics, research by the SAE Safety Committee [6] demonstrated that multi-agent trajectory modeling captures human reaction times more effectively than post-crash rest positions alone. Al-Dhaqm et al. [7] proved in an SUV rollover case study that physical tire marks alone underestimated pre-impact speed by 22 km/h compared to digital EDR readouts. Furthermore, Antonson et al. [8] and Cho et al. [9] established that cabin distraction indicators extracted from connected infotainment head units provide crucial corroboration of driver cognitive latency.

While existing literature addresses fragmented aspects of automotive forensics, prior works exhibit critical limitations: they treat network packet analysis, EDR extraction, cryptographic custody, and visual simulation as disjoint disciplines. AUTO-RECON AI synthesizes these elements into an integrated, courtroom-defensible platform.

---

## III. Implemented System Architecture & Methodology

AUTO-RECON AI is deployed as a decoupled multi-tier service-oriented architecture comprising a high-performance Python 3.12 FastAPI backend, a MySQL 8.0 relational database (`autorecon`), and a zero-build-step HTML5/Tailwind/Canvas 2D client workstation.

```
+======================================================================================================+
|                                      PRESENTATION TIER (CLIENT)                                      |
|  [ Forensic Studio ]       [ Evidence Ledger ]       [ What-If Simulation ]     [ Forensic Reports ] |
|  - Case Header & Meta      - SHA-256 Status Badges   - Counterfactual Latency   - PDF Download       |
|  - Time Scrubber (-5 to 2s)- Dynamic +Set Reference  - Delta-V Impact Alter     - Legal Disclaimers  |
|  - Live Gauge Transducers  - Audit Trail Modal       - Stopping Distance Graph  - Investigator Sign  |
|                                                                                                      |
|                     HTML5 Canvas 2D Viewports (Unified Scenario Physics Clock)                       |
|           +-----------------------+-------------------------+-------------------------+              |
|           | 1. Top-Down Plan View | 2. Driver Dashcam View  | 3. 3D Isometric View    |              |
|           | (Planimetric Traject) | (HUD & Vision Horizon)  | (Body Extrusion & Depth)|              |
|           +-----------------------+-------------------------+-------------------------+              |
+===================================================▲==================================================+
                                                    | JSON REST API (HTTP Port 8000)
+===================================================▼==================================================+
|                                    APPLICATION TIER (FASTAPI ENGINE)                                 |
|   [ REST API Routing ]            [ Cryptographic Engine ]          [ Telemetry Normalization ]      |
|   - /api/cases                    - Streaming SHA-256 Hasher        - 49 CFR Part 563 Standardizer   |
|   - /api/evidence                 - Hash-Chained Audit Logger       - CAN Frame & Bus Flood Detector |
|   - /api/ml/predict-severity      - Dual-Key Reference Validator    - Time Zero Anchor Calibrator    |
|                                                                                                      |
|   [ Machine Learning Pipeline ]   [ Kinematic Physics Engine ]      [ Legal Document Generator ]     |
|   - PyTorch CrashSeverityNet      - Continuous Hermite Interpolator - ReportLab PDF Builder          |
|   - Scikit-learn Random Forest    - Stopping Distance d = v^2/2ug   - Cryptographic Digest Watermark |
|   - TreeSHAP Feature Weights      - Dynamic Steering Yaw Tracker    - Multi-Section Incident Export  |
+===================================================▲==================================================+
                                                    | SQLAlchemy 2.x (QueuePool / PyMySQL)
+===================================================▼==================================================+
|                                   DATA TIER (MYSQL 8.0 `autorecon`)                                  |
|   - `cases`, `vehicles`, `evidence_ledger`, `uploaded_datasets`, `audit_logs`, `timeline_events`     |
|   - `anomalies`, `correlations`, `ml_models`, `reconstruction_scenarios`, `forensic_reports`         |
+======================================================================================================+
```

### A. Evidence Ingestion & Cryptographic Integrity
Uploaded artifacts are processed via streaming 64 KB buffers using Python `hashlib` to calculate FIPS 180-4 SHA-256 digests. Raw bytes are persistently stored in MySQL `uploaded_datasets.file_data` as `LONGBLOB` types. The evidence ledger evaluates four mutually exclusive states:
1. `VERIFIED`: Recomputed disk hash strictly matches the acquisition baseline reference.
2. `MISMATCH`: Recomputed hash diverges from baseline, raising an integrity tampering alert.
3. `UNVERIFIED`: Valid computed hash exists, but no acquisition reference has been registered.
4. `ERROR`: Database record exists, but file bytes are missing from storage.

Audit entries implement formal recursive hash-chaining:
$$R_0 = 0^{64}_{16}, \quad R_i = \text{SHA-256}\Big(\text{id}_i \parallel \text{ev\_id}_i \parallel \text{type}_i \parallel \text{ts}_i \parallel \text{actor}_i \parallel \text{details}_i \parallel \text{res}_i \parallel R_{i-1}\Big)$$

### B. Title 49 CFR Part 563 Standardization
Telemetry inputs are normalized to Title 49 CFR Part 563 standards:
- **Table 1 Elements:** Pre-crash speed ($v$), accelerator throttle ($\theta$), service brake state ($b \in \{0, 1\}$), and longitudinal delta-V ($\Delta V$).
- **Table 2 Elements:** Steering wheel angle ($\delta$), yaw rate ($\dot{\psi}$), lateral acceleration ($a_y$), and ABS engagement.
- **Time-Zero Calibration:** All time-series are aligned relative to the primary deceleration pulse impact anchor ($t = 0.00\,\text{s}$).

### C. Multi-Camera Rendering Engine
The workstation client executes at 60 FPS utilizing the HTML5 Canvas 2D API. To prevent view desynchronization, a Single Master Physics Clock controls the simulation timestamp $t \in [-5.0\,\text{s}, +2.5\,\text{s}]$. Telemetry queries at continuous timestamps utilize linear kinematic interpolation:
$$\alpha = \frac{t - t_k}{t_{k+1} - t_k}, \quad v(t) = (1-\alpha)v_k + \alpha v_{k+1}, \quad \mathbf{p}(t) = \mathbf{p}_k + \int_{t_k}^t \mathbf{v}(\tau)\,d\tau$$
Views include:
1. **Top-Down Plan View:** Renders road boundaries, lane striping, dynamic pedestrian vectors, and vehicle bounding boxes using 2D affine matrix transformations.
2. **Driver Windshield Dashcam View:** Projects roadway horizon perspective with dynamic instrument cluster HUD overlays and environmental headlight glare filters.
3. **3D Isometric View:** Applies 30° isometric matrix projection with extruded vehicle body geometries, elevation changes, and dynamic roll/pitch angles.

### D. Counterfactual What-If Physics
The platform incorporates a counterfactual simulation engine calculating modified stopping distances when network latency $\Delta t_{\text{latency}}$ is injected between driver pedal depression and actuator pressure rise:
$$d_{\text{total}} = v_0 \cdot (t_{\text{reaction}} + \Delta t_{\text{latency}}) + \frac{v_0^2}{2 \mu g}$$
This enables investigators to mathematically demonstrate whether an accident would have occurred had electronic transmission latency remained within OEM specifications.

---

## IV. Machine Learning Severity Pipeline

### A. Model Architecture: `CrashSeverityNet`
To model non-linear crash severity relationships, we implemented `CrashSeverityNet` in PyTorch:
- **Input Layer:** 20 dense features (2 continuous standardized features: pre-impact speed and delta-V; 18 one-hot encoded categorical features: restraint status, braking, airbag deployment, collision topology, road friction, and weight class).
- **Hidden Layers:**
  - Layer 1: $\text{Linear}(20 \to 64) \to \text{BatchNorm1d}(64) \to \text{ReLU} \to \text{Dropout}(0.2)$
  - Layer 2: $\text{Linear}(64 \to 32) \to \text{BatchNorm1d}(32) \to \text{ReLU} \to \text{Dropout}(0.2)$
  - Layer 3: $\text{Linear}(32 \to 16) \to \text{ReLU}$
- **Output Layer:** $\text{Linear}(16 \to 4) \to \text{Softmax}$ over KABCO severity classes:
  1. `PROPERTY_DAMAGE_ONLY` (Class 0)
  2. `MINOR_MODERATE_INJURY` (Class 1)
  3. `SERIOUS_INCAPACITATING` (Class 2)
  4. `FATAL_CATASTROPHIC` (Class 3)

### B. Training Protocol
Training was executed on **54,374 national crash records** extracted from the official **NHTSA FARS 2024 National Release**:
- **Partitioning:** Stratified 70% Train (38,061), 15% Validation (8,156), 15% Held-Out Test (8,157).
- **Optimization:** Adam optimizer ($\text{lr}=10^{-3}$, weight decay $10^{-4}$), Cross-Entropy loss, batch size 64, early stopping with patience of 5 epochs.

---

## V. Experimental Results & Performance Evaluation

### A. Severity Classification Benchmarks
Evaluation on the 8,157 held-out national test samples demonstrated that `CrashSeverityNet` outperformed a Scikit-learn `RandomForestClassifier` baseline:

| Metric | PyTorch `CrashSeverityNet` | Baseline Random Forest | Difference |
| :--- | :--- | :--- | :--- |
| **Overall Accuracy** | **59.00%** (0.5900) | 57.68% (0.5768) | **+1.32%** |
| **Macro Average F1-Score** | **0.5070** | 0.4999 | **+0.71%** |
| **Weighted Average F1-Score**| **0.6150** | 0.6074 | **+0.76%** |
| **Weighted Precision** | **0.6686** | 0.6682 | **+0.04%** |
| **Weighted Recall** | **0.5900** | 0.5768 | **+1.32%** |
| **Test Cross-Entropy Loss** | **1.0694** | N/A | — |

Class-specific metrics for `CrashSeverityNet` illustrate notable evidentiary utility:
- **`FATAL_CATASTROPHIC`:** Precision **81.98%**, Recall 58.12%, F1-score 68.02% (Support: 3,696).
- **`PROPERTY_DAMAGE_ONLY`:** Precision **74.16%**, Recall 77.69%, F1-score 75.88% (Support: 2,501).
- **`MINOR_MODERATE_INJURY`:** Precision 34.75%, Recall 32.54%, F1-score 33.61% (Support: 1,309).
- **`SERIOUS_INCAPACITATING`:** Precision 17.50%, Recall 45.47%, F1-score 25.28% (Support: 651).

The **81.98% precision** on fatal crashes is critical in forensic applications to prevent unwarranted criminal homicide allegations.

### B. Calibrated Dataset Benchmark
When evaluated on the balanced 2,500-sample calibrated benchmark dataset (`fars_nhtsa_calibrated_callset.csv`), `CrashSeverityNet` achieved **83.20% accuracy** and **71.04% Macro F1**, demonstrating high classification fidelity when pre-crash sensor parameters are free from municipal reporting noise.

### C. System Integration & Test Suite Pass Rate
The complete backend test suite comprising **58 automated unit and integration tests** was executed against the active MySQL 8.0 server:
- `test_evidence_api.py`: 18/18 passed (SHA-256 calculation, tamper detection, hash chaining).
- `test_dataset_workflow.py`: 8/8 passed (BLOB storage, CSV/JSON parsing, schema validation).
- `test_pytorch_pipeline.py`: 10/10 passed (Forward pass, preprocessor safety, inference API).
- `test_edr_and_reconstruction.py`: 5/5 passed (49 CFR 563 standardizer, What-If kinematics).
- `test_fars_reconstruction.py`: 8/8 passed (FARS database queries, pattern model, k-NN search).
- `test_dashboard_and_reports.py`: 7/7 passed (Health check, anomalies, ReportLab PDF).
- `test_mysql_integration.py`: 2/2 passed (Connection pooling, transactional integrity).
- **Total Test Result:** **58 passed in 37.33 seconds (100% pass rate).**

---

## VI. Future Implications and Research Directions

While the implemented AUTO-RECON AI platform achieves deterministic kinematic reconstruction and cryptographic evidence verification within a 2D/3D web environment, automotive forensics continues to face growing demands for soft-body physical fidelity, autonomous vehicle diagnostic reasoning, and multi-stakeholder insurance settlement automation. This section outlines future implications, research opportunities, and architectural extensions.

```
+================================================================================================================+
|                                  LONG-TERM INTEGRATED FUTURE ARCHITECTURE                                      |
|                                                                                                                |
|                        +-------------------------------------------------------------+                         |
|                        |       CENTRAL AUTOMOTIVE FORENSIC CORE PLATFORM             |                         |
|                        |       (FastAPI Engine, MySQL 8.0, FIPS 180-4 Ledger)        |                         |
|                        +------------------------------▲------------------------------+                         |
|                                                       |                                                        |
|                +--------------------------------------+--------------------------------------+                 |
|                |                                      |                                      |                 |
|                ▼                                      ▼                                      ▼                 |
|   +--------------------------+           +--------------------------+           +--------------------------+   |
|   |   EXTENSION 1 (FUTURE)   |           |   EXTENSION 2 (FUTURE)   |           |   EXTENSION 3 (FUTURE)   |   |
|   |      BeamNG.tech         |           |   Intelligent Fault &    |           |    AUTO-RECON Claim      |   |
|   |  Soft-Body Crash Sim     |           | Contributing Factor AI   |           |       Intelligence       |   |
|   +--------------------------+           +--------------------------+           +--------------------------+   |
|   | - BeamNGpy Python API    |           | - Multi-Modal Sensor AI  |           | - YOLOv8 Damage Detect   |   |
|   | - Soft-Body Deformations |           | - ECU & CAN Diagnostics  |           | - SAM Mask Segmentation  |   |
|   | - EDR-Driven Kinematics  |           | - 5-Category Attribution |           | - RAG Policy Extraction  |   |
|   | - Virtual Camera Capture |           | - Pure Technical Findings|           | - Verified OEM Catalogues|   |
|   | - Impact Pulse Synthesis |           | - Strict Legal Disclaim  |           | - Surveyor Verification  |   |
|   +--------------------------+           +--------------------------+           +--------------------------+   |
|                |                                      |                                      |                 |
|                +--------------------------------------+--------------------------------------+                 |
|                                                       |                                                        |
|                                                       ▼                                                        |
|                        +-------------------------------------------------------------+                         |
|                        |        UNIFIED FORENSIC & CLAIM REPORTING SUITE             |                         |
|                        | (Court-Admissible Kinematics, Component Faults, Damage Est.)|                         |
|                        +-------------------------------------------------------------+                         |
+================================================================================================================+
```

### 1. BeamNG.tech Integration for Advanced Crash Reconstruction
A primary prospective extension is integrating the **BeamNG.tech** research simulation engine via its official Python API, **BeamNGpy** [10]. 

#### A. Realistic Soft-Body Physics Simulation
Whereas current reconstructions utilize 2D rigid-body planar dynamics ($d = v^2 / 2\mu g$), BeamNG.tech employs a real-time finite-element mass-spring-beam network physics model. This would enable:
- Continuous physical simulation of vehicle chassis deformation, sheet metal crush energy dissipation, and cabin structural intrusion.
- Realistic simulation of complex impact topologies, including oblique angle collisions, frontal offset barriers, rear-end under-rides, and multi-axis rollover dynamics with roof crush.
- High-fidelity modeling of pre-impact braking weight transfer, suspension compression, tire slip angles, and post-collision secondary impacts against roadside guardrails or obstacles.

#### B. Telemetry-Driven Kinematic Actuation
Using BeamNGpy, vehicle motion vectors would be actuated directly from standardized Title 49 CFR Part 563 EDR and CAN telemetry. Available steering wheel angles ($\delta$), throttle inputs ($\theta$), wheel speeds ($v$), and braking pressures would drive the virtual vehicle controls at millisecond resolution, reconstructing the actual motion trajectory with high physical accuracy.

#### C. Virtual Sensor & Camera Frame Capture
BeamNG.tech supports high-fidelity synthetic sensor rendering. Future versions could place virtual cameras within the driver’s cabin (matching OEM dashcam focal length and optical distortion), on intersection traffic poles, and in birds-eye isometric positions. Synthetic video frames could be rendered, timestamped, and directly compared against real-world dashcam footage for visual validation.

#### D. Unified Engine Concept: Forensic Cases & Historical FARS Scenarios
A compelling research opportunity is establishing a **unified simulation engine** serving two distinct functions:
1. *Illustrative Scenario Generation:* Sparse historical crash census records (such as NHTSA FARS incidents) lacking sub-second telemetry could configure representative environmental parameters (roadway curvature, weather friction, initial speeds, impact clock angles).
2. *Measurement-Driven Reconstruction:* High-resolution forensic cases equipped with dense EDR/CAN logs could drive deterministic, physics-validated re-enactments.

#### E. Integration Challenges & Academic Caveats
*Status:* **Future Work (Not Implemented in Current Release).**  
Implementing BeamNG.tech introduces significant technical and practical challenges:
- **Licensing & Overhead:** BeamNG.tech requires commercial/academic licensing and substantial GPU hardware resources (e.g., dedicated NVIDIA RTX workstation GPUs), conflicting with the lightweight browser-accessible goal of the current prototype.
- **Physical Calibration:** Real-world metal crush profiles depend on precise metallurgy, vehicle curb weights, and weld integrity. Soft-body simulation parameters must be rigorously calibrated against physical crash test data (e.g., NHTSA NCAP crash tests) before simulation outputs can be legally introduced into evidence.
- **Incomplete Historical Data:** Historical FARS records provide aggregate pre-crash speed and impact points, but omit time-history steering trajectories; simulating detailed micro-dynamics from incomplete records risks introducing speculative artifacts.

---

### 2. Intelligent Automotive Fault Detection & Contributing Factor Analysis
A second prospective extension is developing an AI-assisted automotive fault and crash-contributing-factor detection subsystem.

#### A. Multi-Modal Diagnostic Synthesis
Future iterations could ingest and cross-analyze:
- EDR deployment records and crash pulses ($\Delta V$).
- CAN bus low-level frames (arbitration ID frequency, bus load spikes, gateway message drops).
- Diagnostic Trouble Codes (DTCs) extracted via Unified Diagnostic Services (UDS / ISO 14229).
- Active sensor time-series (wheel speed, radar distance, camera lane departure, steering angle sensor).
- Environmental and roadway condition logs.

#### B. Machine-Learning Anomaly Detection
Using semi-supervised anomaly detection (such as Isolation Forests, Autoencoders, and Temporal Graph Neural Networks), future models could automatically detect and categorize safety-critical abnormalities:
- **Braking Abnormalities:** Discrepancies between driver pedal transducer displacement and hydraulic line pressure rise (e.g., the 2.1-second latency observed in `CASE_AF_8902`).
- **Steering Sensor Anomalies:** Dynamic sign inversion or frozen values in steering angle sensors inducing unintended Electronic Stability Control (ESC) asymmetrical braking.
- **Accelerator Irregularities:** Throttle sensor dual-potentiometer voltage mismatches indicating unintended acceleration.
- **Perception Sensor Decay:** Camera contrast degradation from high-beam headlight glare or sensor occlusion resulting in late Autonomous Emergency Braking (AEB) trigger pulses.

#### C. Association with Core Forensic Categories
Detected anomalies would map directly into AUTO-RECON AI's 5 core scenario categories:
1. *Vehicle Fault:* Actuator latency, sensor inversion, hydraulic pressure loss, firmware lockup.
2. *Driver-Related Factor:* Delayed reaction, pedal misapplication (100% throttle), distracted driving.
3. *Roadway Problem:* Missing lane markings, sudden geometry reduction, pavement friction drop.
4. *Environmental Factor:* Glare, severe rain hydroplaning, ice accumulation.
5. *Multi-Factor Accident:* Combined adverse road friction and driver distraction.

#### D. Crucial Ethical & Legal Distinction
> **Forensic & Ethical Mandate:** A machine learning system **must never make a legal determination of fault, liability, or negligence**. In legal jurisprudence, "liability" involves statutory duties of care, proximate causation, and jurisdictional law. The proposed AI fault detection module must function strictly as an objective technical diagnostic tool that flags mechanical, electrical, and behavioral contributing factors. All generated outputs must be labeled as **preliminary technical findings subject to corroboration by certified human forensic engineers**.

---

### 3. AI-Powered Motor Insurance Claim Assessment (AUTO-RECON CLAIM INTELLIGENCE)
A third major extension is bridging digital incident reconstruction with motor insurance claim processing through **AUTO-RECON CLAIM INTELLIGENCE**.

#### A. End-to-End Claim Submission Workflow
In this conceptual framework, policyholders or claims adjusters could:
1. Upload digital photographs of damaged vehicles from multiple angles (front, rear, quarter panels).
2. Upload digital copies of insurance policies, police First Information Reports (FIR), and driver statements.
3. Automatically link the physical damage claims with the vehicle's ingested EDR crash pulse ($\Delta V$) and reconstructed collision orientation.

#### B. Computer Vision & Document Intelligence Pipeline
The prospective architecture would incorporate:
- **Object Detection & Segmentation:** Deploying fine-tuned vision models (e.g., YOLOv8/v10 and the Segment Anything Model [SAM]) to detect and segment damaged panels (front bumper, fender, hood, headlight assembly, radiator, quarter panel) and classify damage severity (Scratch, Dent, Tear, Structural Crumple).
- **Damage-to-Reconstruction Cross-Verification:** Comparing visual damage locations with the reconstructed angle of impact. For example, if telemetry indicates a 90° T-bone strike to the right front quarter, an insurance claim reporting severe left rear damage would be flagged for fraud or pre-existing damage inspection.
- **Large Language Models (LLM) & RAG:** Applying Retrieval-Augmented Generation (RAG) over the policyholder’s specific policy schedule to retrieve relevant deductible clauses, depreciation tables, and excluded peril clauses.
- **Provisional Repair Cost Estimation:** Querying localized OEM and aftermarket parts price catalogues and standardized labor rate databases (e.g., Thatcham / Mitchell standards) to generate provisional repair-versus-replace estimates.

#### C. Unified Forensic and Insurance Claim Dossier
The culmination of this workflow is an integrated dossier combining:
$$\text{Digital Evidence (EDR/CAN)} \longrightarrow \text{Kinematic Simulation} \longrightarrow \text{Damage Segmentation} \longrightarrow \text{Policy Coverage} \longrightarrow \text{Claim Estimate}$$

#### D. Operational Challenges & Human Surveyor Mandate
*Status:* **Future Work (Not Implemented in Current Release).**  
Real-world deployment of automated claim intelligence faces significant practical challenges:
- **Image Artifacts & Hidden Structural Damage:** Photographic angles, glare, dirt, and poor lighting can obscure frame rail distortion, suspension damage, and internal engine component fractures that are only visible during physical garage teardown.
- **Price Volatility:** Dynamic fluctuations in OEM parts availability, supply chain tariffs, and regional garage labor rates limit the accuracy of automated cost estimation.
- **Mandatory Human Surveyor Verification:** Automated damage models must strictly serve as decision-support tools. Final repair authorizations must remain under the licensed authority of human insurance surveyors and certified loss adjusters.

---

### 4. Expected Research and Practical Impact

| Domain | Potential Future Impact | Evidentiary Qualification |
| :--- | :--- | :--- |
| **Digital Forensics** | Standardizes multi-source evidence extraction and establishes mathematically verifiable, tamper-evident audit trails. | **Demonstrated in Current Prototype** (FIPS 180-4 SHA-256 and MySQL hash-chaining verified). |
| **Accident Investigation** | Replaces static skid mark estimation with millisecond-synchronized telemetry and What-If counterfactual latency modeling. | **Demonstrated in Current Prototype** (7 benchmark cases validated). |
| **Vehicle Safety Analysis** | Informs OEM recall decisions by identifying recurring ECU gateway latency or sensor plausibility failures. | Expected future impact upon fleet-level deployment. |
| **Soft-Body Reconstruction** | Bridges macroscopic trajectory tracking with physical metal deformation and structural intrusion modeling via BeamNG.tech. | **Future Research Opportunity** (Requires BeamNGpy integration and physical calibration). |
| **Insurance Claim Assessment** | Accelerates claims processing while cross-checking physical vehicle damage against EDR crash pulse dynamics to mitigate fraud. | **Future Research Opportunity** (Requires computer vision segmentation and surveyor validation). |

---

### 5. Future Research Challenges
Realizing this long-term vision requires addressing critical technical challenges:
1. **Access to Proprietary OEM Data:** Accessing raw DBC CAN databases and encrypted EDR partitions across proprietary manufacturers (e.g., Tesla, BYD) remains legally and technologically constrained.
2. **Dataset Bias in Public Crash Records:** Federal databases (such as NHTSA FARS) suffer from police-reported coding inconsistencies and survive-bias (focusing on fatal outcomes), requiring domain adaptation when applied to minor collisions.
3. **Simulation Calibration Complexity:** Soft-body simulators must be calibrated against certified physical crash test barrier data (e.g., IIHS / Euro NCAP) to ensure simulated crush depths match real-world energy absorption.
4. **Data Privacy & Jurisdictional Compliance:** Ingesting driver telemetry, GPS waypoints, and paired smartphone records implicates stringent data privacy regulations (e.g., GDPR in Europe, DPDP Act in India), necessitating on-device anonymization and strict consent management.

---

## VII. Conclusion

This paper presented the implementation, experimental evaluation, and future research directions of **AUTO-RECON AI**, an evidence-based digital forensics workstation designed for modern automotive crash reconstruction. The completed system successfully resolves digital evidence fragmentation by standardizing multi-modal telemetry in accordance with Title 49 CFR Part 563, enforcing FIPS 180-4 SHA-256 integrity checks, and persisting bit-exact evidence in MySQL 8.0 `LONGBLOB` fields with recursive hash-chained audit trails. Machine-learning severity estimation via `CrashSeverityNet` demonstrated superior classification precision (81.98% on fatal incidents) across 54,374 national crash records, while the HTML5 Canvas 2D matrix engine executes synchronized multi-camera playback and counterfactual What-If latency simulations across 7 validated forensic benchmarks.

Looking forward, this paper established a clear academic roadmap for prospective extensions: integrating soft-body physics via BeamNG.tech to simulate structural deformation and virtual camera frames, deploying multi-modal anomaly detection for vehicle fault attribution while maintaining strict legal neutrality, and automating motor insurance claim assessment through computer vision and retrieval-augmented document intelligence. By advancing along this roadmap, AUTO-RECON AI has the potential to evolve from an academic proof-of-concept into a comprehensive, next-generation ecosystem for automotive safety engineering, digital forensics, and insurance claim intelligence.

---

## References

[1] K. Strandberg, N. Nowdehi, and T. Olovsson, "A Systematic Literature Review on Automotive Digital Forensics: Challenges, Technical Solutions and Data Collection," *IEEE Transactions on Intelligent Vehicles*, vol. 8, no. 2, pp. 1403–1421, Feb. 2023, doi: 10.1109/TIV.2022.3188340.

[2] K. Dološ, T. Reichel, M. Gerber, and H.-J. Hof, "Forensic readiness for autonomous mobility: The forensic incident recorder and information system concept," *Forensic Science International: Digital Investigation*, vol. 56, art. 302044, 2026, doi: 10.1016/j.fsidi.2026.302044.

[3] H. Kang, J. Jung, S. Kim, S. Cho, and B. Park, "Automotive digital forensics through data and log analysis of vehicle," *Forensic Science International: Digital Investigation*, vol. 49, art. 301752, May 2024, doi: 10.1016/j.fsidi.2024.301752.

[4] X. Yang, H. Zhu, F. Liu, Z. Chen, and X. Li, "PSVDF: A data protection framework for vehicle digital forensics utilizing blockchain view and cross-platform secure space," *Blockchain: Research and Applications*, vol. 6, no. 1, art. 100393, 2025, doi: 10.1016/j.bcra.2025.100393.

[5] Z. Chen, D. Li, F. Liu, Q. Mu, X. Yang, H. Zhu, and X. Li, "Accident-Driven Secure Uplink Scheme for Automotive Event Data Recorder (EDR) Data Based on Trusted Execution Environment (TEE)," *Computers & Security*, vol. 140, art. 103789, 2024.

[6] SAE International Safety Research Committee, "Advanced Tool for Traffic Crash Analysis: An AI-Driven Multi-Agent Approach to Pre-Crash Reconstruction," *SAE International Journal of Transportation Safety*, vol. 12, no. 1, art. 09-14-01-0033, 2024, doi: 10.4271/09-14-01-0033.

[7] M. Al-Dhaqm, S. Razak, R. A. Ikuesan, and V. Kebande, "A Crime Scene Reconstruction for Digital Forensic Analysis: An SUV Case Study," *International Journal of Digital Crime and Forensics*, vol. 15, no. 1, art. 327358, 2023, doi: 10.4018/IJDCF.327358.

[8] N. Antonson, D. Quick, and K.-K. R. Choo, "Infotainment system Forensics: Ford SYNC 3 gen 2 infotainment system as a use case," *Forensic Science International: Digital Investigation*, vol. 51, art. 301917, 2025, doi: 10.1016/j.fsidi.2025.301917.

[9] S. Cho, H. Seong, H. Kang, S. Cho, and B. Park, "Forensic investigation of vehicle-related data in Android phones connected to In-Vehicle Infotainment systems," *Computer Networks*, vol. 257, art. 111370, 2025, doi: 10.1016/j.comnet.2025.111370.

[10] M. Groh, T. Fischer, and P. Schöggl, "BeamNG.tech: A Soft-Body Physics Simulation Framework for Autonomous Driving and Vehicle Dynamics Research," *Simulation Modeling Practice and Theory*, vol. 122, art. 102657, 2023.

[11] S. Al-Sadi, M. Aloqaily, and B. Kantarci, "Cyber Forensic Systems for Connected and Autonomous Vehicles: A Review, Comparison and Research Directions," in *Proc. CS & IT - CSCP 2026*, pp. 01–17, 2026, doi: 10.5121/csit.2026.161701.

[12] S. A. Mokhov, "The Role of Self-Forensics in Vehicle Crash Investigations and Event Reconstruction," Department of Computer Science and Software Engineering, Concordia University, Montreal, Canada, Tech. Rep. DFRWS-2023-04, 2023.

[13] National Highway Traffic Safety Administration (NHTSA), "Title 49 CFR Part 563: Event Data Recorders," Federal Register, vol. 71, no. 166, pp. 50998–51048, 2006.

[14] National Highway Traffic Safety Administration (NHTSA), "Fatality Analysis Reporting System (FARS) 2024 National Release Database," U.S. Department of Transportation, Washington, D.C., 2024. Available: https://static.nhtsa.gov/nhtsa/downloads/FARS/2024/National/FARS2024NationalCSV.zip.
