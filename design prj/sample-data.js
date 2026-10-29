/**
 * AUTO-RECON AI - Automotive Digital Forensics Knowledgebase & Demonstration Datasets
 * Designed for forensic engineering analysis, incident reconstruction, and explainable findings.
 * Includes 6 Demonstration Incident Scenarios, Multi-Modal Analysis Components,
 * and Dynamic Forensic Investigator Recommendation Datasets.
 */

// ==========================================================================
// 1. AI + PHYSICS ANALYSIS COMPONENTS
// ==========================================================================
const ANALYSIS_COMPONENTS = {
  "TEMPORAL_ANALYSIS": {
    id: "TEMPORAL_ANALYSIS",
    name: "Temporal Signal Analysis",
    description: "Evaluates microsecond-aligned sequential packet streams across CAN networks and ECU event buffers to identify arbitration delays, message drops, and timing anomalies.",
    method: "Sequence Modeling & Arbitration Timing Inspection"
  },
  "PHYSICS_VALIDATION": {
    id: "PHYSICS_VALIDATION",
    name: "Physics Validation",
    description: "Validates recorded sensor telemetry against Newtonian kinematic constraints (conservation of momentum, tire-road friction coefficient, vehicle mass inertia, and deceleration limits).",
    method: "Kinematic Constraint Verification"
  },
  "SENSOR_FUSION": {
    id: "SENSOR_FUSION",
    name: "Sensor Fusion",
    description: "Cross-references multi-sensor data streams (wheel pulse transducers, IMU accelerometers, GPS positioning, and radar targets) to reconstruct a continuous state trajectory.",
    method: "Extended Kalman Filter State Estimation"
  },
  "EXPLAINABLE_AI": {
    id: "EXPLAINABLE_AI",
    name: "Explainable AI (XAI)",
    description: "Calculates mathematical feature contribution weights for each telemetry channel to provide evidence-grounded rationales for detected anomalies.",
    method: "Shapley Additive Explanations (TreeSHAP)"
  }
};

// ==========================================================================
// 2. 6 DEMONSTRATION INCIDENT SCENARIOS WITH FORENSIC RECOMMENDATIONS
// ==========================================================================
const FORENSIC_CASES = {
  "CASE_AF_8902": {
    id: "AF-8902",
    title: "Urban Intersection — Brake Response Anomaly",
    shortTitle: "1. Urban Intersection — Brake Response Anomaly",
    scenarioType: "Intersection Collision (Timing Anomaly Investigation)",
    primaryDataSources: ["CAN Bus Log", "EDR EEPROM", "Brake Transducers", "Video Flow"],
    vehicleInfo: {
      make: "Apex EV",
      model: "Vortex Sedan",
      year: "2025",
      vin: "1HGCR2F83PA098124",
      ecuFirmware: "v4.12.8-prod",
      edrModule: "Bosch CDR Gen 4"
    },
    incidentTime: "2026-08-14 17:42:19 UTC",
    location: {
      address: "Intersection of Cyber Highway & 4th Avenue",
      lat: 28.613939,
      lng: 77.209021,
      speedLimit: 60,
      roadCondition: "Dry Asphalt, Daylight"
    },
    summary: "Vehicle collided with cross-traffic at 57.8 km/h. Physical driver brake pedal activation was confirmed at t = -3.10s, but hydraulic brake line pressure was delayed by 2.1 seconds on the vehicle network.",
    summaryTags: ["Brake Delay Anomaly", "Driver Input Recorded", "Impact Deceleration Recorded", "Demonstration Case"],
    aiVerdict: {
      primaryCause: "Brake response timing anomaly detected prior to intersection entry",
      confidence: 92.4,
      driverActionVerified: "Telemetry indicates driver depressed brake pedal at t = -3.10s. CAN message transmission for hydraulic brake line pressure reflects an anomalous delay of approximately 2.1 seconds before pressure rise.",
      supportingEvidence: [
        "Brake switch input (EDR Pin 14) transitioned to ACTIVE at t = -3.10s",
        "CAN ID 0x01B0 (hydraulic command) delayed until t = -1.00s",
        "CAN bus load spiked to 94% between t = -3.10s and t = -1.50s",
        "Vehicle deceleration delayed until t = -0.50s, reaching -18.4g at impact"
      ],
      xaiFeatureWeights: [
        { feature: "Brake pedal switch input (Pin 14)", weight: 0.38, impact: "Driver action confirmed" },
        { feature: "Actuator command latency (CAN 0x01B0)", weight: 0.32, impact: "Transmission delay anomaly" },
        { feature: "Wheel speed deceleration curve", weight: 0.18, impact: "Delayed physical braking" },
        { feature: "Radar / camera closing rate", weight: 0.12, impact: "Consistent with collision velocity" }
      ],
      anomalyCount: 3,
      crashTimeSec: 0.00
    },
    investigatorRecommendation: {
      assessment: "CAN/network anomaly",
      assessmentSubtext: "High-priority bus load saturation and delayed actuator command transmission",
      confidence: 92.4,
      summary: "The reconstructed timeline indicates an abnormal vehicle event associated with unusual CAN communication and ECU activity. The available evidence suggests that the incident requires further investigation of the vehicle communication network and affected ECU.",
      whyReasons: [
        "Driver brake switch input (EDR Pin 14) transitioned to ACTIVE at t = -3.10s with 0% accelerator demand, confirming deliberate human stopping intent.",
        "CAN bus load spiked abnormally to 94% between t = -3.10s and t = -1.50s with high-frequency frame sequence (ID 0x0284).",
        "Hydraulic actuator command frame (ID 0x01B0) was delayed on the arbitration bus until t = -1.00s, producing an anomalous 2.1-second transmission latency.",
        "Evidence correlation shows an unambiguous temporal relationship between network contention and lack of vehicle deceleration prior to the 57.8 km/h collision."
      ],
      detectedAnomalies: [
        { time: "t = -3.10s", component: "CAN Bus Arbitration", description: "Bus load spiked to 89% with high-priority frame flooding (ID 0x0284)." },
        { time: "t = -2.50s", component: "Network Traffic", description: "Repetitive payload FF FF FF 00 1B 00 transmitted every 5ms." },
        { time: "t = -1.00s", component: "Brake Actuator ECU", description: "Hydraulic command frame 0x01B0 delayed by 2100ms." },
        { time: "t = 0.00s", component: "EDR Impact Pulse", description: "High-energy intersection collision recorded at -18.4g." }
      ],
      recommendedNextSteps: [
        "Review relevant CAN frames and ECU logs around the detected incident timestamp (t = -5.0s to t = +1.0s) and correlate them with the EDR event.",
        "Identify the transmitting ECU responsible for arbitration ID 0x0284 during the 2.1-second contention window.",
        "Perform bench testing on the hydraulic brake actuator module to inspect command queue buffer handling and arbitration timeout behavior.",
        "Check gateway routing tables and diagnostic event memory for uncommanded diagnostic sessions or bus flooding origin."
      ],
      furtherExaminationEvidence: [
        "High-speed chassis CAN transceiver physical layer logs and terminating resistor integrity",
        "Gateway ECU message routing tables and arbitration priority matrix",
        "Hydraulic brake control module EEPROM fault freeze-frames"
      ],
      limitations: [
        "Raw bit-level oscilloscope analog waveforms were not recorded; analysis relies on decoded timestamped frames.",
        "Cabin microphone recording was unequipped to verify acoustic alert chime timing."
      ]
    },
    stakeholderGuidance: {
      scenarioCategory: "VEHICLE_FAULT",
      categoryLabel: "Vehicle / Car Fault (Braking Subsystem Anomaly)",
      hasSufficientEvidence: true,
      recommendations: [
        {
          causeDetected: "Hydraulic Brake Actuator Latency & CAN Arbitration Delay",
          evidenceLevel: "Confirmed Evidence",
          confidence: 92.4,
          responsibleStakeholder: "VEHICLE MANUFACTURER",
          stakeholderIcon: "fa-industry",
          evidence: "Driver brake switch input (EDR Pin 14) transitioned to ACTIVE at t = -3.10s. CAN command frame 0x01B0 (hydraulic command) was delayed on the arbitration bus until t = -1.00s due to high-priority frame flooding (ID 0x0284), creating an anomalous 2.1-second transmission latency.",
          recommendedAction: "Vehicle manufacturer engineering team should investigate the braking subsystem CAN arbitration priority queue and review gateway buffer timeout thresholds to prevent message starvation."
        },
        {
          causeDetected: "Hydraulic Brake Line Pressure Build Latency",
          evidenceLevel: "Probable Contributing Factor",
          confidence: 88.0,
          responsibleStakeholder: "VEHICLE SERVICE / MAINTENANCE",
          stakeholderIcon: "fa-wrench",
          evidence: "Deceleration was limited to -0.28g until t = -0.50s despite 100 Bar brake pedal application, indicating hydraulic pre-charge delay.",
          recommendedAction: "Authorized service technicians should perform hydraulic brake fluid pressure line tests and inspect actuator valve spool travel for mechanical sticking."
        }
      ],
      incidentResponsibility: {
        primary: {
          factor: "Vehicle communication & actuator anomaly",
          confidenceLevel: "High Confidence (92%)",
          evidenceSummary: "Confirmed CAN message arbitration delay of 2.1 seconds prior to pressure rise."
        },
        secondary: {
          factor: "Cross-traffic vehicle path conflict",
          confidenceLevel: "Probable factor (85%)",
          evidenceSummary: "Target vehicle crossed intersection during signal transition."
        },
        vehicleFault: {
          status: "Confirmed electronic/actuator anomaly detected",
          evidenceSummary: "2.1-second latency between driver pedal command and hydraulic line pressure rise."
        },
        roadEnvironment: {
          status: "Nominal dry road surface",
          evidenceSummary: "No infrastructure defects or pavement irregularities identified."
        },
        decisionSupportNotice: "This assessment represents a technical forensic decision-support indicator based on synchronized EDR, CAN, and kinematic data. It is not a legal verdict."
      }
    },
    evidenceHashes: [
      { source: "EDR EEPROM Dump (.bin)", sha256: "08ff1ff6d740cb5d4860f7f643a970167164ed6e2d3718fc11fffe6f106571d4", size: "4.2 MB", status: "VERIFIED", verifiedBy: "Investigator SHA-256 Ledger" },
      { source: "High-Speed CAN Log (.asc)", sha256: "e0c0415949fb6ac8edd306a34dcae0fbad6020623419af533d1875ef89d402c4", size: "128.5 MB", status: "VERIFIED", verifiedBy: "Investigator SHA-256 Ledger" },
      { source: "Forward Dashcam Stream (.mp4)", sha256: "0df0b8a8eab1ace33cb976565ff5ba3e18eaf7a170568aaa6e66feecb31308c0", size: "482.1 MB", status: "VERIFIED", verifiedBy: "Investigator SHA-256 Ledger" },
      { source: "GPS NMEA & IMU Log (.log)", sha256: "ba53f9baa318bb4d4ba8064721f32296f408c8ec488cd809d9caddb1ed8fbb4e", size: "1.8 MB", status: "VERIFIED", verifiedBy: "Investigator SHA-256 Ledger" }
    ],
    timelineMilestones: [
      { t: -5.0, label: "Approach", desc: "Cruise at 72 km/h", type: "nominal" },
      { t: -3.1, label: "Brake Depressed", desc: "Driver input 82%", type: "action" },
      { t: -1.0, label: "Actuator Latency", desc: "CAN delay 2.1s", type: "anomaly" },
      { t: 0.0, label: "IMPACT", desc: "Collision at 57.8 km/h", type: "impact" },
      { t: 1.5, label: "Final Stop", desc: "Vehicle rest", type: "nominal" }
    ],
    telemetry: [
      { t: -5.0, speed: 72.0, throttle: 48, brake: 0, steer: 1.2, yaw: 0.1, longG: -0.02, abs: false, canLoad: 38, canId: "0x0120", canPayload: "48 00 00 48 01 2A", anomaly: false, notes: "Cruising at steady speed" },
      { t: -4.5, speed: 71.8, throttle: 45, brake: 0, steer: 0.8, yaw: 0.0, longG: -0.03, abs: false, canLoad: 39, canId: "0x0120", canPayload: "45 00 00 47 01 2A", anomaly: false, notes: "Approaching intersection" },
      { t: -4.0, speed: 71.2, throttle: 35, brake: 0, steer: -1.0, yaw: -0.2, longG: -0.05, abs: false, canLoad: 41, canId: "0x0130", canPayload: "23 00 12 00 00 11", anomaly: false, notes: "Driver releases accelerator pedal" },
      { t: -3.5, speed: 70.0, throttle: 0, brake: 0, steer: -1.5, yaw: -0.3, longG: -0.12, abs: false, canLoad: 42, canId: "0x0130", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Accelerator pedal at 0%" },
      { t: -3.1, speed: 69.4, throttle: 0, brake: 82, steer: -4.2, yaw: -0.8, longG: -0.15, abs: false, canLoad: 89, canId: "0x0284", canPayload: "FF FF FF 00 1B 00", anomaly: true, notes: "EVENT: Driver presses brake (82%). CAN bus load rises sharply." },
      { t: -2.5, speed: 68.9, throttle: 0, brake: 88, steer: -8.5, yaw: -1.2, longG: -0.18, abs: false, canLoad: 94, canId: "0x0284", canPayload: "FF FF FF 00 1B 00", anomaly: true, notes: "Brake command delayed; hydraulic pressure remains low." },
      { t: -2.0, speed: 67.5, throttle: 0, brake: 95, steer: -14.0, yaw: -2.1, longG: -0.22, abs: false, canLoad: 92, canId: "0x0284", canPayload: "FF FF FF 00 1B 00", anomaly: true, notes: "Driver applies left steering to evade; deceleration minimal." },
      { t: -1.5, speed: 65.8, throttle: 0, brake: 100, steer: -22.0, yaw: -3.4, longG: -0.28, abs: false, canLoad: 88, canId: "0x0284", canPayload: "FF FF FF 00 1B 00", anomaly: true, notes: "Hydraulic actuator response absent despite pedal depression." },
      { t: -1.0, speed: 63.2, throttle: 0, brake: 100, steer: -30.5, yaw: -4.8, longG: -0.45, abs: false, canLoad: 74, canId: "0x01B0", canPayload: "64 00 58 01 00 00", anomaly: false, notes: "Hydraulic command frame 0x01B0 received by brake module." },
      { t: -0.5, speed: 59.5, throttle: 0, brake: 100, steer: -35.0, yaw: -6.2, longG: -0.85, abs: true, canLoad: 58, canId: "0x01B0", canPayload: "64 00 58 01 00 01", anomaly: false, notes: "Hydraulic line pressure builds; ABS activates." },
      { t: 0.0, speed: 57.8, throttle: 0, brake: 100, steer: -38.2, yaw: 18.5, longG: -18.4, abs: true, canLoad: 62, canId: "0x0001", canPayload: "AC 01 DE AD BE EF", anomaly: true, notes: "IMPACT: T-Bone collision at intersection center (-18.4g)" },
      { t: 0.5, speed: 28.0, throttle: 0, brake: 100, steer: -55.0, yaw: 42.0, longG: -4.2, abs: true, canLoad: 68, canId: "0x0002", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Post-impact rotational trajectory" },
      { t: 1.0, speed: 12.0, throttle: 0, brake: 100, steer: -40.0, yaw: 15.0, longG: -1.2, abs: false, canLoad: 45, canId: "0x0002", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Deceleration against road curb" },
      { t: 1.5, speed: 0.0, throttle: 0, brake: 100, steer: -30.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 35, canId: "0x0000", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Vehicle brought to a complete stop" },
      { t: 2.0, speed: 0.0, throttle: 0, brake: 0, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 31, canId: "0x0000", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "EDR locked event record recorded" },
      { t: 2.5, speed: 0.0, throttle: 0, brake: 0, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 28, canId: "0x0000", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Event recording cycle finalized" }
    ]
  },

  "CASE_AF_4421": {
    id: "AF-4421",
    title: "Highway Exit — Sudden Acceleration Analysis",
    shortTitle: "2. Highway Exit — Sudden Acceleration Analysis",
    scenarioType: "Exit Ramp Collision (Pedal Application Investigation)",
    primaryDataSources: ["EDR Crash Table", "Powertrain CAN", "Throttle Sensors"],
    vehicleInfo: {
      make: "Hyperion",
      model: "AeroPulse GT",
      year: "2024",
      vin: "3FA6P0HD8LR192847",
      ecuFirmware: "v2.09.1",
      edrModule: "Denso EDR Gen 3"
    },
    incidentTime: "2026-07-22 09:15:44 UTC",
    location: {
      address: "Expressway Exit Ramp 12B, Westbound",
      lat: 19.076090,
      lng: 72.877426,
      speedLimit: 80,
      roadCondition: "Wet Asphalt, Overcast"
    },
    summary: "Investigation into reported uncommanded acceleration during exit ramp negotiation. Sensor telemetry indicates 99% accelerator demand with 0 Bar hydraulic brake line pressure until 200ms before barrier impact.",
    summaryTags: ["Pedal Misapplication Indicated", "0 Bar Brake Pressure", "Accelerating Trajectory", "Demonstration Case"],
    aiVerdict: {
      primaryCause: "Pedal input pattern indicates accelerator depression rather than brake application",
      confidence: 94.0,
      driverActionVerified: "Dual throttle position sensor signals (TPS1 & TPS2) indicate 99% accelerator demand until 200ms before barrier impact. Hydraulic brake pressure remained at 0 Bar throughout the acceleration event.",
      supportingEvidence: [
        "Dual throttle sensors TPS1 and TPS2 tracked synchronously to 99%",
        "Hydraulic brake line pressure remained at 0 Bar until t = -0.20s",
        "Vehicle accelerated from 65.0 km/h to 119.5 km/h on curved ramp",
        "No uncommanded throttle actuation DTCs recorded in PCM memory"
      ],
      xaiFeatureWeights: [
        { feature: "Throttle position sensor 1 & 2 agreement", weight: 0.45, impact: "Consistent with pedal application" },
        { feature: "Hydraulic brake line pressure (0 Bar)", weight: 0.35, impact: "No early braking recorded" },
        { feature: "Engine RPM / torque demand match", weight: 0.15, impact: "Nominal powertrain response" },
        { feature: "CAN frame cyclic counter continuity", weight: 0.05, impact: "Bus communications intact" }
      ],
      anomalyCount: 1,
      crashTimeSec: 0.00
    },
    investigatorRecommendation: {
      assessment: "Driver/physical event",
      assessmentSubtext: "Physical pedal misapplication with continuous throttle and absence of braking",
      confidence: 94.0,
      summary: "The reconstructed timeline indicates that vehicle acceleration resulted from physical accelerator pedal depression without concurrent brake demand. The available evidence suggests the incident is consistent with driver pedal misapplication rather than an electronic throttle malfunction.",
      whyReasons: [
        "Dual independent throttle position sensors (TPS1 and TPS2) tracked synchronously to 99% demand with zero signal plausibility divergence.",
        "Hydraulic brake line pressure transducer registered exactly 0 Bar continuously from t = -5.0s until emergency panic braking at t = -0.20s.",
        "Powertrain Control Module (PCM) logged zero uncommanded acceleration Diagnostic Trouble Codes (DTCs) or communication bus errors.",
        "Engine RPM, transmission gear ratio, and wheel speeds show deterministic kinematic alignment with commanded throttle demand."
      ],
      detectedAnomalies: [
        { time: "t = -4.00s", component: "Driver Input Interface", description: "Rapid throttle demand surge to 80% on curved exit ramp." },
        { time: "t = -3.50s", component: "Kinematic Speed Profile", description: "Velocity accelerated to 99% throttle, exceeding posted 60 km/h ramp advisory." },
        { time: "t = -0.20s", component: "Brake Hydraulic Circuit", description: "Late emergency brake application 200ms pre-impact." }
      ],
      recommendedNextSteps: [
        "Examine the physical driver footwell area, floor mat anchors, and pedal cluster for mechanical entrapment or interference.",
        "Download non-volatile flash logs from the Powertrain Control Module (PCM) to verify analog sensor voltage linearity curves.",
        "Conduct a mechanical return-spring resistance test on the electronic accelerator pedal assembly.",
        "Interview vehicle occupants regarding driver footing and sudden evasive maneuvers."
      ],
      furtherExaminationEvidence: [
        "Physical accelerator pedal assembly and return springs",
        "Vehicle floor mat retainers and driver footwell carpet clearance",
        "PCM and TCM freeze-frame freeze records"
      ],
      limitations: [
        "Driver footwell camera was not installed; physical pedal contact is inferred from dual sensor potentiometer telemetry."
      ]
    },
    stakeholderGuidance: {
      scenarioCategory: "DRIVER_FAULT",
      categoryLabel: "Driver / Human Fault (Pedal Misapplication & Delayed Braking)",
      hasSufficientEvidence: true,
      recommendations: [
        {
          causeDetected: "Driver Pedal Misapplication & Sustained Accelerator Demand",
          evidenceLevel: "Confirmed Evidence",
          confidence: 94.0,
          responsibleStakeholder: "DRIVER / ROAD USER",
          stakeholderIcon: "fa-user",
          evidence: "Dual independent throttle position sensors (TPS1 & TPS2) tracked synchronously to 99% demand on the exit curve, while hydraulic brake pressure remained at 0 Bar until 200ms before crash cushion impact.",
          recommendedAction: "Drivers should maintain disciplined foot placement and reduce speed well in advance of curved exit ramps to avoid sudden emergency pedal confusion."
        }
      ],
      incidentResponsibility: {
        primary: {
          factor: "Driver behavior (Pedal misapplication & delayed braking)",
          confidenceLevel: "High Confidence (94%)",
          evidenceSummary: "Continuous 99% accelerator demand recorded with 0 Bar brake pressure until 200ms pre-impact."
        },
        secondary: {
          factor: "None identified",
          confidenceLevel: "Single primary causal factor",
          evidenceSummary: "Kinematic data confirms speed surge directly matches commanded throttle percentage."
        },
        vehicleFault: {
          status: "No technical malfunction detected",
          evidenceSummary: "Dual TPS potentiometers matched with 0% error; zero uncommanded throttle DTCs recorded in PCM."
        },
        roadEnvironment: {
          status: "Wet asphalt, overcast daylight",
          evidenceSummary: "Exit ramp advisory signage and impact attenuator met highway safety standards."
        },
        decisionSupportNotice: "This assessment represents a technical forensic decision-support indicator based on synchronized EDR, CAN, and kinematic data. It is not a legal verdict."
      }
    },
    evidenceHashes: [
      { source: "EDR Crash Log (.bin)", sha256: "13bdb670f3e2e1f6a5ac04998736c4a6bfd0ae190c891b148aee628538f3f476", size: "3.8 MB", status: "VERIFIED", verifiedBy: "Investigator SHA-256 Ledger" },
      { source: "Powertrain CAN Dump (.asc)", sha256: "b1d6845a7b6fd0b95e03694ccf9bb7ff483b0a31d26e1f396591ee80b188679e", size: "94.2 MB", status: "VERIFIED", verifiedBy: "Investigator SHA-256 Ledger" },
      { source: "Dashcam Video (.mp4)", sha256: "e1b42d6a0349232434d818e1827cadaac7edbce6d44ccf4d8a0a9f9fd293f36c", size: "340.0 MB", status: "VERIFIED", verifiedBy: "Investigator SHA-256 Ledger" }
    ],
    timelineMilestones: [
      { t: -5.0, label: "Ramp Approach", desc: "Cruise at 65 km/h", type: "nominal" },
      { t: -4.0, label: "Throttle Surge", desc: "Accelerator to 80%", type: "anomaly" },
      { t: -0.2, label: "Late Braking", desc: "200ms pre-impact", type: "action" },
      { t: 0.0, label: "IMPACT", desc: "Attenuator at 117 km/h", type: "impact" },
      { t: 1.5, label: "Final Rest", desc: "Rest at barrier", type: "nominal" }
    ],
    telemetry: [
      { t: -5.0, speed: 65.0, throttle: 20, brake: 0, steer: 0.0, yaw: 0.0, longG: 0.05, abs: false, canLoad: 35, canId: "0x0110", canPayload: "14 00 00 00 00 00", anomaly: false, notes: "Approaching exit ramp" },
      { t: -4.5, speed: 66.2, throttle: 25, brake: 0, steer: 2.0, yaw: 0.1, longG: 0.08, abs: false, canLoad: 36, canId: "0x0110", canPayload: "19 00 00 00 00 00", anomaly: false, notes: "Initiating ramp turn" },
      { t: -4.0, speed: 69.5, throttle: 80, brake: 0, steer: 4.5, yaw: 0.3, longG: 0.35, abs: false, canLoad: 37, canId: "0x0110", canPayload: "50 00 00 00 00 00", anomaly: true, notes: "EVENT: Throttle increases rapidly to 80%" },
      { t: -3.5, speed: 76.0, throttle: 98, brake: 0, steer: 8.0, yaw: 0.8, longG: 0.52, abs: false, canLoad: 38, canId: "0x0110", canPayload: "62 00 00 00 00 00", anomaly: true, notes: "Throttle reaches 98%; vehicle accelerates along curve" },
      { t: -3.0, speed: 84.5, throttle: 99, brake: 0, steer: 12.0, yaw: 1.5, longG: 0.58, abs: false, canLoad: 39, canId: "0x0110", canPayload: "63 00 00 00 00 00", anomaly: false, notes: "Velocity exceeds posted ramp limit" },
      { t: -2.5, speed: 93.0, throttle: 99, brake: 0, steer: 18.0, yaw: 2.4, longG: 0.60, abs: false, canLoad: 40, canId: "0x0110", canPayload: "63 00 00 00 00 00", anomaly: false, notes: "Steering corrections applied with continuous throttle" },
      { t: -2.0, speed: 101.2, throttle: 99, brake: 0, steer: 25.0, yaw: 3.8, longG: 0.55, abs: false, canLoad: 41, canId: "0x0110", canPayload: "63 00 00 00 00 00", anomaly: false, notes: "Speed passes 100 km/h; brake pressure at 0 Bar" },
      { t: -1.5, speed: 108.5, throttle: 99, brake: 0, steer: 35.0, yaw: 5.5, longG: 0.48, abs: false, canLoad: 42, canId: "0x0110", canPayload: "63 00 00 00 00 00", anomaly: false, notes: "Vehicle yaw angle deviates from ramp lane" },
      { t: -1.0, speed: 114.0, throttle: 99, brake: 0, steer: 45.0, yaw: 7.8, longG: 0.35, abs: false, canLoad: 43, canId: "0x0110", canPayload: "63 00 00 00 00 00", anomaly: false, notes: "Driver steering input sharpens toward barrier" },
      { t: -0.5, speed: 118.2, throttle: 99, brake: 0, steer: 48.0, yaw: 9.2, longG: 0.20, abs: false, canLoad: 45, canId: "0x0110", canPayload: "63 00 00 00 00 00", anomaly: false, notes: "Pre-impact trajectory points directly to attenuator" },
      { t: -0.2, speed: 119.5, throttle: 0, brake: 100, steer: 50.0, yaw: 10.5, longG: -0.90, abs: true, canLoad: 55, canId: "0x01B0", canPayload: "64 00 00 00 00 00", anomaly: false, notes: "EVENT: Brake pedal depressed 200ms before barrier impact" },
      { t: 0.0, speed: 117.0, throttle: 0, brake: 100, steer: 52.0, yaw: 32.0, longG: -24.5, abs: true, canLoad: 68, canId: "0x0001", canPayload: "AC 01 DE AD BE EF", anomaly: true, notes: "IMPACT: Crash cushion contact at 117 km/h (-24.5g)" },
      { t: 0.5, speed: 45.0, throttle: 0, brake: 100, steer: 60.0, yaw: 65.0, longG: -8.2, abs: true, canLoad: 72, canId: "0x0002", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Vehicle deflection along guardrail" },
      { t: 1.0, speed: 15.0, throttle: 0, brake: 100, steer: 40.0, yaw: 20.0, longG: -2.1, abs: false, canLoad: 50, canId: "0x0002", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Secondary barrier friction deceleration" },
      { t: 1.5, speed: 0.0, throttle: 0, brake: 0, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 32, canId: "0x0000", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Vehicle at final resting position" },
      { t: 2.0, speed: 0.0, throttle: 0, brake: 0, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 30, canId: "0x0000", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "EDR locked record stored" },
      { t: 2.5, speed: 0.0, throttle: 0, brake: 0, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 28, canId: "0x0000", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Data capture completed" }
    ]
  },

  "CASE_AF_6715": {
    id: "AF-6715",
    title: "ADAS Handover — Late Driver Warning",
    shortTitle: "3. ADAS Handover — Late Driver Warning",
    scenarioType: "ADAS Disengagement (Handover Latency Investigation)",
    primaryDataSources: ["Perception Log", "CAN-FD", "Cabin Video", "RTK GPS"],
    vehicleInfo: {
      make: "Autonoma",
      model: "PathFinder X9",
      year: "2025",
      vin: "5YJSA1E29MF819203",
      ecuFirmware: "v5.22-prod",
      edrModule: "Autonoma Recorder 2.0"
    },
    incidentTime: "2026-08-01 22:38:05 UTC",
    location: {
      address: "State Route 88 North, Construction Shift",
      lat: 12.971598,
      lng: 77.594566,
      speedLimit: 90,
      roadCondition: "Unlit Highway, Construction Zone"
    },
    summary: "Vehicle operating in Level 2 lane centering departed the paved roadway in a construction lane shift. Vision confidence fell to 18% at t = -2.0s, while the driver takeover alert was issued 800ms before departure.",
    summaryTags: ["Late Warning Timing", "Vision Degradation", "Lane Departure Recorded", "Demonstration Case"],
    aiVerdict: {
      primaryCause: "ADAS handover alert timing was inconsistent with driver reaction requirements",
      confidence: 91.5,
      driverActionVerified: "Camera confidence degraded in construction transition zone at t = -1.8s. Takeover request was issued at t = -0.8s, providing approximately 800ms before lane boundary departure.",
      supportingEvidence: [
        "Vision perception confidence dropped below threshold at t = -2.00s",
        "Acoustic and visual handover warning issued at t = -0.80s",
        "Available human takeover window measured at approximately 800ms",
        "Manual counter-steering initiated at t = -0.40s prior to barrier contact"
      ],
      xaiFeatureWeights: [
        { feature: "Takeover alert lead time (800ms)", weight: 0.42, impact: "Short warning window" },
        { feature: "Vision camera confidence decay", weight: 0.28, impact: "Perception loss" },
        { feature: "Steering wheel hands-on sensor", weight: 0.18, impact: "Driver reaction measurement" },
        { feature: "Steering torque disengagement transient", weight: 0.12, impact: "System disengagement" }
      ],
      anomalyCount: 3,
      crashTimeSec: 0.00
    },
    investigatorRecommendation: {
      assessment: "Vehicle/system malfunction",
      assessmentSubtext: "Active safety perception degradation and delayed driver takeover alert issuance",
      confidence: 91.5,
      summary: "The reconstructed timeline indicates that automated lane centering disengaged with inadequate warning lead time during a highway construction shift. The evidence indicates the incident is related to active safety perception decay and insufficient human handover lead time.",
      whyReasons: [
        "Optical vision perception confidence collapsed from 92% to 18% at t = -2.00s upon encountering unstriped pavement.",
        "Takeover Request (TOR) acoustic chime was withheld by the ADAS controller until t = -0.80s, leaving only 800ms for driver intervention.",
        "Standard forensic human factors benchmark (SAE J3016) specifies 1.5 to 2.5 seconds minimum reaction time for takeover in unlit conditions.",
        "Driver initiated emergency counter-steering at t = -0.40s, but physical roadway departure was already kinematically inevitable."
      ],
      detectedAnomalies: [
        { time: "t = -2.00s", component: "Vision Perception ECU", description: "Lane tracking confidence fell below 20% operational threshold." },
        { time: "t = -0.80s", component: "HMI Warning Alert", description: "Takeover request chime delayed until 800ms before departure." },
        { time: "t = 0.00s", component: "Barrier Impact", description: "Roadway departure collision into construction barricade at 82 km/h." }
      ],
      recommendedNextSteps: [
        "Audit ADAS domain controller internal event ring buffers (.pcap) to inspect lane tracking state-machine transitions.",
        "Compare system handover timing logic with OEM functional safety hazard analysis (ISO 26262 ASIL-B requirements).",
        "Analyze steering column capacitive hands-on sensor data to confirm driver attentiveness state prior to the alert.",
        "Inspect forward optical camera housing for lens road-film contamination or optical distortion."
      ],
      furtherExaminationEvidence: [
        "ADAS perception ECU raw object classification logs (.pcap)",
        "Cabin infrared driver monitoring camera recordings",
        "Steering wheel capacitive sensor touch logs"
      ],
      limitations: [
        "Local RTK GPS base station correction was unavailable in the construction zone corridor."
      ]
    },
    stakeholderGuidance: {
      scenarioCategory: "ROAD_PROBLEM",
      categoryLabel: "Road / Infrastructure Problem (Unmarked Construction Shift & Vision Degradation)",
      hasSufficientEvidence: true,
      recommendations: [
        {
          causeDetected: "Missing Construction Lane Markings & Sudden Pavement Shift",
          evidenceLevel: "Confirmed Evidence",
          confidence: 89.0,
          responsibleStakeholder: "ROAD / GOVERNMENT AUTHORITY",
          stakeholderIcon: "fa-road",
          evidence: "Optical camera perception confidence fell sharply from 92% to 18% when transitioning into unstriped asphalt with missing retro-reflective lane delimiters in the construction zone.",
          recommendedAction: "Road authority / highway maintenance contractor should inspect the construction work zone, install high-contrast temporary reflective lane striping, and deploy advance illuminated taper signage."
        },
        {
          causeDetected: "Short ADAS Takeover Alert Lead Time (800ms)",
          evidenceLevel: "Probable Contributing Factor",
          confidence: 82.5,
          responsibleStakeholder: "VEHICLE MANUFACTURER",
          stakeholderIcon: "fa-industry",
          evidence: "Takeover Request (TOR) acoustic warning was withheld until t = -0.80s, providing only 800ms before roadway departure, below the SAE J3016 recommended 1.5s to 2.5s driver takeover threshold.",
          recommendedAction: "Vehicle manufacturer should recalibrate ADAS operational design domain (ODD) fallback logic to alert drivers earlier when vision confidence begins decaying."
        }
      ],
      incidentResponsibility: {
        primary: {
          factor: "Road infrastructure defect (Missing lane delineation & unstriped shift)",
          confidenceLevel: "High Confidence (89%)",
          evidenceSummary: "Unstriped pavement caused active safety camera perception confidence to drop to 18%."
        },
        secondary: {
          factor: "Vehicle ADAS handover warning latency",
          confidenceLevel: "Probable factor (82%)",
          evidenceSummary: "Acoustic takeover chime provided only 800ms lead time before barrier contact."
        },
        vehicleFault: {
          status: "Compressed handover warning timing",
          evidenceSummary: "Camera tracking confidence degraded 1.2s before driver alert was triggered."
        },
        roadEnvironment: {
          status: "Unlit highway, construction zone shift, missing lane markings",
          evidenceSummary: "Pavement lane markings abruptly ended at construction detour taper."
        },
        decisionSupportNotice: "This assessment represents a technical forensic decision-support indicator based on synchronized EDR, CAN, and kinematic data. It is not a legal verdict."
      }
    },
    evidenceHashes: [
      { source: "ADAS Perception Log (.pcap)", sha256: "eef4dca7012e0dd50db9ca297a89b99f57d7c6073405391d7f6335339401c482", size: "850.0 MB", status: "VERIFIED", verifiedBy: "Investigator SHA-256 Ledger" },
      { source: "Chassis CAN-FD Stream (.mf4)", sha256: "7af47925a0f31b39771597025697cb353cf78d3d4297fe2f7e78e6e8d86d63bb", size: "215.4 MB", status: "VERIFIED", verifiedBy: "Investigator SHA-256 Ledger" }
    ],
    timelineMilestones: [
      { t: -5.0, label: "Lane Centering", desc: "L2 active at 90 km/h", type: "nominal" },
      { t: -2.0, label: "Vision Decay", desc: "Confidence falls to 18%", type: "anomaly" },
      { t: -0.8, label: "Takeover Alert", desc: "Warning chime issued", type: "action" },
      { t: 0.0, label: "IMPACT", desc: "Roadway departure 82 km/h", type: "impact" },
      { t: 1.5, label: "Shoulder Rest", desc: "Vehicle stopped", type: "nominal" }
    ],
    telemetry: [
      { t: -5.0, speed: 90.0, throttle: 35, brake: 0, steer: 0.5, yaw: 0.0, longG: 0.0, abs: false, canLoad: 45, canId: "0x0350", canPayload: "01 00 5A 00 00 00", anomaly: false, notes: "ADAS lane centering active" },
      { t: -4.0, speed: 89.8, throttle: 35, brake: 0, steer: 0.8, yaw: 0.0, longG: 0.0, abs: false, canLoad: 46, canId: "0x0350", canPayload: "01 00 5A 00 00 00", anomaly: false, notes: "Entering construction zone shift" },
      { t: -3.0, speed: 89.5, throttle: 35, brake: 0, steer: 1.0, yaw: 0.1, longG: 0.0, abs: false, canLoad: 48, canId: "0x0350", canPayload: "01 00 5A 00 00 00", anomaly: false, notes: "Temporary pavement markings begin" },
      { t: -2.0, speed: 88.0, throttle: 32, brake: 0, steer: 1.5, yaw: 0.2, longG: -0.05, abs: false, canLoad: 52, canId: "0x0360", canPayload: "02 1F 00 00 00 00", anomaly: true, notes: "EVENT: Vision confidence drops to 18%" },
      { t: -1.5, speed: 87.2, throttle: 30, brake: 0, steer: 2.0, yaw: 0.3, longG: -0.08, abs: false, canLoad: 55, canId: "0x0360", canPayload: "02 05 00 00 00 00", anomaly: true, notes: "Camera tracking confidence lost on right boundary" },
      { t: -0.8, speed: 86.0, throttle: 20, brake: 0, steer: 2.2, yaw: 0.5, longG: -0.10, abs: false, canLoad: 60, canId: "0x0380", canPayload: "FF 01 00 00 00 00", anomaly: true, notes: "EVENT: Takeover request warning chime issued" },
      { t: -0.4, speed: 84.5, throttle: 0, brake: 15, steer: -5.0, yaw: -0.5, longG: -0.25, abs: false, canLoad: 58, canId: "0x01B0", canPayload: "10 00 00 00 00 00", anomaly: false, notes: "Manual brake and steering input recorded" },
      { t: 0.0, speed: 82.0, throttle: 0, brake: 60, steer: -18.0, yaw: -4.5, longG: -6.8, abs: true, canLoad: 62, canId: "0x0001", canPayload: "AC 01 DE AD BE EF", anomaly: true, notes: "IMPACT: Roadway departure into construction barrier (-6.8g)" },
      { t: 0.5, speed: 50.0, throttle: 0, brake: 90, steer: -25.0, yaw: -12.0, longG: -4.5, abs: true, canLoad: 65, canId: "0x0002", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Shoulder gravel displacement" },
      { t: 1.0, speed: 20.0, throttle: 0, brake: 100, steer: -15.0, yaw: -5.0, longG: -2.0, abs: false, canLoad: 48, canId: "0x0002", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Secondary contact with road marker" },
      { t: 1.5, speed: 0.0, throttle: 0, brake: 100, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 34, canId: "0x0000", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Vehicle stopped in road shoulder" },
      { t: 2.0, speed: 0.0, throttle: 0, brake: 0, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 30, canId: "0x0000", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Event logs saved to flash memory" },
      { t: 2.5, speed: 0.0, throttle: 0, brake: 0, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 28, canId: "0x0000", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Recording closed" }
    ]
  },

  "CASE_AF_9104": {
    id: "AF-9104",
    title: "Steering System — Sensor Anomaly",
    shortTitle: "4. Steering System — Sensor Anomaly",
    scenarioType: "Chassis Control (Sensor Discrepancy Investigation)",
    primaryDataSources: ["Chassis CAN", "SAS Sensor", "ESC Module"],
    vehicleInfo: {
      make: "Quantex",
      model: "E-Van 400",
      year: "2025",
      vin: "4V4NC9EJ8PN201948",
      ecuFirmware: "v3.88-rel",
      edrModule: "Continental SASM Module"
    },
    incidentTime: "2026-08-20 03:14:22 UTC",
    location: {
      address: "Logistics Corridor Expressway, Km 140",
      lat: 13.082680,
      lng: 80.270721,
      speedLimit: 100,
      roadCondition: "Dry Highway, Night"
    },
    summary: "Commercial van experienced uncommanded yaw divergence during high-speed cruising. Analysis revealed steering angle messages (ID 0x0024) inverted in sign relative to physical vehicle trajectory, causing asymmetrical ESC brake activation.",
    summaryTags: ["Sensor Signal Discrepancy", "Uncommanded Yaw Deviation", "Rollover Recorded", "Demonstration Case"],
    aiVerdict: {
      primaryCause: "Discrepancy detected between steering sensor signal and physical yaw response",
      confidence: 93.0,
      driverActionVerified: "Steering Angle Sensor (SAS) message ID 0x0024 showed an inverted sign value relative to physical heading, resulting in an asymmetrical ESC brake pulse prior to rollover.",
      supportingEvidence: [
        "Steering sensor reported -35.0 deg while physical wheel angle was +12.0 deg",
        "ESC system commanded left differential braking based on sensor reading",
        "Vehicle yaw rate diverged rapidly to -45.0 deg/s",
        "Vehicle tripped against median barrier resulting in rollover"
      ],
      xaiFeatureWeights: [
        { feature: "Steering angle vs heading disagreement", weight: 0.44, impact: "Sensor discrepancy" },
        { feature: "CAN frame 0x0024 counter sequence", weight: 0.30, impact: "Signal transmission anomaly" },
        { feature: "ESC differential brake command", weight: 0.16, impact: "Actuator response" },
        { feature: "Driver steering column torque", weight: 0.10, impact: "Corrective effort" }
      ],
      anomalyCount: 3,
      crashTimeSec: 0.00
    },
    investigatorRecommendation: {
      assessment: "CAN/network anomaly",
      assessmentSubtext: "Steering Angle Sensor frame corruption and uncommanded differential ESC braking",
      confidence: 93.0,
      summary: "The reconstructed timeline indicates an erroneous steering sensor message stream transmitted over the chassis network, causing unwarranted electronic stability intervention. The available evidence suggests the incident is related to CAN signal corruption or sensor integrity failure.",
      whyReasons: [
        "Steering Angle Sensor arbitration ID 0x0024 broadcast an inverted sign reading (-35.0°) while physical road wheel heading was +12.0°.",
        "Chassis CAN bus load spiked to 88% coincident with rapid message sequence counter irregularities in ID 0x0024.",
        "ESC control logic responded to the corrupted steering input by commanding aggressive left front differential braking.",
        "Asymmetrical braking induced a violent yaw divergence (-45.0°/s) and tripped rollover that could not be corrected by driver steering."
      ],
      detectedAnomalies: [
        { time: "t = -2.50s", component: "SAS CAN Frame 0x0024", description: "Steering angle sign bit inverted from positive to negative (payload FF EB)." },
        { time: "t = -1.50s", component: "ESC Control Module", description: "Uncommanded left front brake pressure pulse triggered." },
        { time: "t = 0.00s", component: "Chassis Kinematics", description: "Median barrier impact and rollover at 86 km/h (-12.5g)." }
      ],
      recommendedNextSteps: [
        "Extract CAN message captures between t = -10.0s and t = +5.0s to examine frame counter sequence continuity for ID 0x0024.",
        "Perform optical encoder disc inspection and clean-room microscopic analysis on the Steering Angle Sensor unit.",
        "Inspect chassis wiring harness and ground distribution blocks for intermittent high-resistance faults or EMI coupling.",
        "Check vehicle gateway firewall and telematics module for unauthorized diagnostic write sessions preceding the anomaly."
      ],
      furtherExaminationEvidence: [
        "Steering Angle Sensor physical module and optical disc encoder",
        "ESC module non-volatile diagnostic trouble registers (DTC snapshot)",
        "Chassis network gateway configuration logs"
      ],
      limitations: [
        "Steering column mechanical torsion bar strain gauge logs were not available."
      ]
    },
    stakeholderGuidance: {
      scenarioCategory: "VEHICLE_FAULT",
      categoryLabel: "Vehicle / Car Fault (Steering Sensor Corruption & ESC Intervention)",
      hasSufficientEvidence: true,
      recommendations: [
        {
          causeDetected: "Steering Angle Sensor Inverted Sign Frame (CAN ID 0x0024)",
          evidenceLevel: "Confirmed Evidence",
          confidence: 93.0,
          responsibleStakeholder: "VEHICLE MANUFACTURER",
          stakeholderIcon: "fa-industry",
          evidence: "Chassis CAN frame 0x0024 transmitted an inverted steering angle sign (-35.0° vs physical heading +12.0°), triggering uncommanded left differential braking by the Electronic Stability Control (ESC) module.",
          recommendedAction: "Vehicle manufacturer should review Steering Angle Sensor plausibility check routines in ESC firmware and implement multi-channel cross-validation with yaw-rate transducers before initiating differential brake pulses."
        },
        {
          causeDetected: "Steering Sensor Physical Integrity",
          evidenceLevel: "Probable Contributing Factor",
          confidence: 89.0,
          responsibleStakeholder: "VEHICLE SERVICE / MAINTENANCE",
          stakeholderIcon: "fa-wrench",
          evidence: "Chassis CAN bus load spiked to 88% with message counter sequence irregularities in ID 0x0024.",
          recommendedAction: "Service network should conduct diagnostic impedance tests on the steering column harness and inspect the optical disc encoder for contamination or micro-cracks."
        }
      ],
      incidentResponsibility: {
        primary: {
          factor: "Vehicle electronic sensor anomaly (Corrupted SAS signal & ESC intervention)",
          confidenceLevel: "High Confidence (93%)",
          evidenceSummary: "Corrupted SAS sign bit triggered uncommanded differential braking and rollover."
        },
        secondary: {
          factor: "None — Uncommanded vehicle dynamics",
          confidenceLevel: "No driver error detected",
          evidenceSummary: "Driver counter-steering was appropriate but overridden by ESC differential braking."
        },
        vehicleFault: {
          status: "Confirmed Steering Angle Sensor sign bit inversion and unwarranted differential braking",
          evidenceSummary: "CAN frame 0x0024 counter and parity irregularities confirmed."
        },
        roadEnvironment: {
          status: "Dry straight highway, nominal environmental baseline",
          evidenceSummary: "Pavement in good condition, ambient temperature nominal."
        },
        decisionSupportNotice: "This assessment represents a technical forensic decision-support indicator based on synchronized EDR, CAN, and kinematic data. It is not a legal verdict."
      }
    },
    evidenceHashes: [
      { source: "Chassis CAN Stream (.pcap)", sha256: "a0c17a54adc0dd93fc4f9dec68028e2b9aa4fc0064a2ca18d20861633210c219", size: "310.0 MB", status: "VERIFIED", verifiedBy: "Investigator SHA-256 Ledger" }
    ],
    timelineMilestones: [
      { t: -5.0, label: "Highway Cruise", desc: "Center lane 98 km/h", type: "nominal" },
      { t: -2.5, label: "SAS Discrepancy", desc: "Inverted sign reading", type: "anomaly" },
      { t: -1.5, label: "ESC Brake Pulse", desc: "Asymmetrical braking", type: "action" },
      { t: 0.0, label: "IMPACT", desc: "Median rollover 86 km/h", type: "impact" },
      { t: 2.0, label: "Final Rest", desc: "Shoulder rest", type: "nominal" }
    ],
    telemetry: [
      { t: -5.0, speed: 98.0, throttle: 40, brake: 0, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 42, canId: "0x0024", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Cruising in center lane" },
      { t: -3.5, speed: 97.5, throttle: 40, brake: 0, steer: 2.0, yaw: 0.1, longG: 0.0, abs: false, canLoad: 44, canId: "0x0024", canPayload: "00 14 00 00 00 00", anomaly: false, notes: "Driver initiates gentle lane adjustment" },
      { t: -2.5, speed: 97.0, throttle: 38, brake: 0, steer: 5.0, yaw: 0.2, longG: -0.02, abs: false, canLoad: 78, canId: "0x0024", canPayload: "FF EB 00 00 00 00", anomaly: true, notes: "EVENT: Steering sensor message shows inverted sign reading" },
      { t: -1.5, speed: 95.0, throttle: 20, brake: 0, steer: 12.0, yaw: -4.5, longG: -0.15, abs: false, canLoad: 88, canId: "0x0024", canPayload: "FF 88 00 00 00 00", anomaly: true, notes: "ESC triggers left front brake pulse based on sensor value" },
      { t: -0.5, speed: 91.0, throttle: 0, brake: 40, steer: 35.0, yaw: -18.2, longG: -0.65, abs: true, canLoad: 92, canId: "0x0024", canPayload: "FF 00 00 00 00 00", anomaly: true, notes: "Yaw rate increases; driver counter-steers" },
      { t: 0.0, speed: 86.0, throttle: 0, brake: 80, steer: 45.0, yaw: -45.0, longG: -12.5, abs: true, canLoad: 95, canId: "0x0001", canPayload: "DE AD BE EF 00 00", anomaly: true, notes: "IMPACT: Rollover initiated at median barrier (-12.5g)" },
      { t: 1.0, speed: 25.0, throttle: 0, brake: 100, steer: 0.0, yaw: -80.0, longG: -3.5, abs: false, canLoad: 40, canId: "0x0000", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Vehicle skidding on side structure" },
      { t: 2.0, speed: 0.0, throttle: 0, brake: 0, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 25, canId: "0x0000", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Rest on highway shoulder" }
    ]
  },

  "CASE_AF_3389": {
    id: "AF-3389",
    title: "Heavy Vehicle — Brake Pressure Loss",
    shortTitle: "5. Heavy Vehicle — Brake Pressure Loss",
    scenarioType: "Commercial Braking (Pneumatic Pressure Anomaly)",
    primaryDataSources: ["J1939 Powertrain", "Brake Reservoir Sensors", "EDR"],
    vehicleInfo: {
      make: "Titan",
      model: "Mammoth 6x4 Tractor",
      year: "2023",
      vin: "1THTR6488NN819201",
      ecuFirmware: "v1.44-j1939",
      edrModule: "Bendix SafetyDirect"
    },
    incidentTime: "2026-06-11 14:20:09 UTC",
    location: {
      address: "Mountain Pass Descent, Grade 8%, Curve 4",
      lat: 34.052235,
      lng: -118.243683,
      speedLimit: 55,
      roadCondition: "Dry Mountain Highway"
    },
    summary: "Loaded commercial combination vehicle was unable to control speed down an 8% grade. Telemetry demonstrates continuous full pedal application while secondary pneumatic reservoir pressure fell to 2.1 Bar.",
    summaryTags: ["Pneumatic Pressure Loss", "Continuous Brake Application", "Grade Descent Incident", "Demonstration Case"],
    aiVerdict: {
      primaryCause: "Pneumatic pressure drop detected in secondary brake supply circuit",
      confidence: 95.0,
      driverActionVerified: "Continuous brake pedal treadle application recorded for 12 seconds. Secondary reservoir pressure dropped to 2.1 Bar, significantly reducing foundation braking capacity on downgrade.",
      supportingEvidence: [
        "Secondary pneumatic reservoir pressure decreased to 2.1 Bar at t = -3.50s",
        "Brake treadle sensor remained at 100% displacement continuously",
        "Deceleration limited to -0.15g during sustained downgrade application",
        "Vehicle entered sand arrester bed at 92.0 km/h"
      ],
      xaiFeatureWeights: [
        { feature: "Pneumatic pressure sensor 2 drop", weight: 0.52, impact: "Pressure depletion" },
        { feature: "Brake treadle displacement", weight: 0.28, impact: "Full driver application" },
        { feature: "Engine compression brake active", weight: 0.12, impact: "Auxiliary braking active" },
        { feature: "Wheel hub temperature trend", weight: 0.08, impact: "Thermal loading" }
      ],
      anomalyCount: 2,
      crashTimeSec: 0.00
    },
    investigatorRecommendation: {
      assessment: "Vehicle/system malfunction",
      assessmentSubtext: "Pneumatic reservoir pressure starvation and mechanical brake fade during grade descent",
      confidence: 95.0,
      summary: "The reconstructed timeline indicates that the commercial vehicle experienced pneumatic pressure depletion in its secondary foundation brake circuit during sustained downgrade descent. The evidence indicates the incident is related to pneumatic component failure.",
      whyReasons: [
        "Secondary pneumatic air circuit pressure fell to 2.1 Bar at t = -3.50s, breaching federal commercial vehicle minimum safety thresholds (FMVSS 121).",
        "Driver brake treadle transducer registered continuous 100% full application for over 12 seconds, proving driver attempted full foundation braking.",
        "Auxiliary engine compression brake (Jake brake) was active throughout, confirming all retardation mechanisms were utilized.",
        "Net vehicle deceleration was kinematically capped at -0.15g due to pressure loss, resulting in runaway speed down the 8% grade."
      ],
      detectedAnomalies: [
        { time: "t = -3.50s", component: "Pneumatic Supply Circuit", description: "Secondary reservoir pressure plummeted to 2.1 Bar." },
        { time: "t = -2.00s", component: "Vehicle Kinematics", description: "Velocity accelerated to 82 km/h despite 100% continuous pedal application." },
        { time: "t = 0.00s", component: "Arrester Bed Entry", description: "Emergency escape ramp arrest at 92 km/h (-8.5g)." }
      ],
      recommendedNextSteps: [
        "Perform physical pneumatic pressure leak checks on secondary air tanks, check valves, and spring brake chambers.",
        "Measure pushrod travel and slack adjuster stroke length on all tractor and trailer wheel-ends.",
        "Examine foundation brake drums and linings for severe glazing, heat checks, or thermal degradation.",
        "Inspect the engine-driven air compressor governor cut-out and unloader valve."
      ],
      furtherExaminationEvidence: [
        "Secondary pneumatic reservoir tank, relay valves, and rubber glad-hand couplings",
        "S-cam foundation brake shoes, linings, and brake drums",
        "Tractor air compressor unloader valve"
      ],
      limitations: [
        "Infrared foundation brake temperature telemetry was not logged by the J1939 network."
      ]
    },
    stakeholderGuidance: {
      scenarioCategory: "MULTIPLE_FACTORS",
      categoryLabel: "Multiple Contributing Factors (Commercial Brake Depletion & 8% Mountain Grade)",
      hasSufficientEvidence: true,
      recommendations: [
        {
          causeDetected: "Secondary Pneumatic Reservoir Pressure Depletion",
          evidenceLevel: "Confirmed Evidence",
          confidence: 95.0,
          responsibleStakeholder: "VEHICLE SERVICE / MAINTENANCE",
          stakeholderIcon: "fa-wrench",
          evidence: "Secondary pneumatic air circuit pressure dropped to 2.1 Bar at t = -3.50s despite 100% continuous driver pedal application, limiting foundation braking capacity to -0.15g.",
          recommendedAction: "Commercial vehicle fleet maintenance must inspect air brake relay valves, glad-hand seals, compressor unloader valves, and adjust slack adjuster stroke lengths according to commercial vehicle safety standards."
        },
        {
          causeDetected: "Steep 8% Grade Descent & Arrester Ramp Signage",
          evidenceLevel: "Probable Contributing Factor",
          confidence: 84.0,
          responsibleStakeholder: "ROAD / GOVERNMENT AUTHORITY",
          stakeholderIcon: "fa-road",
          evidence: "Continuous sustained descent on 8% mountain grade led to thermal lining stress and speed runaway prior to runaway truck arrester bed entry.",
          recommendedAction: "Highway authority should review mountain pass downgrade warning signage, evaluate brake check brake-inspection turnout areas at the summit, and maintain arrester bed gravel depth."
        },
        {
          causeDetected: "Grade Descent Speed Management & Gear Selection",
          evidenceLevel: "Possible Contributing Factor",
          confidence: 76.0,
          responsibleStakeholder: "DRIVER / ROAD USER",
          stakeholderIcon: "fa-user",
          evidence: "Tractor entered steep 8% grade at 68 km/h without preemptive downshifting to lower transmission gear, over-relying on foundation air brakes.",
          recommendedAction: "Commercial drivers should select lower transmission gears prior to descending steep mountain grades to maximize engine compression braking and preserve pneumatic reserve."
        }
      ],
      incidentResponsibility: {
        primary: {
          factor: "Vehicle pneumatic system malfunction (Reservoir pressure drop to 2.1 Bar)",
          confidenceLevel: "High Confidence (95%)",
          evidenceSummary: "Air pressure starved below FMVSS 121 statutory safety threshold."
        },
        secondary: {
          factor: "Road geometry & steep 8% grade",
          confidenceLevel: "High Confidence (84%)",
          evidenceSummary: "Severe downgrade accelerated vehicle runaway when foundation brakes faded."
        },
        vehicleFault: {
          status: "Confirmed pneumatic pressure depletion in secondary brake circuit",
          evidenceSummary: "Air pressure fell from 7.5 Bar to 2.1 Bar under sustained application."
        },
        roadEnvironment: {
          status: "8% continuous mountain downgrade descent",
          evidenceSummary: "Geometric profile created extreme potential energy acceleration."
        },
        decisionSupportNotice: "This assessment represents a technical forensic decision-support indicator based on synchronized EDR, CAN, and kinematic data. It is not a legal verdict."
      }
    },
    evidenceHashes: [
      { source: "J1939 Powertrain Log (.csv)", sha256: "e753722447d9af958b2c61ca65bb1ff48230a1d0ddb4d3c5509aa6fed5a5044d", size: "48.2 MB", status: "VERIFIED", verifiedBy: "Investigator SHA-256 Ledger" }
    ],
    timelineMilestones: [
      { t: -5.0, label: "Grade Descent", desc: "8% downgrade 68 km/h", type: "nominal" },
      { t: -3.5, label: "Pressure Loss", desc: "Reservoir < 2.5 Bar", type: "anomaly" },
      { t: -1.0, label: "Escape Approach", desc: "Ramp entry approach", type: "action" },
      { t: 0.0, label: "IMPACT", desc: "Arrester bed 92 km/h", type: "impact" },
      { t: 2.5, label: "Vehicle Arrested", desc: "Gravel stopped", type: "nominal" }
    ],
    telemetry: [
      { t: -5.0, speed: 68.0, throttle: 0, brake: 70, steer: 2.0, yaw: 0.1, longG: -0.18, abs: false, canLoad: 35, canId: "0x00FE", canPayload: "46 00 00 00 00 00", anomaly: false, notes: "Descending 8% mountain grade" },
      { t: -3.5, speed: 74.0, throttle: 0, brake: 100, steer: 4.0, yaw: 0.2, longG: -0.15, abs: false, canLoad: 38, canId: "0x00FE", canPayload: "64 00 00 00 00 00", anomaly: true, notes: "EVENT: Reservoir pressure drops below 2.5 Bar" },
      { t: -2.0, speed: 82.0, throttle: 0, brake: 100, steer: 8.0, yaw: 0.5, longG: -0.12, abs: false, canLoad: 42, canId: "0x00FE", canPayload: "64 00 00 00 00 00", anomaly: true, notes: "Vehicle continues acceleration down grade with 100% treadle" },
      { t: -1.0, speed: 89.0, throttle: 0, brake: 100, steer: 18.0, yaw: 1.8, longG: -0.10, abs: false, canLoad: 45, canId: "0x00FE", canPayload: "64 00 00 00 00 00", anomaly: true, notes: "Steering into escape ramp approach" },
      { t: 0.0, speed: 92.0, throttle: 0, brake: 100, steer: 32.0, yaw: 14.5, longG: -8.5, abs: false, canLoad: 50, canId: "0x0001", canPayload: "AC 01 00 00 00 00", anomaly: true, notes: "IMPACT: Arrester bed entry at 92 km/h (-8.5g)" },
      { t: 1.5, speed: 10.0, throttle: 0, brake: 100, steer: 0.0, yaw: 0.0, longG: -1.5, abs: false, canLoad: 30, canId: "0x0000", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Gravel displacement arresting vehicle" },
      { t: 2.5, speed: 0.0, throttle: 0, brake: 0, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 28, canId: "0x0000", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Vehicle stopped in arrester bed" }
    ]
  },

  "CASE_AF_1082": {
    id: "AF-1082",
    title: "Pedestrian AEB — Sensor Conflict",
    shortTitle: "6. Pedestrian AEB — Sensor Conflict",
    scenarioType: "Active Safety (Sensor Conflict Investigation)",
    primaryDataSources: ["Forward Radar", "Camera Log", "CAN Bus", "EDR"],
    vehicleInfo: {
      make: "Voltix",
      model: "Aura Crossover",
      year: "2025",
      vin: "7FATR82E5PP109283",
      ecuFirmware: "v2.80-aeb",
      edrModule: "Aptiv AEB Sensor Box"
    },
    incidentTime: "2026-08-25 21:05:12 UTC",
    location: {
      address: "Downtown Pedestrian Crossing, Elm Street",
      lat: 37.774929,
      lng: -122.419416,
      speedLimit: 40,
      roadCondition: "Wet Asphalt, Night, Glare"
    },
    summary: "AEB system did not execute autonomous braking for crossing pedestrian. Radar telemetry tracked the target with high confidence, while the forward optical camera suppressed target confirmation due to low-light headlight glare conditions.",
    summaryTags: ["Radar/Vision Discrepancy", "AEB Inaction Recorded", "Low-Speed Pedestrian Contact", "Demonstration Case"],
    aiVerdict: {
      primaryCause: "Multi-sensor conflict between front radar detection and optical vision system",
      confidence: 91.0,
      driverActionVerified: "Front 77GHz radar detected crossing obstacle at 38m. Forward camera optical processing did not confirm target under headlight glare conditions, preventing AEB actuation.",
      supportingEvidence: [
        "77GHz radar object classification active at 38m (t = -2.00s)",
        "Forward camera glare flag set to TRUE at t = -2.00s",
        "Multi-sensor fusion logic required dual confirmation for brake pulse",
        "Manual braking initiated 300ms before contact, reducing speed from 42 to 34 km/h"
      ],
      xaiFeatureWeights: [
        { feature: "Front radar obstacle tracking (38m)", weight: 0.46, impact: "Target tracked" },
        { feature: "Camera optical glare flag", weight: 0.32, impact: "Suppressed confirmation" },
        { feature: "TTC threshold calculation", weight: 0.14, impact: "Braking threshold crossed" },
        { feature: "Driver emergency reaction latency", weight: 0.08, impact: "Human reaction time" }
      ],
      anomalyCount: 2,
      crashTimeSec: 0.00
    },
    investigatorRecommendation: {
      assessment: "Vehicle/system malfunction",
      assessmentSubtext: "Multi-sensor fusion logic suppression under optical headlight glare",
      confidence: 91.0,
      summary: "The reconstructed timeline indicates that the Autonomous Emergency Braking (AEB) system did not execute automated stopping due to a sensor fusion conflict between radar and vision subsystems. The evidence indicates the incident is related to active safety sensor fusion limitations under nighttime optical glare.",
      whyReasons: [
        "Forward 77GHz millimeter-wave radar object tracking (ID 0x0220) detected and classified the crossing pedestrian at 38m distance.",
        "Forward optical camera algorithm flagged an optical GLARE state from oncoming traffic headlights, withholding optical confirmation.",
        "AEB central supervisory controller required coincidence between radar and camera before triggering autonomous pre-crash braking.",
        "Driver initiated manual emergency braking 300ms before impact, decelerating vehicle from 42 km/h to 34 km/h at contact."
      ],
      detectedAnomalies: [
        { time: "t = -2.00s", component: "Sensor Fusion Controller", description: "Radar target tracked at 38m; camera optical glare flag suppressed fusion confirmation." },
        { time: "t = -1.00s", component: "AEB Actuator Command", description: "No autonomous brake pre-fill commanded despite Time-To-Collision (TTC) under 1.2s." },
        { time: "t = 0.00s", component: "Pedestrian Contact", description: "Low-speed pedestrian contact recorded at 34 km/h (-8.2g)." }
      ],
      recommendedNextSteps: [
        "Download and inspect raw micro-Doppler radar point clouds and camera raw Bayer frames from the active safety domain controller.",
        "Audit AEB supervisory fusion firmware calibration logic for single-sensor degraded mode fallback rules.",
        "Examine windshield camera mounting bracket, defrost heating grid, and lens coating for optical scatter or distortion.",
        "Correlate EDR time-to-collision thresholds with OEM Euro NCAP active safety specification compliance data."
      ],
      furtherExaminationEvidence: [
        "Active safety domain controller non-volatile log dump",
        "Windshield forward optical camera module and bracket",
        "77GHz front radar transceiver alignment calibration records"
      ],
      limitations: [
        "Pedestrian wearable optical retro-reflectors or lateral thermal camera imagery were not available."
      ]
    },
    stakeholderGuidance: {
      scenarioCategory: "ENVIRONMENTAL",
      categoryLabel: "Environmental / External Factor (Headlight Glare & Wet Pavement Reflection)",
      hasSufficientEvidence: true,
      recommendations: [
        {
          causeDetected: "Nighttime Headlight Glare & Wet Pavement Reflection",
          evidenceLevel: "Confirmed Evidence",
          confidence: 91.0,
          responsibleStakeholder: "EMERGENCY / TRAFFIC AUTHORITY",
          stakeholderIcon: "fa-shield-halved",
          evidence: "Forward optical camera optical glare flag was triggered by oncoming traffic headlights and wet pavement reflection, suppressing pedestrian classification at the crosswalk.",
          recommendedAction: "Municipal traffic authority should evaluate crosswalk overhead floodlighting, install pedestrian-activated illuminated warning beacons, and review street lamp maintenance."
        },
        {
          causeDetected: "Driver Speed & Reduced Night Visibility Caution",
          evidenceLevel: "Probable Contributing Factor",
          confidence: 84.0,
          responsibleStakeholder: "DRIVER / ROAD USER",
          stakeholderIcon: "fa-user",
          evidence: "Vehicle traveled at 42 km/h approaching the pedestrian crossing in dark, wet conditions; manual braking was initiated only 300ms before contact.",
          recommendedAction: "Drivers must exercise heightened caution, reduce speed below the posted limit, and actively scan crosswalk perimeters when driving under low-illumination and wet road conditions."
        },
        {
          causeDetected: "AEB Dual-Sensor Confirmation Suppression Under Glare",
          evidenceLevel: "Possible Contributing Factor",
          confidence: 78.0,
          responsibleStakeholder: "VEHICLE MANUFACTURER",
          stakeholderIcon: "fa-industry",
          evidence: "Front 77GHz radar successfully detected and tracked the pedestrian at 38m, but supervisory fusion withheld autonomous brake pre-fill because camera vision was degraded by glare.",
          recommendedAction: "Vehicle manufacturer should evaluate radar-dominant degraded mode braking logic for pedestrian AEB when optical cameras experience localized glare."
        }
      ],
      incidentResponsibility: {
        primary: {
          factor: "Environmental factor (Nighttime wet pavement glare & optical reflection)",
          confidenceLevel: "High Confidence (91%)",
          evidenceSummary: "Optical glare flag set to TRUE, suppressing camera vision target confirmation."
        },
        secondary: {
          factor: "Driver late reaction (300ms lead time) & vehicle AEB conservative suppression",
          confidenceLevel: "Probable factor (81%)",
          evidenceSummary: "Dual sensor requirement prevented autonomous pre-crash braking."
        },
        vehicleFault: {
          status: "Sensor fusion logic required dual optical+radar confirmation, suppressing brake pre-charge",
          evidenceSummary: "Radar object at 38m ignored due to absence of simultaneous camera bounding box."
        },
        roadEnvironment: {
          status: "Wet asphalt, dark night, oncoming headlight glare at pedestrian crossing",
          evidenceSummary: "Low ambient lumen level combined with reflective surface water."
        },
        decisionSupportNotice: "This assessment represents a technical forensic decision-support indicator based on synchronized EDR, CAN, and kinematic data. It is not a legal verdict."
      }
    },
    evidenceHashes: [
      { source: "Front Radar Stream (.mf4)", sha256: "1bd7f000dd56400f85e93464313d368ba81ea00882bafa08fd396ab720dbcb78", size: "412.0 MB", status: "VERIFIED", verifiedBy: "Investigator SHA-256 Ledger" }
    ],
    timelineMilestones: [
      { t: -5.0, label: "Approach", desc: "Cruising 42 km/h", type: "nominal" },
      { t: -2.0, label: "Sensor Conflict", desc: "Radar 38m, optical glare", type: "anomaly" },
      { t: -0.3, label: "Manual Brake", desc: "Driver emergency pedal", type: "action" },
      { t: 0.0, label: "IMPACT", desc: "Pedestrian contact 34 km/h", type: "impact" },
      { t: 1.0, label: "Vehicle Stopped", desc: "Full stop", type: "nominal" }
    ],
    telemetry: [
      { t: -5.0, speed: 42.0, throttle: 25, brake: 0, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 40, canId: "0x0210", canPayload: "00 2A 00 00 00 00", anomaly: false, notes: "Cruising toward crosswalk" },
      { t: -3.0, speed: 41.5, throttle: 20, brake: 0, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 45, canId: "0x0210", canPayload: "00 26 00 26 00 00", anomaly: false, notes: "Pedestrian steps into crossing lane" },
      { t: -2.0, speed: 41.0, throttle: 18, brake: 0, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 60, canId: "0x0220", canPayload: "01 5C 00 00 00 00", anomaly: true, notes: "EVENT: Radar confirms obstacle at 38m; camera glare flag set" },
      { t: -1.0, speed: 40.0, throttle: 10, brake: 0, steer: 0.0, yaw: 0.0, longG: -0.05, abs: false, canLoad: 65, canId: "0x0220", canPayload: "01 5C 00 00 00 00", anomaly: true, notes: "AEB does not pre-charge brakes due to lack of camera confirmation" },
      { t: -0.3, speed: 39.0, throttle: 0, brake: 60, steer: -5.0, yaw: -0.5, longG: -0.45, abs: false, canLoad: 70, canId: "0x01B0", canPayload: "3C 00 00 00 00 00", anomaly: false, notes: "EVENT: Driver observes pedestrian and applies manual braking" },
      { t: 0.0, speed: 34.0, throttle: 0, brake: 100, steer: -8.0, yaw: -1.2, longG: -8.2, abs: true, canLoad: 75, canId: "0x0001", canPayload: "AC 01 DE AD BE EF", anomaly: true, notes: "IMPACT: Low-speed pedestrian contact at 34 km/h" },
      { t: 1.0, speed: 0.0, throttle: 0, brake: 100, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 35, canId: "0x0000", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Vehicle brought to stop" }
    ]
  },

  "CASE_AF_MULT": {
    id: "AF-5503",
    title: "Expressway Pileup — Multi-Factor Incident",
    shortTitle: "5. Expressway Pileup — Multi-Factor (Driver + Road + ADAS)",
    scenarioType: "Multi-Vehicle Chain Collision (Distraction, Slick Surface & ADAS Latency)",
    primaryDataSources: ["Cabin DMS Video", "Front Radar & Camera", "Chassis CAN-FD", "EDR Record"],
    vehicleInfo: {
      make: "Centurion",
      model: "Nexus GT",
      year: "2025",
      vin: "1NXCR4F99PA810291",
      ecuFirmware: "v3.19.4-prod",
      edrModule: "Bosch CDR Gen 4"
    },
    incidentTime: "2026-09-02 18:15:30 UTC",
    location: {
      address: "Metropolitan Expressway Eastbound, Km 42",
      lat: 28.535517,
      lng: 77.391029,
      speedLimit: 100,
      roadCondition: "Wet Asphalt, Standing Water, Heavy Rain"
    },
    summary: "Driver distracted by mobile device in heavy precipitation collided with decelerating lead vehicle. Reconstructed evidence demonstrates 2.4s glance away from road, delayed braking reaction, reduced tire friction (mu=0.42), and a 400ms CAN arbitration delay in the forward collision warning chime.",
    summaryTags: ["Driver Distraction", "Wet Road Surface Defect", "FCW Alert Arbitration Delay", "Multi-Factor Incident", "Demonstration Case"],
    aiVerdict: {
      primaryCause: "Multi-factor incident involving driver inattention, degraded road surface friction, and active safety alert latency",
      confidence: 88.5,
      driverActionVerified: "Cabin DMS confirms driver eyes off roadway for 2.4 seconds prior to braking. Physical brake pedal was depressed at t = -1.10s. Road surface friction was reduced to mu=0.42 due to water ponding, resulting in collision at 48.5 km/h.",
      supportingEvidence: [
        "Cabin DMS camera logged driver gaze diversion for 2.4 seconds (t = -3.50s to t = -1.10s)",
        "Driver initiated panic brake pedal application at t = -1.10s (only 1.1s pre-impact)",
        "Tire-road friction coefficient measured at mu = 0.42 with 4.5mm water ponding depth",
        "CAN bus arbitration delay of 400ms queued Forward Collision Warning (FCW) audio chime behind non-critical frames"
      ],
      xaiFeatureWeights: [
        { feature: "Driver glance distraction duration (2.4s)", weight: 0.44, impact: "Delayed driver braking" },
        { feature: "Road surface friction coefficient (mu=0.42)", weight: 0.32, impact: "Extended stopping distance" },
        { feature: "FCW warning chime latency (400ms)", weight: 0.16, impact: "Delayed audio alert" },
        { feature: "Lead vehicle closing speed", weight: 0.08, impact: "Kinematic closure rate" }
      ],
      anomalyCount: 3,
      crashTimeSec: 0.00
    },
    investigatorRecommendation: {
      assessment: "Driver/physical event",
      assessmentSubtext: "Driver mobile device distraction compounded by reduced pavement friction and active safety alert queuing",
      confidence: 88.5,
      summary: "The reconstructed timeline indicates that driver inattention was the primary initiator, but stopping failure was significantly compounded by poor road surface water drainage and active safety audio chime latency. Multiple stakeholder actions are indicated.",
      whyReasons: [
        "Cabin DMS telemetry proves driver eyes were diverted downward for 2.4s immediately preceding deceleration of lead traffic.",
        "Emergency braking was initiated at t = -1.10s, allowing only 11 meters of deceleration space from 85 km/h.",
        "Roadway water pooling caused hydrodynamic tire skid, capping deceleration at -0.42g.",
        "Forward collision warning alert frame on CAN ID 0x0380 was queued behind infotainment traffic for 400ms."
      ],
      detectedAnomalies: [
        { time: "t = -3.50s", component: "Driver Monitoring System", description: "Driver gaze diversion flag active (mobile device usage pattern)." },
        { time: "t = -1.50s", component: "Chassis CAN Network", description: "FCW chime frame 0x0380 queued behind low-priority infotainment frames." },
        { time: "t = -1.10s", component: "Braking System", description: "Emergency brake pressure rise with tire hydroplaning slip ratio > 45%." },
        { time: "t = 0.00s", component: "Impact Event", description: "Rear-end collision into lead vehicle at 48.5 km/h (-14.2g)." }
      ],
      recommendedNextSteps: [
        "Extract high-rate DMS camera frame metadata to calculate exact pupil gaze vectors.",
        "Request highway maintenance drainage slope laser profilometry records for Km 42.",
        "Audit vehicle gateway arbitration priority configuration for ID 0x0380 (Safety Chime)."
      ],
      furtherExaminationEvidence: [
        "Mobile phone cellular data session activity records around incident timestamp",
        "Pavement macro-texture and sand-patch friction test reports",
        "Vehicle gateway message queue scheduling logic"
      ],
      limitations: [
        "Precipitation rate sensor on road gantries was not connected to local V2X broadcast."
      ]
    },
    stakeholderGuidance: {
      scenarioCategory: "MULTIPLE_FACTORS",
      categoryLabel: "Multiple Contributing Factors (Driver + Road Infrastructure + Vehicle ADAS)",
      hasSufficientEvidence: true,
      recommendations: [
        {
          causeDetected: "Driver Inattention & Delayed Hazard Response",
          evidenceLevel: "Confirmed Evidence",
          confidence: 88.0,
          responsibleStakeholder: "DRIVER / ROAD USER",
          stakeholderIcon: "fa-user",
          evidence: "Cabin driver monitoring telemetry records gaze diversion from forward lane for 2.4s; driver applied emergency braking at t = -1.10s, allowing only 11m stopping distance at 85 km/h.",
          recommendedAction: "Drivers must eliminate mobile device distractions, maintain continuous forward visual attention, and double following distance when operating in rainy or wet conditions."
        },
        {
          causeDetected: "Reduced Road Surface Micro-Texture & Drainage Ponding",
          evidenceLevel: "Probable Contributing Factor",
          confidence: 84.0,
          responsibleStakeholder: "ROAD / GOVERNMENT AUTHORITY",
          stakeholderIcon: "fa-road",
          evidence: "Measured tire-road friction coefficient dropped to mu = 0.42 with 4.5mm localized surface water pooling due to insufficient shoulder cross-slope gradient.",
          recommendedAction: "Road authority should inspect expressway surface drainage, repave with open-graded friction course (OGFC) asphalt, and deploy automated variable speed limit signs during heavy rain."
        },
        {
          causeDetected: "Forward Collision Warning (FCW) Chime Arbitration Latency",
          evidenceLevel: "Possible Contributing Factor",
          confidence: 74.0,
          responsibleStakeholder: "VEHICLE MANUFACTURER",
          stakeholderIcon: "fa-industry",
          evidence: "FCW acoustic warning broadcast was delayed by 400ms on CAN bus ID 0x0380 due to arbitration queue saturation by non-safety infotainment frames.",
          recommendedAction: "Vehicle manufacturer should reprioritize safety-critical acoustic warning frame arbitration IDs and verify pre-collision audio chime preemption logic."
        }
      ],
      incidentResponsibility: {
        primary: {
          factor: "Driver behavior (Inattention & delayed reaction)",
          confidenceLevel: "High Confidence (88%)",
          evidenceSummary: "Eyes off road for 2.4s, braking delayed to 1.1s before collision."
        },
        secondary: {
          factor: "Road condition (Degraded surface drainage & friction loss)",
          confidenceLevel: "High Confidence (84%)",
          evidenceSummary: "Tire-road friction dropped to mu=0.42 with localized standing water."
        },
        vehicleFault: {
          status: "Minor active safety arbitration delay (400ms latency)",
          evidenceSummary: "FCW chime queued behind non-critical bus traffic."
        },
        roadEnvironment: {
          status: "Wet asphalt, standing water, heavy precipitation",
          evidenceSummary: "Rainfall intensity 22mm/hr with reduced visibility."
        },
        decisionSupportNotice: "This assessment represents a technical forensic decision-support indicator based on synchronized EDR, CAN, and kinematic data. It is not a legal verdict."
      }
    },
    evidenceHashes: [
      { source: "Cabin DMS Telemetry (.bin)", sha256: "34fa9812bbca1029384756102938475610293847561029384756102938475610", size: "64.5 MB", status: "VERIFIED", verifiedBy: "Investigator SHA-256 Ledger" },
      { source: "CAN-FD Traffic Trace (.pcap)", sha256: "9912038475610293847561029384756102938475610293847561029384756102", size: "280.0 MB", status: "VERIFIED", verifiedBy: "Investigator SHA-256 Ledger" },
      { source: "EDR Event Crash Record (.bin)", sha256: "4501928374651029384756102938475610293847561029384756102938475610", size: "4.8 MB", status: "VERIFIED", verifiedBy: "Investigator SHA-256 Ledger" }
    ],
    timelineMilestones: [
      { t: -5.0, label: "Expressway Cruise", desc: "85 km/h in Rain", type: "nominal" },
      { t: -3.5, label: "Driver Distracted", desc: "Eyes off road", type: "anomaly" },
      { t: -1.5, label: "FCW Audio Delay", desc: "400ms queue latency", type: "anomaly" },
      { t: -1.1, label: "Panic Brake", desc: "Driver 100% pedal", type: "action" },
      { t: 0.0, label: "IMPACT", desc: "Rear-end collision 48 km/h", type: "impact" },
      { t: 1.5, label: "Final Stop", desc: "Vehicle at rest", type: "nominal" }
    ],
    telemetry: [
      { t: -5.0, speed: 85.0, throttle: 35, brake: 0, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 42, canId: "0x0110", canPayload: "23 00 00 00 00 00", anomaly: false, notes: "Cruising in wet conditions at 85 km/h" },
      { t: -4.0, speed: 85.0, throttle: 35, brake: 0, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 44, canId: "0x0110", canPayload: "23 00 00 00 00 00", anomaly: false, notes: "Lead vehicle initiates deceleration at 60m" },
      { t: -3.5, speed: 84.8, throttle: 32, brake: 0, steer: 0.2, yaw: 0.0, longG: -0.02, abs: false, canLoad: 52, canId: "0x0340", canPayload: "01 02 00 00 00 00", anomaly: true, notes: "EVENT: Cabin DMS flags driver gaze diverted away from road" },
      { t: -2.5, speed: 84.5, throttle: 30, brake: 0, steer: 0.2, yaw: 0.0, longG: -0.02, abs: false, canLoad: 55, canId: "0x0340", canPayload: "01 02 00 00 00 00", anomaly: true, notes: "Driver continues looking down; closing distance drops to 35m" },
      { t: -1.5, speed: 83.0, throttle: 20, brake: 0, steer: 0.5, yaw: 0.1, longG: -0.05, abs: false, canLoad: 86, canId: "0x0380", canPayload: "FF 01 00 00 00 00", anomaly: true, notes: "FCW warning chime frame delayed in CAN arbitration queue" },
      { t: -1.1, speed: 81.0, throttle: 0, brake: 100, steer: -2.0, yaw: -0.2, longG: -0.42, abs: true, canLoad: 78, canId: "0x01B0", canPayload: "64 00 00 00 00 00", anomaly: false, notes: "EVENT: Driver looks up and applies 100% emergency brake" },
      { t: -0.5, speed: 66.0, throttle: 0, brake: 100, steer: -4.0, yaw: -0.5, longG: -0.42, abs: true, canLoad: 72, canId: "0x01B0", canPayload: "64 00 00 00 00 00", anomaly: false, notes: "Tires hydroplaning on standing water (decel capped at -0.42g)" },
      { t: 0.0, speed: 48.5, throttle: 0, brake: 100, steer: -6.0, yaw: 2.5, longG: -14.2, abs: true, canLoad: 80, canId: "0x0001", canPayload: "AC 01 DE AD BE EF", anomaly: true, notes: "IMPACT: Rear-end collision into lead vehicle (-14.2g)" },
      { t: 0.5, speed: 18.0, throttle: 0, brake: 100, steer: -8.0, yaw: 5.0, longG: -3.5, abs: false, canLoad: 45, canId: "0x0002", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Post-impact secondary sliding" },
      { t: 1.5, speed: 0.0, throttle: 0, brake: 100, steer: 0.0, yaw: 0.0, longG: 0.0, abs: false, canLoad: 30, canId: "0x0000", canPayload: "00 00 00 00 00 00", anomaly: false, notes: "Vehicle stopped on expressway lane" }
    ]
  }
};


if (typeof window !== 'undefined') {
  window.ANALYSIS_COMPONENTS = ANALYSIS_COMPONENTS;
  window.FORENSIC_CASES = FORENSIC_CASES;
}
