"""
Test Suite: 49 CFR Part 563 EDR Extraction, CAN Bus & Incident Reconstruction
"""

import pytest
from backend.edr_service import EDR49CFR563Parser, CANBusLogParser, VehicleDataFusionEngine
from backend.reconstruction_service import get_reconstruction_trajectory, calculate_what_if_simulation

def test_edr_49_cfr_563_parser():
    raw_edr_bytes = b"EDR_CRASH_DATA_BLOCK_REV3_DELTA_V_-24.8KPH_SEATBELT_LATCHED"
    parsed = EDR49CFR563Parser.parse_edr_payload(raw_edr_bytes, "test_edr.bin")

    assert parsed["regulation"] == "49 CFR Part 563"
    assert parsed["delta_v_max_kph"] == -24.8
    assert parsed["driver_seatbelt_status"] == "LATCHED"
    assert len(parsed["pre_crash_records"]) == 11
    # Check 0.5s sampling rate (-5.0s to 0.0s) per 49 CFR 563 Table 1
    assert parsed["pre_crash_records"][0]["time_offset_s"] == -5.0
    assert parsed["pre_crash_records"][-1]["time_offset_s"] == 0.0

def test_can_bus_parser_and_flood_detection():
    can_content = "TIMESTAMP,ID,DATA\n1.0,0x0284,00 00\n1.1,0x01B0,FF 00\n"
    # Add flooding messages
    for i in range(60):
        can_content += f"1.{2+i},0x0284,B1 2A 00 00\n"

    parsed = CANBusLogParser.parse_can_log(can_content.encode("utf-8"), "test_can.log")
    assert parsed["total_frames"] == 62
    assert "0x0284" in parsed["unique_ids"]
    assert parsed["flooding_detected"] is True
    assert parsed["dominant_id"] == "0x0284"

def test_vehicle_data_fusion():
    edr_data = EDR49CFR563Parser.parse_edr_payload(b"DELTA_V_-24.8KPH", "test.bin")
    can_data = CANBusLogParser.parse_can_log(b"1.0,0x0284,00\n", "test.log")

    fused = VehicleDataFusionEngine.fuse_case_telemetry(edr_data, can_data)
    assert len(fused) == 11
    assert fused[0]["speed_kph"] > 0
    assert "can_bus_load_pct" in fused[0]

def test_kinematic_reconstruction_trajectories():
    res = get_reconstruction_trajectory("CASE_AF_8902", view_mode="topdown")
    assert res["case_id"] == "CASE_AF_8902"
    assert res["view_mode"] == "topdown"
    assert len(res["trajectory"]) > 100
    assert "assumptions" in res
    assert len(res["assumptions"]) >= 3

def test_what_if_simulation_physics():
    # Test normal latency (0ms latency reduction)
    res_normal = calculate_what_if_simulation("CASE_AF_8902", latency_ms=0.0)
    assert res_normal["avoidance_status"] == "COLLISION_AVOIDED_FULL_STOP"
    assert res_normal["simulated_impact_speed_kph"] == 0.0

    # Test baseline 2100ms latency (simulates actual incident collision)
    res_delayed = calculate_what_if_simulation("CASE_AF_8902", latency_ms=2100.0)
    assert res_delayed["simulated_impact_speed_kph"] > 30.0
    assert res_delayed["avoidance_status"] == "COLLISION_OCCURRED"
