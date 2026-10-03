from typing import Dict, Any, Tuple
from backend.app.config import RISK_WEIGHTS, RISK_LEVEL_THRESHOLDS

class RiskAssessmentEngine:
    """
    Risk Assessment Engine (Chapters 3.6, 4.2.3, 10.1 - 10.9)
    Evaluates 5 security indicators based on the exact scoring weights in Chapter 10.8:
    - Unknown Device (Weight 25)
    - Firmware Risk (Weight 25)
    - Credential Risk (Weight 25)
    - Network Exposure (Weight 15)
    - Security Configuration (Weight 10)
    
    Produces a composite Risk Score (0-100), Risk Level (Low/Medium/High),
    and an explainable breakdown of findings.
    """

    def evaluate_device(self, device_data: Dict[str, Any]) -> Dict[str, Any]:
        factor_scores = {}
        findings = []

        is_known = device_data.get("is_known_device", False)
        device_type = device_data.get("device_type", "Unknown Device")
        firmware = (device_data.get("firmware_version") or "").lower()
        credential = (device_data.get("credential_status") or "").lower()
        open_ports = device_data.get("open_ports") or []
        exposure_desc = (device_data.get("network_exposure") or "").lower()
        config_desc = (device_data.get("security_configuration") or "").lower()

        # Indicator 1: Unknown Device Risk (Weight 25)
        # Chapter 10.6: Devices not matching known inventory represent an unmanaged threat
        if not is_known or device_type == "Unknown Device":
            unknown_score = RISK_WEIGHTS["unknown_device"]
            findings.append({
                "factor": "Unknown Device",
                "score": unknown_score,
                "detail": "Device is unapproved, not in authorized inventory, or has unknown type."
            })
        else:
            unknown_score = 0
        factor_scores["factor_unknown"] = unknown_score

        # Indicator 2: Firmware Risk (Weight 25)
        # Chapter 10.3: Outdated firmware or known CVE associations
        if "cve" in firmware or "vulnerable" in firmware or "outdated" in firmware:
            firmware_score = RISK_WEIGHTS["firmware_risk"]
            findings.append({
                "factor": "Firmware Risk",
                "score": firmware_score,
                "detail": f"Vulnerable or outdated firmware detected: {device_data.get('firmware_version', 'Unknown')}"
            })
        elif "unknown" in firmware or not firmware:
            firmware_score = 15  # Unverified firmware carries moderate risk
            findings.append({
                "factor": "Firmware Risk",
                "score": firmware_score,
                "detail": "Firmware version could not be confirmed or verified."
            })
        elif "minor" in firmware:
            firmware_score = 10
            findings.append({
                "factor": "Firmware Risk",
                "score": firmware_score,
                "detail": "Minor firmware updates available; no high-severity CVE actively identified."
            })
        else:
            firmware_score = 0
        factor_scores["factor_firmware"] = firmware_score

        # Indicator 3: Credential Risk (Weight 25)
        # Chapter 10.4: Default, weak or factory credentials detected
        if any(w in credential for w in ["default", "factory", "admin:admin", "admin:1234", "weak"]):
            credential_score = RISK_WEIGHTS["credential_risk"]
            findings.append({
                "factor": "Credential Risk",
                "score": credential_score,
                "detail": f"Default or weak credentials present: {device_data.get('credential_status')}"
            })
        elif "unknown" in credential:
            credential_score = 12
            findings.append({
                "factor": "Credential Risk",
                "score": credential_score,
                "detail": "Credential protection status has not been confirmed."
            })
        else:
            credential_score = 0
        factor_scores["factor_credential"] = credential_score

        # Indicator 4: Network Exposure Risk (Weight 15)
        # Chapter 10.5: Risky open ports (Telnet 23, unencrypted HTTP 80, RTSP 554, FTP 21, etc.)
        risky_ports_found = [p for p in open_ports if p in [21, 23, 80, 554, 8080, 37777]]
        if 23 in open_ports:
            exposure_score = RISK_WEIGHTS["network_exposure"]
            findings.append({
                "factor": "Network Exposure",
                "score": exposure_score,
                "detail": "High-risk unencrypted management service (Telnet port 23) is open."
            })
        elif len(risky_ports_found) >= 2 or "high" in exposure_desc:
            exposure_score = RISK_WEIGHTS["network_exposure"]
            findings.append({
                "factor": "Network Exposure",
                "score": exposure_score,
                "detail": f"Multiple exposed or sensitive service ports open: {open_ports}"
            })
        elif len(risky_ports_found) == 1 or "medium" in exposure_desc:
            exposure_score = 8
            findings.append({
                "factor": "Network Exposure",
                "score": exposure_score,
                "detail": f"Service ports exposed to local network: {open_ports}"
            })
        else:
            exposure_score = 2 if len(open_ports) > 0 else 0
        factor_scores["factor_exposure"] = exposure_score

        # Indicator 5: Security Configuration (Weight 10)
        # Chapter 10.7: Missing encryption (HTTP instead of HTTPS), weak protocols
        if any(w in config_desc for w in ["insecure", "no tls", "upnp"]):
            config_score = RISK_WEIGHTS["security_configuration"]
            findings.append({
                "factor": "Security Configuration",
                "score": config_score,
                "detail": f"Insecure configuration setting detected: {device_data.get('security_configuration')}"
            })
        elif "unknown" in config_desc:
            config_score = 5
        elif "acceptable" in config_desc:
            config_score = 3
        else:
            config_score = 0
        factor_scores["factor_config"] = config_score

        # Total Calculation
        total_risk_score = (
            factor_scores["factor_unknown"] +
            factor_scores["factor_firmware"] +
            factor_scores["factor_credential"] +
            factor_scores["factor_exposure"] +
            factor_scores["factor_config"]
        )
        total_risk_score = min(100, max(0, total_risk_score))

        # Risk Level Categorization (Chapter 10.8 & 10.9)
        # 0–30: Low, 31–60: Medium, 61–100: High
        if total_risk_score <= RISK_LEVEL_THRESHOLDS["LOW_MAX"]:
            risk_level = "Low"
        elif total_risk_score <= RISK_LEVEL_THRESHOLDS["MEDIUM_MAX"]:
            risk_level = "Medium"
        else:
            risk_level = "High"

        return {
            "risk_score": total_risk_score,
            "risk_level": risk_level,
            "factor_unknown": factor_scores["factor_unknown"],
            "factor_firmware": factor_scores["factor_firmware"],
            "factor_credential": factor_scores["factor_credential"],
            "factor_exposure": factor_scores["factor_exposure"],
            "factor_config": factor_scores["factor_config"],
            "findings": findings
        }

risk_engine = RiskAssessmentEngine()
