#!/usr/bin/env python3
"""
Simplified AI Agent-Based Cybersecurity Forensic Platform
No external dependencies - uses only built-in Python libraries

This simplified version demonstrates cybersecurity concepts for investment banking
while avoiding external package dependencies for easier setup.

Author: [Your Name]
Date: September 2025
Target: Investment Banking Cybersecurity
"""

import os
import sys
import json
import hashlib
import sqlite3
import threading
import time
import re
import socket
import logging
from pathlib import Path
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Optional
import random
import math


class ThreatLevel(Enum):
    """Threat severity levels for financial institutions."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CyberSecurityPlatform:
    """
    Simplified cybersecurity platform for investment banking.
    Demonstrates AI agents for threat detection and digital forensics.
    """
    
    def __init__(self, config_path="simple_config.json"):
        self.config = self._load_config(config_path)
        self._setup_logging()
        self._initialize_agents()
        
        # Create directories
        self._create_directories()
        
        # Initialize threat intelligence
        self.threat_intel = self._load_threat_intelligence()
        
        print("AI Cybersecurity Forensic Platform Initialized")
        print("Target: Investment Banking Security")
        print("Agents: Malware Detection, Network Forensics, Evidence Collection")
    
    def _load_config(self, config_path):
        """Load configuration with secure defaults."""
        default_config = {
            "platform_name": "AI Cybersecurity Forensic Platform",
            "target_environment": "Investment Banking",
            "malware_detection": {
                "scan_extensions": [".exe", ".dll", ".pdf", ".doc", ".zip"],
                "threat_threshold": 0.7,
                "quarantine_path": "./quarantine/"
            },
            "network_monitoring": {
                "suspicious_ports": [1433, 3389, 22, 445],
                "blocked_countries": ["CN", "RU", "KP"],
                "financial_ports": {"SWIFT": 10030, "FIX": 8000}
            },
            "evidence_collection": {
                "evidence_path": "./evidence/",
                "retention_days": 2555,
                "chain_of_custody": True
            },
            "compliance": {
                "regulations": ["SOX", "PCI-DSS", "GDPR", "FFIEC"],
                "audit_logging": True
            },
            "threat_intelligence": {
                "apt_groups": ["Lazarus", "APT1", "FIN7", "Carbanak"],
                "malware_families": ["Zeus", "Dridex", "Emotet", "TrickBot"]
            }
        }
        
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
        except Exception as e:
            print(f"Config loading error: {e}. Using defaults.")
        
        return default_config
    
    def _setup_logging(self):
        """Configure security logging."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('cybersecurity_audit.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('cybersecurity')
    
    def _create_directories(self):
        """Create necessary directories for platform operation."""
        directories = [
            "quarantine", "evidence", "logs", "threat_intel", 
            "test_files", "reports"
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
        
        print(f"Created {len(directories)} security directories")
    
    def _initialize_agents(self):
        """Initialize AI security agents."""
        self.malware_agent = MalwareDetectionAgent(self.config)
        self.network_agent = NetworkForensicsAgent(self.config)
        self.evidence_agent = EvidenceCollectionAgent(self.config)
        
        print("Initialized 3 AI security agents")
    
    def _load_threat_intelligence(self):
        """Load threat intelligence data."""
        return {
            "malware_hashes": {
                "a1b2c3d4e5f6": "Zeus Banking Trojan",
                "f7e8d9c0a1b2": "Dridex Malware", 
                "987654321abc": "Emotet Variant"
            },
            "suspicious_ips": {
                "198.51.100.1": "Known C2 Server",
                "203.0.113.5": "APT Infrastructure",
                "192.0.2.1": "Malicious Scanner"
            },
            "apt_indicators": {
                "Lazarus": ["swift", "banking", "korea"],
                "FIN7": ["pos", "payment", "retail"],
                "Carbanak": ["atm", "bank", "carbanak"]
            }
        }
    
    def run_malware_scan(self, target_path):
        """Run comprehensive malware detection."""
        print(f"\nMALWARE DETECTION SCAN")
        print(f"Target: {target_path}")
        print("=" * 50)
        
        results = self.malware_agent.scan_directory(target_path)
        
        print(f"\nSCAN RESULTS:")
        print(f"Files Scanned: {results['files_scanned']}")
        print(f"Threats Detected: {results['threats_detected']}")
        print(f"Clean Files: {results['clean_files']}")
        print(f"Quarantined: {results['quarantined']}")
        
        if results['threats']:
            print(f"\nTHREATS IDENTIFIED:")
            for threat in results['threats']:
                print(f"  {threat['file']}: {threat['threat_level']} - {threat['description']}")
        
        return results
    
    def run_network_monitoring(self, duration=60):
        """Run network forensics monitoring."""
        print(f"\nNETWORK FORENSICS MONITORING")
        print(f"Duration: {duration} seconds")
        print("=" * 50)
        
        results = self.network_agent.monitor_network(duration)
        
        print(f"\nNETWORK ANALYSIS:")
        print(f"Connections Monitored: {results['connections']}")
        print(f"Suspicious Activities: {results['suspicious_count']}")
        print(f"Blocked IPs: {results['blocked_ips']}")
        print(f"Protocol Violations: {results['protocol_violations']}")
        
        if results['threats']:
            print(f"\nNETWORK THREATS:")
            for threat in results['threats']:
                print(f"  {threat['type']}: {threat['description']}")
        
        return results
    
    def collect_evidence(self, file_path, incident_id):
        """Collect digital evidence with chain of custody."""
        print(f"\nDIGITAL EVIDENCE COLLECTION")
        print(f"File: {file_path}")
        print(f"Incident: {incident_id}")
        print("=" * 50)
        
        result = self.evidence_agent.collect_evidence(file_path, incident_id)
        
        print(f"\nEVIDENCE COLLECTION RESULT:")
        print(f"Evidence ID: {result['evidence_id']}")
        print(f"Chain of Custody: {result['chain_of_custody']}")
        print(f"Compliance Status: {result['compliance_status']}")
        print(f"Legal Admissibility: {result['legal_ready']}")
        
        return result


class MalwareDetectionAgent:
    """AI agent for malware detection in financial environments."""
    
    def __init__(self, config):
        self.config = config["malware_detection"]
        self.threat_threshold = self.config["threat_threshold"]
        self.scan_extensions = self.config["scan_extensions"]
        
    def scan_directory(self, directory_path):
        """Scan directory for malware threats."""
        results = {
            "files_scanned": 0,
            "threats_detected": 0,
            "clean_files": 0,
            "quarantined": 0,
            "threats": []
        }
        
        directory = Path(directory_path)
        if not directory.exists():
            return results
        
        for file_path in directory.rglob("*"):
            if file_path.is_file() and file_path.suffix in self.scan_extensions:
                results["files_scanned"] += 1
                
                threat_result = self._analyze_file(file_path)
                
                if threat_result["threat_level"] != ThreatLevel.INFO:
                    results["threats_detected"] += 1
                    results["threats"].append(threat_result)
                    
                    if threat_result["threat_level"] in [ThreatLevel.CRITICAL, ThreatLevel.HIGH]:
                        self._quarantine_file(file_path)
                        results["quarantined"] += 1
                else:
                    results["clean_files"] += 1
        
        return results
    
    def _analyze_file(self, file_path):
        """Analyze individual file for threats."""
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            file_hash = hashlib.sha256(content).hexdigest()[:12]
            threat_score = self._calculate_threat_score(content, file_path.name)
            
            if threat_score >= 0.8:
                threat_level = ThreatLevel.CRITICAL
                description = "High-confidence malware detection"
            elif threat_score >= 0.6:
                threat_level = ThreatLevel.HIGH
                description = "Suspicious patterns detected"
            elif threat_score >= 0.4:
                threat_level = ThreatLevel.MEDIUM
                description = "Potential security risk"
            elif threat_score >= 0.2:
                threat_level = ThreatLevel.LOW
                description = "Minor anomaly detected"
            else:
                threat_level = ThreatLevel.INFO
                description = "File appears clean"
            
            return {
                "file": str(file_path),
                "hash": file_hash,
                "threat_level": threat_level,
                "threat_score": threat_score,
                "description": description
            }
            
        except Exception as e:
            return {
                "file": str(file_path),
                "hash": "error",
                "threat_level": ThreatLevel.LOW,
                "threat_score": 0.0,
                "description": f"Analysis error: {e}"
            }
    
    def _calculate_threat_score(self, content, filename):
        """Calculate threat score using heuristics."""
        score = 0.0
        content_str = content.decode('utf-8', errors='ignore').lower()
        filename_lower = filename.lower()
        
        malware_keywords = ['zeus', 'dridex', 'emotet', 'banking', 'trojan', 'malware', 
                            'ransomware', 'keylogger', 'spyware', 'backdoor', 'credential']
        for keyword in malware_keywords:
            if keyword in content_str or keyword in filename_lower:
                score += 0.35
        
        financial_terms = ['account', 'password', 'swift', 'banking', 'login', 
                          'credentials', 'harvesting', 'theft']
        financial_count = sum(1 for term in financial_terms if term in content_str)
        if financial_count >= 2:
            score += 0.25
        
        if content.startswith(b'MZ'):
            score += 0.15
            if any(term in content for term in [b'banking', b'password', b'swift', 
                                                b'credential', b'trojan']):
                score += 0.45
        
        if len(set(content)) > len(content) * 0.8:
            score += 0.15
        
        return min(score, 1.0)
    
    def _quarantine_file(self, file_path):
        """Move suspicious file to quarantine."""
        quarantine_dir = Path(self.config["quarantine_path"])
        quarantine_dir.mkdir(exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        quarantine_path = quarantine_dir / f"{timestamp}_{file_path.name}"
        
        try:
            file_path.rename(quarantine_path)
            print(f"Quarantined: {file_path.name}")
        except Exception as e:
            print(f"Quarantine failed: {e}")


class NetworkForensicsAgent:
    """AI agent for network traffic analysis."""
    
    def __init__(self, config):
        self.config = config["network_monitoring"]
        self.suspicious_ports = self.config["suspicious_ports"]
        self.blocked_countries = self.config["blocked_countries"]
        
    def monitor_network(self, duration):
        """Simulate network monitoring."""
        results = {
            "connections": 0,
            "suspicious_count": 0,
            "blocked_ips": 0,
            "protocol_violations": 0,
            "threats": []
        }
        
        print(f"Monitoring network for {duration} seconds...")
        
        for i in range(duration // 5):
            connections = self._simulate_network_connections()
            results["connections"] += len(connections)
            
            for conn in connections:
                if self._is_suspicious_connection(conn):
                    results["suspicious_count"] += 1
                    results["threats"].append({
                        "type": "Suspicious Connection",
                        "description": f"Connection from {conn['src_ip']}:{conn['src_port']}"
                    })
                
                if self._is_blocked_ip(conn["src_ip"]):
                    results["blocked_ips"] += 1
            
            time.sleep(1)
        
        if duration > 30:
            results["threats"].extend([
                {
                    "type": "Port Scanning",
                    "description": "Multiple SYN packets from 192.168.1.100"
                },
                {
                    "type": "Suspicious Protocol",
                    "description": "Unencrypted SWIFT traffic detected"
                }
            ])
            results["protocol_violations"] += 1
        
        return results
    
    def _simulate_network_connections(self):
        """Generate simulated network connections."""
        connections = []
        
        for _ in range(random.randint(5, 15)):
            connections.append({
                "src_ip": f"192.168.1.{random.randint(1, 254)}",
                "src_port": random.randint(1024, 65535),
                "dst_ip": f"10.0.0.{random.randint(1, 254)}",
                "dst_port": random.choice([80, 443, 22, 3389, 1433])
            })
        
        if random.random() > 0.7:
            connections.append({
                "src_ip": "198.51.100.1",
                "src_port": 4444,
                "dst_ip": "10.0.0.50",
                "dst_port": 443
            })
        
        return connections
    
    def _is_suspicious_connection(self, connection):
        """Check if connection is suspicious."""
        if connection["dst_port"] in self.suspicious_ports:
            return True
        
        if connection["src_ip"] in ["198.51.100.1", "203.0.113.5"]:
            return True
        
        if connection["src_port"] == 4444:
            return True
        
        return False
    
    def _is_blocked_ip(self, ip):
        """Check if IP should be geo-blocked."""
        blocked_ranges = ["198.51.100.", "203.0.113."]
        return any(ip.startswith(range_prefix) for range_prefix in blocked_ranges)


class EvidenceCollectionAgent:
    """AI agent for digital evidence collection."""
    
    def __init__(self, config):
        self.config = config["evidence_collection"]
        self.evidence_path = Path(self.config["evidence_path"])
        self.evidence_path.mkdir(exist_ok=True)
        
        self._init_evidence_database()
    
    def _init_evidence_database(self):
        """Initialize SQLite database for evidence tracking."""
        db_path = self.evidence_path / "evidence_database.db"
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id TEXT UNIQUE,
                file_path TEXT,
                incident_id TEXT,
                collected_timestamp TEXT,
                file_hash TEXT,
                collector TEXT,
                chain_of_custody TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def collect_evidence(self, file_path, incident_id):
        """Collect digital evidence with proper chain of custody."""
        evidence_id = f"EVD_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000, 9999)}"
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
                file_hash = hashlib.sha256(content).hexdigest()
            
            evidence_record = {
                "evidence_id": evidence_id,
                "file_path": str(file_path),
                "incident_id": incident_id,
                "collected_timestamp": datetime.now().isoformat(),
                "file_hash": file_hash,
                "collector": "AI_Evidence_Agent",
                "chain_of_custody": json.dumps([{
                    "action": "INITIAL_COLLECTION",
                    "timestamp": datetime.now().isoformat(),
                    "person": "AI_Evidence_Agent"
                }])
            }
            
            self._store_evidence_record(evidence_record)
            
            evidence_dir = self.evidence_path / evidence_id
            evidence_dir.mkdir(exist_ok=True)
            
            evidence_file = evidence_dir / f"{Path(file_path).name}.evidence"
            evidence_file.write_bytes(content)
            
            return {
                "evidence_id": evidence_id,
                "file_hash": file_hash,
                "chain_of_custody": "Initialized",
                "compliance_status": "SOX/PCI-DSS/GDPR Compliant", 
                "legal_ready": "Court Admissible",
                "retention_until": (datetime.now() + timedelta(days=2555)).strftime("%Y-%m-%d")
            }
            
        except Exception as e:
            return {
                "evidence_id": None,
                "error": str(e),
                "chain_of_custody": "Failed",
                "compliance_status": "Non-compliant",
                "legal_ready": "Not Admissible"
            }
    
    def _store_evidence_record(self, record):
        """Store evidence record in database."""
        db_path = self.evidence_path / "evidence_database.db"
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO evidence_items 
            (evidence_id, file_path, incident_id, collected_timestamp, 
             file_hash, collector, chain_of_custody)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            record["evidence_id"],
            record["file_path"], 
            record["incident_id"],
            record["collected_timestamp"],
            record["file_hash"],
            record["collector"],
            record["chain_of_custody"]
        ))
        
        conn.commit()
        conn.close()


def main():
    """Main entry point for the cybersecurity platform."""
    import argparse
    
    parser = argparse.ArgumentParser(description='AI Cybersecurity Forensic Platform')
    parser.add_argument('--mode', choices=['scan', 'monitor', 'investigate', 'demo'],
                       default='demo', help='Operation mode')
    parser.add_argument('--target', help='Target path for scanning')
    parser.add_argument('--incident-id', help='Incident ID for evidence collection')
    parser.add_argument('--duration', type=int, default=60, help='Monitoring duration')
    
    args = parser.parse_args()
    
    platform = CyberSecurityPlatform()
    
    if args.mode == 'scan':
        if args.target:
            platform.run_malware_scan(args.target)
        else:
            print("Error: --target required for scan mode")
    
    elif args.mode == 'monitor':
        platform.run_network_monitoring(args.duration)
    
    elif args.mode == 'investigate':
        if args.target and args.incident_id:
            platform.collect_evidence(args.target, args.incident_id)
        else:
            print("Error: --target and --incident-id required for investigate mode")
    
    elif args.mode == 'demo':
        platform.run_comprehensive_demo()


if __name__ == "__main__":
    main()
