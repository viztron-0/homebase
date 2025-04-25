#!/usr/bin/env python3
"""
Security Manager for Viztron Homebase Module

This module implements the security functionality for the
Viztron Homebase Module, handling encryption, authentication,
access control, and intrusion detection.

Author: Viztron System Team
Date: April 20, 2025
"""

import os
import sys
import time
import logging
import json
import threading
import queue
import socket
import ssl
import uuid
import hashlib
import hmac
import base64
import secrets
import re
import subprocess
import ipaddress
from typing import Dict, List, Any, Optional, Tuple, Set, Union, Callable
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/viztron/security_manager.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('security_manager')

class SecurityLevel(Enum):
    """Enumeration of security levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


class EncryptionAlgorithm(Enum):
    """Enumeration of supported encryption algorithms."""
    AES_256_GCM = "AES-256-GCM"
    AES_256_CBC = "AES-256-CBC"
    CHACHA20_POLY1305 = "ChaCha20-Poly1305"


class HashAlgorithm(Enum):
    """Enumeration of supported hash algorithms."""
    SHA256 = "SHA-256"
    SHA384 = "SHA-384"
    SHA512 = "SHA-512"
    BLAKE2B = "BLAKE2b"


class SecurityManager:
    """
    Main security manager for the Viztron Homebase Module.
    
    This class provides a unified interface for security operations,
    including encryption, authentication, access control, and intrusion detection.
    """
    
    def __init__(self, config_path: str = "/etc/viztron/security_config.json"):
        """
        Initialize the security manager.
        
        Args:
            config_path: Path to the security configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        
        # Create required directories
        os.makedirs("/var/log/viztron", exist_ok=True)
        os.makedirs("/var/lib/viztron/security", exist_ok=True)
        
        # Initialize encryption keys
        self.encryption_keys = self._load_encryption_keys()
        
        # Initialize authentication tokens
        self.auth_tokens = {}
        
        # Initialize access control lists
        self.acls = self._load_acls()
        
        # Initialize intrusion detection
        self.ids_events = queue.Queue()
        self.ids_rules = self._load_ids_rules()
        
        # Initialize firewall
        self._initialize_firewall()
        
        # Start security monitoring thread
        self.running = True
        self.monitoring_thread = threading.Thread(target=self._security_monitoring_loop)
        self.monitoring_thread.daemon = True
        self.monitoring_thread.start()
        
        # Create PID file
        self._create_pid_file()
        
        logger.info("Security manager initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load security configuration from file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                return {
                    "security_level": "high",
                    "encryption": {
                        "algorithm": "AES-256-GCM",
                        "key_rotation_interval": 86400,  # 24 hours
                        "key_size": 32  # 256 bits
                    },
                    "authentication": {
                        "token_expiration": 3600,  # 1 hour
                        "max_failed_attempts": 5,
                        "lockout_duration": 900,  # 15 minutes
                        "password_policy": {
                            "min_length": 12,
                            "require_uppercase": True,
                            "require_lowercase": True,
                            "require_numbers": True,
                            "require_special": True,
                            "max_age": 90  # days
                        }
                    },
                    "access_control": {
                        "default_policy": "deny",
                        "admin_roles": ["admin", "security_admin"],
                        "user_roles": ["user", "operator", "viewer"]
                    },
                    "intrusion_detection": {
                        "enabled": True,
                        "sensitivity": "medium",
                        "log_retention": 30,  # days
                        "alert_threshold": 3,
                        "scan_interval": 300  # 5 minutes
                    },
                    "firewall": {
                        "enabled": True,
                        "default_policy": "deny",
                        "allowed_services": ["ssh", "http", "https", "mqtt"],
                        "allowed_ips": ["192.168.1.0/24"],
                        "blocked_ips": []
                    },
                    "secure_boot": {
                        "enabled": True,
                        "verify_signatures": True,
                        "allow_recovery": True
                    },
                    "secure_storage": {
                        "encrypt_sensitive_data": True,
                        "encrypt_configuration": True,
                        "encrypt_credentials": True
                    },
                    "audit": {
                        "enabled": True,
                        "log_level": "info",
                        "log_retention": 90,  # days
                        "log_rotation": 10  # MB
                    }
                }
        except Exception as e:
            logger.error(f"Failed to load security config: {str(e)}")
            return {
                "security_level": "high",
                "encryption": {
                    "algorithm": "AES-256-GCM",
                    "key_rotation_interval": 86400
                },
                "authentication": {
                    "token_expiration": 3600
                },
                "access_control": {
                    "default_policy": "deny"
                },
                "intrusion_detection": {
                    "enabled": True
                },
                "firewall": {
                    "enabled": True
                }
            }
    
    def _save_config(self):
        """Save security configuration to file."""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save security config: {str(e)}")
    
    def _create_pid_file(self):
        """Create PID file for the security manager."""
        try:
            pid = os.getpid()
            pid_dir = "/var/run/viztron"
            os.makedirs(pid_dir, exist_ok=True)
            
            with open(f"{pid_dir}/security_manager.pid", 'w') as f:
                f.write(str(pid))
            
            logger.debug(f"Created PID file with PID {pid}")
        except Exception as e:
            logger.error(f"Failed to create PID file: {str(e)}")
    
    def _load_encryption_keys(self) -> Dict[str, Dict[str, Any]]:
        """
        Load encryption keys from secure storage.
        
        Returns:
            Dictionary of encryption keys
        """
        try:
            keys_file = "/var/lib/viztron/security/encryption_keys.json"
            
            if os.path.exists(keys_file):
                # Load keys from file
                with open(keys_file, 'r') as f:
                    keys = json.load(f)
                
                # Check if keys need rotation
                current_time = int(time.time())
                key_rotation_interval = self.config.get("encryption", {}).get("key_rotation_interval", 86400)
                
                for key_id, key_data in list(keys.items()):
                    created_at = key_data.get("created_at", 0)
                    
                    if current_time - created_at > key_rotation_interval:
                        # Key is expired, generate a new one
                        logger.info(f"Rotating encryption key {key_id}")
                        
                        # Keep the old key for decryption
                        keys[key_id]["active"] = False
                        
                        # Generate a new key
                        new_key_id = str(uuid.uuid4())
                        keys[new_key_id] = self._generate_encryption_key()
            else:
                # Generate initial keys
                logger.info("Generating initial encryption keys")
                
                keys = {
                    str(uuid.uuid4()): self._generate_encryption_key()
                }
            
            # Save keys to file
            with open(keys_file, 'w') as f:
                json.dump(keys, f, indent=2)
            
            return keys
        except Exception as e:
            logger.error(f"Failed to load encryption keys: {str(e)}")
            
            # Generate a temporary key
            key_id = str(uuid.uuid4())
            return {
                key_id: self._generate_encryption_key()
            }
    
    def _generate_encryption_key(self) -> Dict[str, Any]:
        """
        Generate a new encryption key.
        
        Returns:
            Dictionary containing key data
        """
        try:
            # Get key size from config
            key_size = self.config.get("encryption", {}).get("key_size", 32)
            
            # Generate random key
            key = secrets.token_bytes(key_size)
            
            # Generate random IV
            iv = secrets.token_bytes(16)
            
            # Create key data
            key_data = {
                "key": base64.b64encode(key).decode('utf-8'),
                "iv": base64.b64encode(iv).decode('utf-8'),
                "algorithm": self.config.get("encryption", {}).get("algorithm", "AES-256-GCM"),
                "created_at": int(time.time()),
                "active": True
            }
            
            return key_data
        except Exception as e:
            logger.error(f"Failed to generate encryption key: {str(e)}")
            raise
    
    def _get_active_encryption_key(self) -> Tuple[str, Dict[str, Any]]:
        """
        Get the active encryption key.
        
        Returns:
            Tuple of (key_id, key_data)
        """
        try:
            # Find active key
            for key_id, key_data in self.encryption_keys.items():
                if key_data.get("active", False):
                    return key_id, key_data
            
            # No active key found, generate a new one
            logger.warning("No active encryption key found, generating a new one")
            
            key_id = str(uuid.uuid4())
            key_data = self._generate_encryption_key()
            self.encryption_keys[key_id] = key_data
            
            # Save keys to file
            keys_file = "/var/lib/viztron/security/encryption_keys.json"
            with open(keys_file, 'w') as f:
                json.dump(self.encryption_keys, f, indent=2)
            
            return key_id, key_data
        except Exception as e:
            logger.error(f"Failed to get active encryption key: {str(e)}")
            raise
    
    def _load_acls(self) -> Dict[str, Dict[str, Any]]:
        """
        Load access control lists from storage.
        
        Returns:
            Dictionary of ACLs
        """
        try:
            acls_file = "/var/lib/viztron/security/acls.json"
            
            if os.path.exists(acls_file):
                # Load ACLs from file
                with open(acls_file, 'r') as f:
                    return json.load(f)
            else:
                # Generate default ACLs
                logger.info("Generating default ACLs")
                
                # Get roles from config
                admin_roles = self.config.get("access_control", {}).get("admin_roles", ["admin"])
                user_roles = self.config.get("access_control", {}).get("user_roles", ["user"])
                
                # Create default ACLs
                acls = {
                    "resources": {
                        "system": {
                            "actions": ["read", "write", "execute"],
                            "roles": admin_roles
                        },
                        "devices": {
                            "actions": ["read", "write", "control"],
                            "roles": admin_roles + user_roles
                        },
                        "cameras": {
                            "actions": ["read", "write", "control"],
                            "roles": admin_roles + user_roles
                        },
                        "zones": {
                            "actions": ["read", "write", "arm", "disarm"],
                            "roles": admin_roles + user_roles
                        },
                        "users": {
                            "actions": ["read", "write", "delete"],
                            "roles": admin_roles
                        },
                        "events": {
                            "actions": ["read", "write", "delete"],
                            "roles": admin_roles + user_roles
                        },
                        "logs": {
                            "actions": ["read", "delete"],
                            "roles": admin_roles
                        },
                        "config": {
                            "actions": ["read", "write"],
                            "roles": admin_roles
                        }
                    }
                }
                
                # Save ACLs to file
                with open(acls_file, 'w') as f:
                    json.dump(acls, f, indent=2)
                
                return acls
        except Exception as e:
            logger.error(f"Failed to load ACLs: {str(e)}")
            
            # Return empty ACLs
            return {
                "resources": {}
            }
    
    def _save_acls(self):
        """Save ACLs to storage."""
        try:
            acls_file = "/var/lib/viztron/security/acls.json"
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(acls_file), exist_ok=True)
            
            # Save ACLs to file
            with open(acls_file, 'w') as f:
                json.dump(self.acls, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save ACLs: {str(e)}")
    
    def _load_ids_rules(self) -> List[Dict[str, Any]]:
        """
        Load intrusion detection rules from storage.
        
        Returns:
            List of IDS rules
        """
        try:
            rules_file = "/var/lib/viztron/security/ids_rules.json"
            
            if os.path.exists(rules_file):
                # Load rules from file
                with open(rules_file, 'r') as f:
                    return json.load(f)
            else:
                # Generate default rules
                logger.info("Generating default IDS rules")
                
                # Create default rules
                rules = [
                    {
                        "id": "auth-failed",
                        "name": "Authentication Failure",
                        "pattern": "authentication failed|login failed|invalid password",
                        "log_file": "/var/log/auth.log",
                        "severity": "medium",
                        "threshold": 5,
                        "timeframe": 300,  # 5 minutes
                        "action": "alert"
                    },
                    {
                        "id": "ssh-scan",
                        "name": "SSH Scan",
                        "pattern": "Invalid user|Failed password|Connection closed by authenticating user",
                        "log_file": "/var/log/auth.log",
                        "severity": "high",
                        "threshold": 10,
                        "timeframe": 300,  # 5 minutes
                        "action": "block"
                    },
                    {
                        "id": "web-attack",
                        "name": "Web Attack",
                        "pattern": "SQL injection|XSS|CSRF|directory traversal|\\.\\.%2f|\\.\\.%5c",
                        "log_file": "/var/log/viztron/http.log",
                        "severity": "high",
                        "threshold": 3,
                        "timeframe": 300,  # 5 minutes
                        "action": "block"
                    },
                    {
                        "id": "api-abuse",
                        "name": "API Abuse",
                        "pattern": "rate limit exceeded|too many requests|API key invalid",
                        "log_file": "/var/log/viztron/api.log",
                        "severity": "medium",
                        "threshold": 10,
                        "timeframe": 300,  # 5 minutes
                        "action": "alert"
                    },
                    {
                        "id": "system-change",
                        "name": "System File Change",
                        "pattern": "modified|changed|replaced",
                        "log_file": "/var/log/viztron/system.log",
                        "severity": "high",
                        "threshold": 1,
                        "timeframe": 300,  # 5 minutes
                        "action": "alert"
                    }
                ]
                
                # Save rules to file
                with open(rules_file, 'w') as f:
                    json.dump(rules, f, indent=2)
                
                return rules
        except Exception as e:
            logger.error(f"Failed to load IDS rules: {str(e)}")
            
            # Return empty rules
            return []
    
    def _initialize_firewall(self):
        """Initialize firewall rules."""
        try:
            # Check if firewall is enabled
            if not self.config.get("firewall", {}).get("enabled", True):
                logger.info("Firewall is disabled")
                return
            
            # Get firewall configuration
            firewall_config = self.config.get("firewall", {})
            default_policy = firewall_config.get("default_policy", "deny")
            allowed_services = firewall_config.get("allowed_services", [])
            allowed_ips = firewall_config.get("allowed_ips", [])
            blocked_ips = firewall_config.get("blocked_ips", [])
            
            # Check if iptables is available
            try:
                subprocess.run(["iptables", "--version"], check=True, capture_output=True)
            except (subprocess.SubprocessError, FileNotFoundError):
                logger.error("iptables not available, cannot initialize firewall")
                return
            
            # Flush existing rules
            subprocess.run(["iptables", "-F"], check=True)
            
            # Set default policies
            if default_policy == "deny":
                subprocess.run(["iptables", "-P", "INPUT", "DROP"], check=True)
                subprocess.run(["iptables", "-P", "FORWARD", "DROP"], check=True)
            else:
                subprocess.run(["iptables", "-P", "INPUT", "ACCEPT"], check=True)
                subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=True)
            
            # Always allow loopback
            subprocess.run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
            
            # Allow established connections
            subprocess.run(["iptables", "-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"], check=True)
            
            # Allow specific services
            service_ports = {
                "ssh": 22,
                "http": 80,
                "https": 443,
                "mqtt": 1883,
                "mqtts": 8883,
                "websocket": 8080,
                "websockets": 8443,
                "rtsp": 554,
                "rtmp": 1935,
                "dns": 53,
                "ntp": 123,
                "dhcp": 67
            }
            
            for service in allowed_services:
                if service in service_ports:
                    port = service_ports[service]
                    subprocess.run(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "ACCEPT"], check=True)
                    
                    # Allow UDP for certain services
                    if service in ["dns", "ntp", "dhcp"]:
                        subprocess.run(["iptables", "-A", "INPUT", "-p", "udp", "--dport", str(port), "-j", "ACCEPT"], check=True)
            
            # Allow specific IPs
            for ip_range in allowed_ips:
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip_range, "-j", "ACCEPT"], check=True)
            
            # Block specific IPs
            for ip_range in blocked_ips:
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip_range, "-j", "DROP"], check=True)
            
            logger.info("Firewall initialized")
        except Exception as e:
            logger.error(f"Failed to initialize firewall: {str(e)}")
    
    def _security_monitoring_loop(self):
        """Main security monitoring loop that runs in a separate thread."""
        logger.info("Security monitoring thread started")
        
        # Get monitoring interval
        scan_interval = self.config.get("intrusion_detection", {}).get("scan_interval", 300)
        
        # Initialize counters
        event_counters = {}
        
        while self.running:
            try:
                # Check for IDS events
                while not self.ids_events.empty():
                    event = self.ids_events.get()
                    
                    # Process event
                    rule_id = event.get("rule_id")
                    source_ip = event.get("source_ip")
                    timestamp = event.get("timestamp", int(time.time()))
                    
                    # Create counter key
                    key = f"{rule_id}:{source_ip}"
                    
                    # Initialize or update counter
                    if key not in event_counters:
                        event_counters[key] = {
                            "count": 1,
                            "first_seen": timestamp,
                            "last_seen": timestamp,
                            "rule_id": rule_id,
                            "source_ip": source_ip,
                            "alerted": False,
                            "blocked": False
                        }
                    else:
                        event_counters[key]["count"] += 1
                        event_counters[key]["last_seen"] = timestamp
                
                # Check counters against thresholds
                current_time = int(time.time())
                
                for key, counter in list(event_counters.items()):
                    # Skip if already blocked
                    if counter["blocked"]:
                        continue
                    
                    # Find matching rule
                    rule = None
                    for r in self.ids_rules:
                        if r["id"] == counter["rule_id"]:
                            rule = r
                            break
                    
                    if not rule:
                        continue
                    
                    # Check if within timeframe
                    timeframe = rule.get("timeframe", 300)
                    if current_time - counter["first_seen"] > timeframe:
                        # Reset counter if outside timeframe
                        event_counters.pop(key)
                        continue
                    
                    # Check if threshold exceeded
                    threshold = rule.get("threshold", 5)
                    if counter["count"] >= threshold:
                        # Threshold exceeded
                        severity = rule.get("severity", "medium")
                        action = rule.get("action", "alert")
                        
                        # Log alert
                        logger.warning(
                            f"IDS Alert: Rule '{rule['name']}' triggered by {counter['source_ip']} "
                            f"({counter['count']} events in {timeframe} seconds)"
                        )
                        
                        # Take action
                        if action == "alert" and not counter["alerted"]:
                            # Send alert
                            self._send_security_alert(rule, counter)
                            counter["alerted"] = True
                        elif action == "block" and not counter["blocked"]:
                            # Block IP
                            self._block_ip(counter["source_ip"])
                            counter["blocked"] = True
                            
                            # Send alert
                            self._send_security_alert(rule, counter)
                            counter["alerted"] = True
                
                # Scan log files for new events
                self._scan_log_files()
                
                # Sleep for scan interval
                # Use shorter sleep intervals to allow for clean shutdown
                for _ in range(scan_interval):
                    if not self.running:
                        break
                    time.sleep(1)
            except Exception as e:
                logger.error(f"Error in security monitoring loop: {str(e)}")
                time.sleep(60)  # Sleep for 1 minute before retrying
    
    def _scan_log_files(self):
        """Scan log files for security events."""
        try:
            # Check if intrusion detection is enabled
            if not self.config.get("intrusion_detection", {}).get("enabled", True):
                return
            
            # Get current time
            current_time = int(time.time())
            
            # Scan each rule
            for rule in self.ids_rules:
                log_file = rule.get("log_file")
                pattern = rule.get("pattern")
                
                if not log_file or not pattern or not os.path.exists(log_file):
                    continue
                
                # Compile regex pattern
                regex = re.compile(pattern, re.IGNORECASE)
                
                # Get file size
                file_size = os.path.getsize(log_file)
                
                # Get last scan position
                last_pos_file = f"/var/lib/viztron/security/ids_pos_{rule['id']}.txt"
                last_pos = 0
                
                if os.path.exists(last_pos_file):
                    with open(last_pos_file, 'r') as f:
                        try:
                            last_pos = int(f.read().strip())
                        except ValueError:
                            last_pos = 0
                
                # Check if file was rotated
                if file_size < last_pos:
                    last_pos = 0
                
                # Open log file and seek to last position
                with open(log_file, 'r') as f:
                    f.seek(last_pos)
                    
                    # Read new lines
                    for line in f:
                        # Check if line matches pattern
                        if regex.search(line):
                            # Extract source IP if present
                            ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                            source_ip = ip_match.group(0) if ip_match else "unknown"
                            
                            # Create event
                            event = {
                                "rule_id": rule["id"],
                                "source_ip": source_ip,
                                "timestamp": current_time,
                                "log_line": line.strip()
                            }
                            
                            # Add to event queue
                            self.ids_events.put(event)
                    
                    # Update last position
                    last_pos = f.tell()
                
                # Save last position
                with open(last_pos_file, 'w') as f:
                    f.write(str(last_pos))
        except Exception as e:
            logger.error(f"Failed to scan log files: {str(e)}")
    
    def _send_security_alert(self, rule: Dict[str, Any], counter: Dict[str, Any]):
        """
        Send a security alert.
        
        Args:
            rule: IDS rule that triggered the alert
            counter: Event counter
        """
        try:
            # Create alert message
            alert = {
                "type": "security_alert",
                "timestamp": int(time.time()),
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "source_ip": counter["source_ip"],
                "count": counter["count"],
                "first_seen": counter["first_seen"],
                "last_seen": counter["last_seen"],
                "action_taken": "blocked" if counter["blocked"] else "alerted"
            }
            
            # Log alert
            logger.warning(f"Security Alert: {json.dumps(alert)}")
            
            # TODO: Send alert to notification system
        except Exception as e:
            logger.error(f"Failed to send security alert: {str(e)}")
    
    def _block_ip(self, ip_address: str):
        """
        Block an IP address.
        
        Args:
            ip_address: IP address to block
        """
        try:
            # Validate IP address
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                logger.error(f"Invalid IP address: {ip_address}")
                return
            
            # Add to iptables
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            
            # Add to blocked IPs list
            blocked_ips = self.config.get("firewall", {}).get("blocked_ips", [])
            if ip_address not in blocked_ips:
                blocked_ips.append(ip_address)
                self.config["firewall"]["blocked_ips"] = blocked_ips
                self._save_config()
            
            logger.info(f"Blocked IP address: {ip_address}")
        except Exception as e:
            logger.error(f"Failed to block IP address {ip_address}: {str(e)}")
    
    def _unblock_ip(self, ip_address: str):
        """
        Unblock an IP address.
        
        Args:
            ip_address: IP address to unblock
        """
        try:
            # Validate IP address
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                logger.error(f"Invalid IP address: {ip_address}")
                return
            
            # Remove from iptables
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            
            # Remove from blocked IPs list
            blocked_ips = self.config.get("firewall", {}).get("blocked_ips", [])
            if ip_address in blocked_ips:
                blocked_ips.remove(ip_address)
                self.config["firewall"]["blocked_ips"] = blocked_ips
                self._save_config()
            
            logger.info(f"Unblocked IP address: {ip_address}")
        except Exception as e:
            logger.error(f"Failed to unblock IP address {ip_address}: {str(e)}")
    
    def encrypt_data(self, data: Union[str, bytes, Dict[str, Any], List[Any]]) -> Dict[str, Any]:
        """
        Encrypt data.
        
        Args:
            data: Data to encrypt
            
        Returns:
            Dictionary containing encrypted data and metadata
        """
        try:
            # Convert data to JSON if it's a dictionary or list
            if isinstance(data, (dict, list)):
                data = json.dumps(data)
            
            # Convert data to bytes if it's a string
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Get active encryption key
            key_id, key_data = self._get_active_encryption_key()
            
            # Get key and IV
            key = base64.b64decode(key_data["key"])
            iv = base64.b64decode(key_data["iv"])
            
            # Get algorithm
            algorithm = key_data["algorithm"]
            
            # Encrypt data
            if algorithm == "AES-256-GCM":
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                
                # Generate random nonce
                nonce = secrets.token_bytes(12)
                
                # Create cipher
                cipher = AESGCM(key)
                
                # Encrypt data
                ciphertext = cipher.encrypt(nonce, data, None)
                
                # Create result
                result = {
                    "algorithm": algorithm,
                    "key_id": key_id,
                    "nonce": base64.b64encode(nonce).decode('utf-8'),
                    "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
                }
            elif algorithm == "AES-256-CBC":
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.primitives import padding
                
                # Create padder
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(data) + padder.finalize()
                
                # Create cipher
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                encryptor = cipher.encryptor()
                
                # Encrypt data
                ciphertext = encryptor.update(padded_data) + encryptor.finalize()
                
                # Create result
                result = {
                    "algorithm": algorithm,
                    "key_id": key_id,
                    "iv": base64.b64encode(iv).decode('utf-8'),
                    "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
                }
            elif algorithm == "ChaCha20-Poly1305":
                from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
                
                # Generate random nonce
                nonce = secrets.token_bytes(12)
                
                # Create cipher
                cipher = ChaCha20Poly1305(key)
                
                # Encrypt data
                ciphertext = cipher.encrypt(nonce, data, None)
                
                # Create result
                result = {
                    "algorithm": algorithm,
                    "key_id": key_id,
                    "nonce": base64.b64encode(nonce).decode('utf-8'),
                    "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
                }
            else:
                raise ValueError(f"Unsupported encryption algorithm: {algorithm}")
            
            return result
        except Exception as e:
            logger.error(f"Failed to encrypt data: {str(e)}")
            raise
    
    def decrypt_data(self, encrypted_data: Dict[str, Any]) -> bytes:
        """
        Decrypt data.
        
        Args:
            encrypted_data: Dictionary containing encrypted data and metadata
            
        Returns:
            Decrypted data as bytes
        """
        try:
            # Get encryption metadata
            algorithm = encrypted_data.get("algorithm")
            key_id = encrypted_data.get("key_id")
            ciphertext = base64.b64decode(encrypted_data.get("ciphertext"))
            
            # Get encryption key
            if key_id not in self.encryption_keys:
                raise ValueError(f"Encryption key not found: {key_id}")
            
            key_data = self.encryption_keys[key_id]
            key = base64.b64decode(key_data["key"])
            
            # Decrypt data
            if algorithm == "AES-256-GCM":
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                
                # Get nonce
                nonce = base64.b64decode(encrypted_data.get("nonce"))
                
                # Create cipher
                cipher = AESGCM(key)
                
                # Decrypt data
                plaintext = cipher.decrypt(nonce, ciphertext, None)
            elif algorithm == "AES-256-CBC":
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.primitives import padding
                
                # Get IV
                iv = base64.b64decode(encrypted_data.get("iv"))
                
                # Create cipher
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                
                # Decrypt data
                padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
                
                # Remove padding
                unpadder = padding.PKCS7(128).unpadder()
                plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
            elif algorithm == "ChaCha20-Poly1305":
                from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
                
                # Get nonce
                nonce = base64.b64decode(encrypted_data.get("nonce"))
                
                # Create cipher
                cipher = ChaCha20Poly1305(key)
                
                # Decrypt data
                plaintext = cipher.decrypt(nonce, ciphertext, None)
            else:
                raise ValueError(f"Unsupported encryption algorithm: {algorithm}")
            
            return plaintext
        except Exception as e:
            logger.error(f"Failed to decrypt data: {str(e)}")
            raise
    
    def hash_data(self, data: Union[str, bytes], algorithm: str = "SHA-256") -> str:
        """
        Hash data.
        
        Args:
            data: Data to hash
            algorithm: Hash algorithm to use
            
        Returns:
            Hex-encoded hash
        """
        try:
            # Convert data to bytes if it's a string
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Hash data
            if algorithm == "SHA-256":
                hash_obj = hashlib.sha256(data)
            elif algorithm == "SHA-384":
                hash_obj = hashlib.sha384(data)
            elif algorithm == "SHA-512":
                hash_obj = hashlib.sha512(data)
            elif algorithm == "BLAKE2b":
                hash_obj = hashlib.blake2b(data)
            else:
                raise ValueError(f"Unsupported hash algorithm: {algorithm}")
            
            # Return hex-encoded hash
            return hash_obj.hexdigest()
        except Exception as e:
            logger.error(f"Failed to hash data: {str(e)}")
            raise
    
    def verify_hash(self, data: Union[str, bytes], hash_value: str, algorithm: str = "SHA-256") -> bool:
        """
        Verify a hash.
        
        Args:
            data: Data to verify
            hash_value: Expected hash value
            algorithm: Hash algorithm to use
            
        Returns:
            True if hash matches, False otherwise
        """
        try:
            # Calculate hash
            calculated_hash = self.hash_data(data, algorithm)
            
            # Compare hashes
            return calculated_hash == hash_value
        except Exception as e:
            logger.error(f"Failed to verify hash: {str(e)}")
            return False
    
    def generate_hmac(self, data: Union[str, bytes], key: Union[str, bytes], algorithm: str = "SHA-256") -> str:
        """
        Generate HMAC.
        
        Args:
            data: Data to sign
            key: Key to use
            algorithm: Hash algorithm to use
            
        Returns:
            Hex-encoded HMAC
        """
        try:
            # Convert data to bytes if it's a string
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Convert key to bytes if it's a string
            if isinstance(key, str):
                key = key.encode('utf-8')
            
            # Generate HMAC
            if algorithm == "SHA-256":
                hmac_obj = hmac.new(key, data, hashlib.sha256)
            elif algorithm == "SHA-384":
                hmac_obj = hmac.new(key, data, hashlib.sha384)
            elif algorithm == "SHA-512":
                hmac_obj = hmac.new(key, data, hashlib.sha512)
            else:
                raise ValueError(f"Unsupported HMAC algorithm: {algorithm}")
            
            # Return hex-encoded HMAC
            return hmac_obj.hexdigest()
        except Exception as e:
            logger.error(f"Failed to generate HMAC: {str(e)}")
            raise
    
    def verify_hmac(self, data: Union[str, bytes], hmac_value: str, key: Union[str, bytes], algorithm: str = "SHA-256") -> bool:
        """
        Verify an HMAC.
        
        Args:
            data: Data to verify
            hmac_value: Expected HMAC value
            key: Key to use
            algorithm: Hash algorithm to use
            
        Returns:
            True if HMAC matches, False otherwise
        """
        try:
            # Calculate HMAC
            calculated_hmac = self.generate_hmac(data, key, algorithm)
            
            # Compare HMACs
            return calculated_hmac == hmac_value
        except Exception as e:
            logger.error(f"Failed to verify HMAC: {str(e)}")
            return False
    
    def generate_token(self, user_id: str, expiration: int = None) -> str:
        """
        Generate an authentication token.
        
        Args:
            user_id: User ID
            expiration: Token expiration time in seconds
            
        Returns:
            Authentication token
        """
        try:
            # Get token expiration from config if not specified
            if expiration is None:
                expiration = self.config.get("authentication", {}).get("token_expiration", 3600)
            
            # Generate token
            token = secrets.token_hex(32)
            
            # Calculate expiration time
            expires_at = int(time.time()) + expiration
            
            # Store token
            self.auth_tokens[token] = {
                "user_id": user_id,
                "expires_at": expires_at,
                "created_at": int(time.time())
            }
            
            return token
        except Exception as e:
            logger.error(f"Failed to generate token: {str(e)}")
            raise
    
    def validate_token(self, token: str) -> Optional[str]:
        """
        Validate an authentication token.
        
        Args:
            token: Authentication token
            
        Returns:
            User ID if token is valid, None otherwise
        """
        try:
            # Check if token exists
            if token not in self.auth_tokens:
                return None
            
            # Get token data
            token_data = self.auth_tokens[token]
            
            # Check if token is expired
            if token_data["expires_at"] < int(time.time()):
                # Remove expired token
                del self.auth_tokens[token]
                return None
            
            # Return user ID
            return token_data["user_id"]
        except Exception as e:
            logger.error(f"Failed to validate token: {str(e)}")
            return None
    
    def revoke_token(self, token: str) -> bool:
        """
        Revoke an authentication token.
        
        Args:
            token: Authentication token
            
        Returns:
            True if token was revoked, False otherwise
        """
        try:
            # Check if token exists
            if token not in self.auth_tokens:
                return False
            
            # Remove token
            del self.auth_tokens[token]
            
            return True
        except Exception as e:
            logger.error(f"Failed to revoke token: {str(e)}")
            return False
    
    def revoke_user_tokens(self, user_id: str) -> int:
        """
        Revoke all tokens for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            Number of tokens revoked
        """
        try:
            # Find tokens for user
            tokens_to_revoke = []
            
            for token, token_data in self.auth_tokens.items():
                if token_data["user_id"] == user_id:
                    tokens_to_revoke.append(token)
            
            # Revoke tokens
            for token in tokens_to_revoke:
                del self.auth_tokens[token]
            
            return len(tokens_to_revoke)
        except Exception as e:
            logger.error(f"Failed to revoke user tokens: {str(e)}")
            return 0
    
    def cleanup_expired_tokens(self) -> int:
        """
        Clean up expired tokens.
        
        Returns:
            Number of tokens removed
        """
        try:
            # Find expired tokens
            current_time = int(time.time())
            tokens_to_remove = []
            
            for token, token_data in self.auth_tokens.items():
                if token_data["expires_at"] < current_time:
                    tokens_to_remove.append(token)
            
            # Remove expired tokens
            for token in tokens_to_remove:
                del self.auth_tokens[token]
            
            return len(tokens_to_remove)
        except Exception as e:
            logger.error(f"Failed to cleanup expired tokens: {str(e)}")
            return 0
    
    def check_access(self, user_id: str, resource: str, action: str) -> bool:
        """
        Check if a user has access to a resource.
        
        Args:
            user_id: User ID
            resource: Resource to access
            action: Action to perform
            
        Returns:
            True if access is allowed, False otherwise
        """
        try:
            # Get user roles
            # This would typically call a user manager module
            user_roles = self._get_user_roles(user_id)
            
            if not user_roles:
                return False
            
            # Get resource ACL
            resources = self.acls.get("resources", {})
            
            if resource not in resources:
                # Resource not found, use default policy
                default_policy = self.config.get("access_control", {}).get("default_policy", "deny")
                return default_policy == "allow"
            
            # Get resource ACL
            resource_acl = resources[resource]
            
            # Check if action is allowed
            allowed_actions = resource_acl.get("actions", [])
            allowed_roles = resource_acl.get("roles", [])
            
            if action not in allowed_actions:
                return False
            
            # Check if user has any of the allowed roles
            for role in user_roles:
                if role in allowed_roles:
                    return True
            
            return False
        except Exception as e:
            logger.error(f"Failed to check access: {str(e)}")
            return False
    
    def _get_user_roles(self, user_id: str) -> List[str]:
        """
        Get roles for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of user roles
        """
        try:
            # This would typically call a user manager module
            # For now, return a default role
            return ["user"]
        except Exception as e:
            logger.error(f"Failed to get user roles: {str(e)}")
            return []
    
    def add_resource_acl(self, resource: str, actions: List[str], roles: List[str]) -> bool:
        """
        Add or update a resource ACL.
        
        Args:
            resource: Resource name
            actions: Allowed actions
            roles: Allowed roles
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get resources
            resources = self.acls.get("resources", {})
            
            # Add or update resource ACL
            resources[resource] = {
                "actions": actions,
                "roles": roles
            }
            
            # Update ACLs
            self.acls["resources"] = resources
            
            # Save ACLs
            self._save_acls()
            
            return True
        except Exception as e:
            logger.error(f"Failed to add resource ACL: {str(e)}")
            return False
    
    def remove_resource_acl(self, resource: str) -> bool:
        """
        Remove a resource ACL.
        
        Args:
            resource: Resource name
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get resources
            resources = self.acls.get("resources", {})
            
            # Check if resource exists
            if resource not in resources:
                return False
            
            # Remove resource
            del resources[resource]
            
            # Update ACLs
            self.acls["resources"] = resources
            
            # Save ACLs
            self._save_acls()
            
            return True
        except Exception as e:
            logger.error(f"Failed to remove resource ACL: {str(e)}")
            return False
    
    def add_ids_rule(self, rule: Dict[str, Any]) -> bool:
        """
        Add or update an IDS rule.
        
        Args:
            rule: IDS rule
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check required fields
            required_fields = ["id", "name", "pattern", "log_file", "severity", "threshold", "timeframe", "action"]
            
            for field in required_fields:
                if field not in rule:
                    logger.error(f"Missing required field in IDS rule: {field}")
                    return False
            
            # Check if rule already exists
            for i, existing_rule in enumerate(self.ids_rules):
                if existing_rule["id"] == rule["id"]:
                    # Update existing rule
                    self.ids_rules[i] = rule
                    
                    # Save rules
                    rules_file = "/var/lib/viztron/security/ids_rules.json"
                    with open(rules_file, 'w') as f:
                        json.dump(self.ids_rules, f, indent=2)
                    
                    return True
            
            # Add new rule
            self.ids_rules.append(rule)
            
            # Save rules
            rules_file = "/var/lib/viztron/security/ids_rules.json"
            with open(rules_file, 'w') as f:
                json.dump(self.ids_rules, f, indent=2)
            
            return True
        except Exception as e:
            logger.error(f"Failed to add IDS rule: {str(e)}")
            return False
    
    def remove_ids_rule(self, rule_id: str) -> bool:
        """
        Remove an IDS rule.
        
        Args:
            rule_id: Rule ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Find rule
            for i, rule in enumerate(self.ids_rules):
                if rule["id"] == rule_id:
                    # Remove rule
                    del self.ids_rules[i]
                    
                    # Save rules
                    rules_file = "/var/lib/viztron/security/ids_rules.json"
                    with open(rules_file, 'w') as f:
                        json.dump(self.ids_rules, f, indent=2)
                    
                    return True
            
            return False
        except Exception as e:
            logger.error(f"Failed to remove IDS rule: {str(e)}")
            return False
    
    def add_firewall_rule(self, rule_type: str, value: str) -> bool:
        """
        Add a firewall rule.
        
        Args:
            rule_type: Rule type (allowed_services, allowed_ips, blocked_ips)
            value: Rule value
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get firewall configuration
            firewall_config = self.config.get("firewall", {})
            
            # Update configuration based on rule type
            if rule_type == "allowed_services":
                allowed_services = firewall_config.get("allowed_services", [])
                
                if value not in allowed_services:
                    allowed_services.append(value)
                    firewall_config["allowed_services"] = allowed_services
            elif rule_type == "allowed_ips":
                allowed_ips = firewall_config.get("allowed_ips", [])
                
                if value not in allowed_ips:
                    allowed_ips.append(value)
                    firewall_config["allowed_ips"] = allowed_ips
            elif rule_type == "blocked_ips":
                blocked_ips = firewall_config.get("blocked_ips", [])
                
                if value not in blocked_ips:
                    blocked_ips.append(value)
                    firewall_config["blocked_ips"] = blocked_ips
            else:
                logger.error(f"Unknown firewall rule type: {rule_type}")
                return False
            
            # Update configuration
            self.config["firewall"] = firewall_config
            
            # Save configuration
            self._save_config()
            
            # Apply firewall rules
            self._initialize_firewall()
            
            return True
        except Exception as e:
            logger.error(f"Failed to add firewall rule: {str(e)}")
            return False
    
    def remove_firewall_rule(self, rule_type: str, value: str) -> bool:
        """
        Remove a firewall rule.
        
        Args:
            rule_type: Rule type (allowed_services, allowed_ips, blocked_ips)
            value: Rule value
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get firewall configuration
            firewall_config = self.config.get("firewall", {})
            
            # Update configuration based on rule type
            if rule_type == "allowed_services":
                allowed_services = firewall_config.get("allowed_services", [])
                
                if value in allowed_services:
                    allowed_services.remove(value)
                    firewall_config["allowed_services"] = allowed_services
            elif rule_type == "allowed_ips":
                allowed_ips = firewall_config.get("allowed_ips", [])
                
                if value in allowed_ips:
                    allowed_ips.remove(value)
                    firewall_config["allowed_ips"] = allowed_ips
            elif rule_type == "blocked_ips":
                blocked_ips = firewall_config.get("blocked_ips", [])
                
                if value in blocked_ips:
                    blocked_ips.remove(value)
                    firewall_config["blocked_ips"] = blocked_ips
            else:
                logger.error(f"Unknown firewall rule type: {rule_type}")
                return False
            
            # Update configuration
            self.config["firewall"] = firewall_config
            
            # Save configuration
            self._save_config()
            
            # Apply firewall rules
            self._initialize_firewall()
            
            return True
        except Exception as e:
            logger.error(f"Failed to remove firewall rule: {str(e)}")
            return False
    
    def validate_password(self, password: str) -> Tuple[bool, str]:
        """
        Validate a password against the password policy.
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Get password policy
            policy = self.config.get("authentication", {}).get("password_policy", {})
            
            # Check minimum length
            min_length = policy.get("min_length", 12)
            if len(password) < min_length:
                return False, f"Password must be at least {min_length} characters long"
            
            # Check for uppercase letters
            if policy.get("require_uppercase", True) and not any(c.isupper() for c in password):
                return False, "Password must contain at least one uppercase letter"
            
            # Check for lowercase letters
            if policy.get("require_lowercase", True) and not any(c.islower() for c in password):
                return False, "Password must contain at least one lowercase letter"
            
            # Check for numbers
            if policy.get("require_numbers", True) and not any(c.isdigit() for c in password):
                return False, "Password must contain at least one number"
            
            # Check for special characters
            if policy.get("require_special", True) and not any(not c.isalnum() for c in password):
                return False, "Password must contain at least one special character"
            
            return True, ""
        except Exception as e:
            logger.error(f"Failed to validate password: {str(e)}")
            return False, "Internal error"
    
    def hash_password(self, password: str) -> Dict[str, str]:
        """
        Hash a password.
        
        Args:
            password: Password to hash
            
        Returns:
            Dictionary containing password hash and salt
        """
        try:
            # Generate salt
            salt = secrets.token_hex(16)
            
            # Hash password
            password_hash = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt.encode("utf-8"),
                100000
            ).hex()
            
            return {
                "hash": password_hash,
                "salt": salt
            }
        except Exception as e:
            logger.error(f"Failed to hash password: {str(e)}")
            raise
    
    def verify_password(self, password: str, password_hash: str, salt: str) -> bool:
        """
        Verify a password.
        
        Args:
            password: Password to verify
            password_hash: Expected password hash
            salt: Salt used for hashing
            
        Returns:
            True if password is correct, False otherwise
        """
        try:
            # Hash password with salt
            hash_to_check = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt.encode("utf-8"),
                100000
            ).hex()
            
            # Compare hashes
            return hash_to_check == password_hash
        except Exception as e:
            logger.error(f"Failed to verify password: {str(e)}")
            return False
    
    def get_security_status(self) -> Dict[str, Any]:
        """
        Get security status.
        
        Returns:
            Dictionary containing security status
        """
        try:
            # Get current time
            current_time = int(time.time())
            
            # Get security level
            security_level = self.config.get("security_level", "high")
            
            # Get firewall status
            firewall_enabled = self.config.get("firewall", {}).get("enabled", True)
            
            # Get intrusion detection status
            ids_enabled = self.config.get("intrusion_detection", {}).get("enabled", True)
            
            # Get encryption status
            encryption_enabled = self.config.get("encryption", {}).get("algorithm", "AES-256-GCM") != "none"
            
            # Get secure boot status
            secure_boot_enabled = self.config.get("secure_boot", {}).get("enabled", True)
            
            # Get secure storage status
            secure_storage_enabled = self.config.get("secure_storage", {}).get("encrypt_sensitive_data", True)
            
            # Get audit status
            audit_enabled = self.config.get("audit", {}).get("enabled", True)
            
            # Get active tokens count
            active_tokens = len(self.auth_tokens)
            
            # Create status
            status = {
                "security_level": security_level,
                "firewall": {
                    "enabled": firewall_enabled,
                    "allowed_services": self.config.get("firewall", {}).get("allowed_services", []),
                    "allowed_ips": self.config.get("firewall", {}).get("allowed_ips", []),
                    "blocked_ips": self.config.get("firewall", {}).get("blocked_ips", [])
                },
                "intrusion_detection": {
                    "enabled": ids_enabled,
                    "rules_count": len(self.ids_rules),
                    "sensitivity": self.config.get("intrusion_detection", {}).get("sensitivity", "medium")
                },
                "encryption": {
                    "enabled": encryption_enabled,
                    "algorithm": self.config.get("encryption", {}).get("algorithm", "AES-256-GCM"),
                    "keys_count": len(self.encryption_keys)
                },
                "authentication": {
                    "active_tokens": active_tokens,
                    "token_expiration": self.config.get("authentication", {}).get("token_expiration", 3600)
                },
                "secure_boot": {
                    "enabled": secure_boot_enabled
                },
                "secure_storage": {
                    "enabled": secure_storage_enabled
                },
                "audit": {
                    "enabled": audit_enabled,
                    "log_level": self.config.get("audit", {}).get("log_level", "info")
                },
                "timestamp": current_time
            }
            
            return status
        except Exception as e:
            logger.error(f"Failed to get security status: {str(e)}")
            return {
                "error": str(e),
                "timestamp": int(time.time())
            }
    
    def audit_log(self, event_type: str, user_id: str, resource: str, action: str, success: bool, details: Optional[str] = None):
        """
        Log an audit event.
        
        Args:
            event_type: Type of event
            user_id: User ID
            resource: Resource accessed
            action: Action performed
            success: Whether the action was successful
            details: Additional details
        """
        try:
            # Check if audit is enabled
            if not self.config.get("audit", {}).get("enabled", True):
                return
            
            # Get log level
            log_level = self.config.get("audit", {}).get("log_level", "info")
            
            # Create audit event
            audit_event = {
                "timestamp": int(time.time()),
                "event_type": event_type,
                "user_id": user_id,
                "resource": resource,
                "action": action,
                "success": success,
                "details": details,
                "ip_address": self._get_client_ip()
            }
            
            # Log event
            if log_level == "debug":
                logger.debug(f"Audit: {json.dumps(audit_event)}")
            else:
                logger.info(f"Audit: {json.dumps(audit_event)}")
            
            # Write to audit log file
            audit_log_file = "/var/log/viztron/audit.log"
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(audit_log_file), exist_ok=True)
            
            # Append to log file
            with open(audit_log_file, 'a') as f:
                f.write(json.dumps(audit_event) + "\n")
        except Exception as e:
            logger.error(f"Failed to log audit event: {str(e)}")
    
    def _get_client_ip(self) -> str:
        """
        Get client IP address.
        
        Returns:
            Client IP address
        """
        try:
            # This would typically get the client IP from the request
            # For now, return a placeholder
            return "127.0.0.1"
        except Exception as e:
            logger.error(f"Failed to get client IP: {str(e)}")
            return "unknown"
    
    def shutdown(self):
        """Perform a graceful shutdown of the security manager."""
        logger.info("Shutting down security manager")
        
        # Stop monitoring thread
        self.running = False
        
        if hasattr(self, "monitoring_thread") and self.monitoring_thread:
            self.monitoring_thread.join(timeout=5.0)
        
        # Save configuration
        self._save_config()
        
        # Save ACLs
        self._save_acls()
        
        # Remove PID file
        try:
            pid_file = "/var/run/viztron/security_manager.pid"
            if os.path.exists(pid_file):
                os.remove(pid_file)
        except Exception as e:
            logger.error(f"Failed to remove PID file: {str(e)}")
        
        logger.info("Security manager shutdown complete")


class SecureStorage:
    """
    Secure storage for sensitive data.
    
    This class provides methods to securely store and retrieve sensitive data.
    """
    
    def __init__(self, security_manager: SecurityManager, storage_dir: str = "/var/lib/viztron/secure_storage"):
        """
        Initialize the secure storage.
        
        Args:
            security_manager: Security manager instance
            storage_dir: Directory for secure storage
        """
        self.security_manager = security_manager
        self.storage_dir = storage_dir
        
        # Create storage directory if it doesn't exist
        os.makedirs(storage_dir, exist_ok=True)
        
        logger.info("Secure storage initialized")
    
    def store(self, key: str, data: Union[str, bytes, Dict[str, Any], List[Any]]) -> bool:
        """
        Store data securely.
        
        Args:
            key: Storage key
            data: Data to store
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Encrypt data
            encrypted_data = self.security_manager.encrypt_data(data)
            
            # Create file path
            file_path = os.path.join(self.storage_dir, f"{key}.json")
            
            # Write to file
            with open(file_path, 'w') as f:
                json.dump(encrypted_data, f, indent=2)
            
            # Set secure permissions
            os.chmod(file_path, 0o600)
            
            return True
        except Exception as e:
            logger.error(f"Failed to store data: {str(e)}")
            return False
    
    def retrieve(self, key: str) -> Optional[Union[str, Dict[str, Any], List[Any]]]:
        """
        Retrieve data securely.
        
        Args:
            key: Storage key
            
        Returns:
            Retrieved data if successful, None otherwise
        """
        try:
            # Create file path
            file_path = os.path.join(self.storage_dir, f"{key}.json")
            
            # Check if file exists
            if not os.path.exists(file_path):
                logger.warning(f"Data not found for key: {key}")
                return None
            
            # Read from file
            with open(file_path, 'r') as f:
                encrypted_data = json.load(f)
            
            # Decrypt data
            decrypted_data = self.security_manager.decrypt_data(encrypted_data)
            
            # Try to parse as JSON
            try:
                return json.loads(decrypted_data)
            except json.JSONDecodeError:
                # Return as string
                return decrypted_data.decode('utf-8')
        except Exception as e:
            logger.error(f"Failed to retrieve data: {str(e)}")
            return None
    
    def delete(self, key: str) -> bool:
        """
        Delete data.
        
        Args:
            key: Storage key
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create file path
            file_path = os.path.join(self.storage_dir, f"{key}.json")
            
            # Check if file exists
            if not os.path.exists(file_path):
                logger.warning(f"Data not found for key: {key}")
                return False
            
            # Delete file
            os.remove(file_path)
            
            return True
        except Exception as e:
            logger.error(f"Failed to delete data: {str(e)}")
            return False
    
    def list_keys(self) -> List[str]:
        """
        List all storage keys.
        
        Returns:
            List of storage keys
        """
        try:
            # Get all files in storage directory
            files = os.listdir(self.storage_dir)
            
            # Extract keys from filenames
            keys = []
            
            for file in files:
                if file.endswith(".json"):
                    keys.append(file[:-5])
            
            return keys
        except Exception as e:
            logger.error(f"Failed to list keys: {str(e)}")
            return []


class CertificateManager:
    """
    Certificate manager for SSL/TLS certificates.
    
    This class provides methods to generate, manage, and validate SSL/TLS certificates.
    """
    
    def __init__(self, cert_dir: str = "/var/lib/viztron/certificates"):
        """
        Initialize the certificate manager.
        
        Args:
            cert_dir: Directory for certificates
        """
        self.cert_dir = cert_dir
        
        # Create certificate directory if it doesn't exist
        os.makedirs(cert_dir, exist_ok=True)
        
        logger.info("Certificate manager initialized")
    
    def generate_self_signed_cert(self, common_name: str, days: int = 365) -> Tuple[str, str]:
        """
        Generate a self-signed certificate.
        
        Args:
            common_name: Common name for the certificate
            days: Validity period in days
            
        Returns:
            Tuple of (cert_file, key_file)
        """
        try:
            # Create filenames
            cert_file = os.path.join(self.cert_dir, f"{common_name}.crt")
            key_file = os.path.join(self.cert_dir, f"{common_name}.key")
            
            # Generate private key
            subprocess.run([
                "openssl", "genrsa",
                "-out", key_file,
                "2048"
            ], check=True, capture_output=True)
            
            # Set secure permissions for key file
            os.chmod(key_file, 0o600)
            
            # Generate certificate
            subprocess.run([
                "openssl", "req",
                "-new",
                "-x509",
                "-key", key_file,
                "-out", cert_file,
                "-days", str(days),
                "-subj", f"/CN={common_name}"
            ], check=True, capture_output=True)
            
            logger.info(f"Generated self-signed certificate for {common_name}")
            
            return cert_file, key_file
        except Exception as e:
            logger.error(f"Failed to generate self-signed certificate: {str(e)}")
            raise
    
    def generate_csr(self, common_name: str, organization: str = "Viztron", country: str = "US") -> Tuple[str, str]:
        """
        Generate a certificate signing request (CSR).
        
        Args:
            common_name: Common name for the certificate
            organization: Organization name
            country: Country code
            
        Returns:
            Tuple of (csr_file, key_file)
        """
        try:
            # Create filenames
            csr_file = os.path.join(self.cert_dir, f"{common_name}.csr")
            key_file = os.path.join(self.cert_dir, f"{common_name}.key")
            
            # Generate private key
            subprocess.run([
                "openssl", "genrsa",
                "-out", key_file,
                "2048"
            ], check=True, capture_output=True)
            
            # Set secure permissions for key file
            os.chmod(key_file, 0o600)
            
            # Generate CSR
            subprocess.run([
                "openssl", "req",
                "-new",
                "-key", key_file,
                "-out", csr_file,
                "-subj", f"/CN={common_name}/O={organization}/C={country}"
            ], check=True, capture_output=True)
            
            logger.info(f"Generated CSR for {common_name}")
            
            return csr_file, key_file
        except Exception as e:
            logger.error(f"Failed to generate CSR: {str(e)}")
            raise
    
    def import_certificate(self, cert_data: str, key_data: str, name: str) -> Tuple[str, str]:
        """
        Import a certificate.
        
        Args:
            cert_data: Certificate data
            key_data: Private key data
            name: Certificate name
            
        Returns:
            Tuple of (cert_file, key_file)
        """
        try:
            # Create filenames
            cert_file = os.path.join(self.cert_dir, f"{name}.crt")
            key_file = os.path.join(self.cert_dir, f"{name}.key")
            
            # Write certificate data
            with open(cert_file, 'w') as f:
                f.write(cert_data)
            
            # Write key data
            with open(key_file, 'w') as f:
                f.write(key_data)
            
            # Set secure permissions for key file
            os.chmod(key_file, 0o600)
            
            logger.info(f"Imported certificate for {name}")
            
            return cert_file, key_file
        except Exception as e:
            logger.error(f"Failed to import certificate: {str(e)}")
            raise
    
    def get_certificate_info(self, cert_file: str) -> Dict[str, Any]:
        """
        Get information about a certificate.
        
        Args:
            cert_file: Certificate file
            
        Returns:
            Dictionary containing certificate information
        """
        try:
            # Run openssl command to get certificate information
            result = subprocess.run([
                "openssl", "x509",
                "-in", cert_file,
                "-text",
                "-noout"
            ], check=True, capture_output=True, text=True)
            
            # Parse output
            output = result.stdout
            
            # Extract subject
            subject_match = re.search(r"Subject: (.*)", output)
            subject = subject_match.group(1) if subject_match else ""
            
            # Extract issuer
            issuer_match = re.search(r"Issuer: (.*)", output)
            issuer = issuer_match.group(1) if issuer_match else ""
            
            # Extract validity
            not_before_match = re.search(r"Not Before: (.*)", output)
            not_before = not_before_match.group(1) if not_before_match else ""
            
            not_after_match = re.search(r"Not After : (.*)", output)
            not_after = not_after_match.group(1) if not_after_match else ""
            
            # Create certificate info
            cert_info = {
                "subject": subject,
                "issuer": issuer,
                "not_before": not_before,
                "not_after": not_after,
                "file": cert_file
            }
            
            return cert_info
        except Exception as e:
            logger.error(f"Failed to get certificate info: {str(e)}")
            return {
                "error": str(e),
                "file": cert_file
            }
    
    def list_certificates(self) -> List[Dict[str, Any]]:
        """
        List all certificates.
        
        Returns:
            List of certificate information
        """
        try:
            # Get all certificate files
            cert_files = []
            
            for file in os.listdir(self.cert_dir):
                if file.endswith(".crt"):
                    cert_files.append(os.path.join(self.cert_dir, file))
            
            # Get information for each certificate
            certificates = []
            
            for cert_file in cert_files:
                cert_info = self.get_certificate_info(cert_file)
                certificates.append(cert_info)
            
            return certificates
        except Exception as e:
            logger.error(f"Failed to list certificates: {str(e)}")
            return []
    
    def delete_certificate(self, name: str) -> bool:
        """
        Delete a certificate.
        
        Args:
            name: Certificate name
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create filenames
            cert_file = os.path.join(self.cert_dir, f"{name}.crt")
            key_file = os.path.join(self.cert_dir, f"{name}.key")
            
            # Check if files exist
            cert_exists = os.path.exists(cert_file)
            key_exists = os.path.exists(key_file)
            
            if not cert_exists and not key_exists:
                logger.warning(f"Certificate not found: {name}")
                return False
            
            # Delete files
            if cert_exists:
                os.remove(cert_file)
            
            if key_exists:
                os.remove(key_file)
            
            logger.info(f"Deleted certificate: {name}")
            
            return True
        except Exception as e:
            logger.error(f"Failed to delete certificate: {str(e)}")
            return False


# Example usage
if __name__ == "__main__":
    # Create security manager
    security_manager = SecurityManager()
    
    try:
        # Create secure storage
        secure_storage = SecureStorage(security_manager)
        
        # Create certificate manager
        cert_manager = CertificateManager()
        
        # Store some test data
        secure_storage.store("test_key", {"username": "admin", "password": "secret"})
        
        # Retrieve the data
        data = secure_storage.retrieve("test_key")
        print(f"Retrieved data: {data}")
        
        # Generate a self-signed certificate
        cert_file, key_file = cert_manager.generate_self_signed_cert("localhost")
        print(f"Generated certificate: {cert_file}")
        
        # Get certificate info
        cert_info = cert_manager.get_certificate_info(cert_file)
        print(f"Certificate info: {cert_info}")
        
        # Run for a while
        print("\nSecurity manager running. Press Ctrl+C to exit.")
        
        # Main loop
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        # Shutdown
        security_manager.shutdown()
