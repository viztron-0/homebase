#!/usr/bin/env python3
"""
Device Manager for Viztron Homebase Module

This module implements the device management functionality for the
Viztron Homebase Module, handling camera devices, sensors, and
other connected peripherals.

Author: Viztron System Team
Date: April 20, 2025
"""

import os
import sys
import time
import logging
import json
import threading
import socket
import ipaddress
import subprocess
import re
import uuid
from typing import Dict, List, Any, Optional, Tuple, Set
from enum import Enum
from dataclasses import dataclass, field, asdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/viztron/device_manager.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('device_manager')

class DeviceType(Enum):
    """Enumeration of supported device types."""
    CAMERA = "camera"
    MOTION_SENSOR = "motion_sensor"
    DOOR_SENSOR = "door_sensor"
    WINDOW_SENSOR = "window_sensor"
    GLASS_BREAK_SENSOR = "glass_break_sensor"
    SMOKE_DETECTOR = "smoke_detector"
    CO_DETECTOR = "co_detector"
    WATER_LEAK_SENSOR = "water_leak_sensor"
    TEMPERATURE_SENSOR = "temperature_sensor"
    HUMIDITY_SENSOR = "humidity_sensor"
    LIGHT_SENSOR = "light_sensor"
    SIREN = "siren"
    KEYPAD = "keypad"
    HUB = "hub"
    UNKNOWN = "unknown"

class ConnectionType(Enum):
    """Enumeration of supported connection types."""
    WIRED = "wired"
    WIFI = "wifi"
    ZIGBEE = "zigbee"
    ZWAVE = "zwave"
    BLUETOOTH = "bluetooth"
    CELLULAR = "cellular"
    UNKNOWN = "unknown"

class DeviceStatus(Enum):
    """Enumeration of device status values."""
    ONLINE = "online"
    OFFLINE = "offline"
    CONNECTING = "connecting"
    ERROR = "error"
    UPDATING = "updating"
    INITIALIZING = "initializing"
    UNKNOWN = "unknown"

@dataclass
class DeviceCapabilities:
    """Data class for device capabilities."""
    video: bool = False
    audio: bool = False
    motion_detection: bool = False
    night_vision: bool = False
    two_way_audio: bool = False
    ptz: bool = False
    recording: bool = False
    streaming: bool = False
    battery_powered: bool = False
    tamper_detection: bool = False
    temperature_sensing: bool = False
    humidity_sensing: bool = False
    light_sensing: bool = False
    custom_capabilities: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DeviceInfo:
    """Data class for device information."""
    id: str
    name: str
    type: DeviceType
    model: str = ""
    manufacturer: str = ""
    firmware_version: str = ""
    hardware_version: str = ""
    serial_number: str = ""
    mac_address: str = ""
    ip_address: str = ""
    connection_type: ConnectionType = ConnectionType.UNKNOWN
    status: DeviceStatus = DeviceStatus.UNKNOWN
    capabilities: DeviceCapabilities = field(default_factory=DeviceCapabilities)
    location: str = ""
    zone: str = ""
    last_seen: float = 0.0
    battery_level: Optional[float] = None
    signal_strength: Optional[float] = None
    custom_attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert device info to dictionary."""
        result = asdict(self)
        # Convert enum values to strings
        result["type"] = self.type.value
        result["connection_type"] = self.connection_type.value
        result["status"] = self.status.value
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DeviceInfo':
        """Create device info from dictionary."""
        # Convert string values to enums
        if "type" in data:
            data["type"] = DeviceType(data["type"])
        if "connection_type" in data:
            data["connection_type"] = ConnectionType(data["connection_type"])
        if "status" in data:
            data["status"] = DeviceStatus(data["status"])
        
        # Convert capabilities dict to DeviceCapabilities
        if "capabilities" in data and isinstance(data["capabilities"], dict):
            capabilities_data = data.pop("capabilities")
            custom_capabilities = {}
            
            # Extract known capabilities
            known_capabilities = {
                field.name for field in DeviceCapabilities.__dataclass_fields__.values()
                if field.name != "custom_capabilities"
            }
            
            # Move unknown capabilities to custom_capabilities
            for key in list(capabilities_data.keys()):
                if key not in known_capabilities:
                    custom_capabilities[key] = capabilities_data.pop(key)
            
            # Add custom_capabilities back to capabilities_data
            capabilities_data["custom_capabilities"] = custom_capabilities
            
            # Create DeviceCapabilities instance
            data["capabilities"] = DeviceCapabilities(**capabilities_data)
        
        return cls(**data)

class DeviceDiscovery:
    """
    Discovers devices on the network.
    
    This class provides methods to discover cameras and other devices
    on the network using various discovery protocols.
    """
    
    def __init__(self, config_path: str = "/etc/viztron/device_discovery.json"):
        """
        Initialize the device discovery.
        
        Args:
            config_path: Path to the device discovery configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        
        # Discovery methods
        self.discovery_methods = {
            "onvif": self._discover_onvif,
            "upnp": self._discover_upnp,
            "mdns": self._discover_mdns,
            "ping_sweep": self._discover_ping_sweep,
            "arp_scan": self._discover_arp_scan
        }
        
        # Device fingerprints for identification
        self.device_fingerprints = self.config.get("device_fingerprints", {})
        
        logger.info("Device discovery initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load device discovery configuration from file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                return {
                    "discovery_methods": ["onvif", "upnp", "mdns", "ping_sweep"],
                    "scan_timeout": 5,
                    "network_interfaces": [],
                    "ip_ranges": [],
                    "device_fingerprints": {}
                }
        except Exception as e:
            logger.error(f"Failed to load device discovery config: {str(e)}")
            return {
                "discovery_methods": ["onvif", "upnp", "mdns", "ping_sweep"],
                "scan_timeout": 5,
                "network_interfaces": [],
                "ip_ranges": [],
                "device_fingerprints": {}
            }
    
    def discover_devices(self, methods: Optional[List[str]] = None, timeout: Optional[int] = None) -> List[DeviceInfo]:
        """
        Discover devices on the network.
        
        Args:
            methods: List of discovery methods to use (if None, uses all configured methods)
            timeout: Timeout in seconds for discovery (if None, uses configured timeout)
            
        Returns:
            List of discovered devices
        """
        # Use configured methods if not specified
        if methods is None:
            methods = self.config.get("discovery_methods", ["onvif", "upnp", "mdns", "ping_sweep"])
        
        # Use configured timeout if not specified
        if timeout is None:
            timeout = self.config.get("scan_timeout", 5)
        
        logger.info(f"Discovering devices using methods: {methods}")
        
        # Run discovery methods in parallel
        threads = []
        discovered_devices = []
        thread_results = {}
        
        for method in methods:
            if method in self.discovery_methods:
                thread = threading.Thread(
                    target=self._run_discovery_method,
                    args=(method, thread_results, timeout)
                )
                thread.daemon = True
                threads.append(thread)
                thread.start()
            else:
                logger.warning(f"Unknown discovery method: {method}")
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout + 1)  # Add 1 second buffer
        
        # Collect results
        for method, devices in thread_results.items():
            logger.info(f"Discovered {len(devices)} devices using {method}")
            discovered_devices.extend(devices)
        
        # Remove duplicates based on MAC address or IP address
        unique_devices = self._remove_duplicate_devices(discovered_devices)
        
        logger.info(f"Discovered {len(unique_devices)} unique devices")
        return unique_devices
    
    def _run_discovery_method(self, method: str, results: Dict[str, List[DeviceInfo]], timeout: int):
        """
        Run a discovery method and store results.
        
        Args:
            method: Discovery method to run
            results: Dictionary to store results
            timeout: Timeout in seconds
        """
        try:
            devices = self.discovery_methods[method](timeout)
            results[method] = devices
        except Exception as e:
            logger.error(f"Error running discovery method {method}: {str(e)}")
            results[method] = []
    
    def _remove_duplicate_devices(self, devices: List[DeviceInfo]) -> List[DeviceInfo]:
        """
        Remove duplicate devices from list.
        
        Args:
            devices: List of devices
            
        Returns:
            List of unique devices
        """
        unique_devices = {}
        
        for device in devices:
            # Use MAC address as primary key if available
            if device.mac_address:
                key = device.mac_address
            # Otherwise use IP address
            elif device.ip_address:
                key = device.ip_address
            # Last resort: use device ID
            else:
                key = device.id
            
            # If device already exists, merge information
            if key in unique_devices:
                unique_devices[key] = self._merge_device_info(unique_devices[key], device)
            else:
                unique_devices[key] = device
        
        return list(unique_devices.values())
    
    def _merge_device_info(self, device1: DeviceInfo, device2: DeviceInfo) -> DeviceInfo:
        """
        Merge information from two device instances.
        
        Args:
            device1: First device
            device2: Second device
            
        Returns:
            Merged device info
        """
        # Convert to dictionaries
        dict1 = device1.to_dict()
        dict2 = device2.to_dict()
        
        # Merge dictionaries, preferring non-empty values from dict2
        merged = dict1.copy()
        
        for key, value in dict2.items():
            # Skip empty values
            if value is None or value == "" or value == 0 or value == {}:
                continue
            
            # For capabilities, merge instead of replace
            if key == "capabilities" and isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = {**merged[key], **value}
                continue
            
            # For custom_attributes, merge instead of replace
            if key == "custom_attributes" and isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = {**merged[key], **value}
                continue
            
            # For other fields, prefer non-default values
            if key not in merged or merged[key] is None or merged[key] == "" or merged[key] == 0:
                merged[key] = value
        
        # Convert back to DeviceInfo
        return DeviceInfo.from_dict(merged)
    
    def _discover_onvif(self, timeout: int) -> List[DeviceInfo]:
        """
        Discover ONVIF cameras.
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            List of discovered devices
        """
        try:
            # Check if onvif module is available
            try:
                import onvif
                from onvif import ONVIFCamera
            except ImportError:
                logger.warning("ONVIF module not available, skipping ONVIF discovery")
                return []
            
            logger.info("Discovering ONVIF devices")
            
            # Use WSDiscovery to find ONVIF devices
            from onvif.discovery import ONVIFService
            
            wsd = ONVIFService()
            devices = wsd.get_devices(timeout=timeout)
            
            discovered = []
            
            for device in devices:
                try:
                    # Extract device information
                    xaddrs = device.get_xaddrs()[0]
                    
                    # Extract IP address from xaddrs
                    ip_match = re.search(r'http://([^:/]+)', xaddrs)
                    if not ip_match:
                        continue
                    
                    ip_address = ip_match.group(1)
                    
                    # Create device info
                    device_id = str(uuid.uuid4())
                    device_info = DeviceInfo(
                        id=device_id,
                        name=f"ONVIF Camera ({ip_address})",
                        type=DeviceType.CAMERA,
                        ip_address=ip_address,
                        connection_type=ConnectionType.WIRED,
                        status=DeviceStatus.ONLINE,
                        capabilities=DeviceCapabilities(
                            video=True,
                            streaming=True
                        ),
                        last_seen=time.time()
                    )
                    
                    # Try to get more information from the device
                    try:
                        # Connect to the device
                        cam = ONVIFCamera(ip_address, 80, None, None, no_cache=True)
                        
                        # Get device information
                        device_info_service = cam.create_devicemgmt_service()
                        device_info_data = device_info_service.GetDeviceInformation()
                        
                        # Update device info
                        device_info.manufacturer = device_info_data.get('Manufacturer', '')
                        device_info.model = device_info_data.get('Model', '')
                        device_info.firmware_version = device_info_data.get('FirmwareVersion', '')
                        device_info.serial_number = device_info_data.get('SerialNumber', '')
                        
                        # Get network interfaces
                        network_interfaces = device_info_service.GetNetworkInterfaces()
                        
                        # Extract MAC address from first interface
                        if network_interfaces and len(network_interfaces) > 0:
                            interface = network_interfaces[0]
                            if hasattr(interface, 'Info') and hasattr(interface.Info, 'HwAddress'):
                                device_info.mac_address = interface.Info.HwAddress
                        
                        # Get capabilities
                        capabilities = device_info_service.GetCapabilities()
                        
                        # Update capabilities
                        if hasattr(capabilities, 'Media') and capabilities.Media:
                            device_info.capabilities.video = True
                            device_info.capabilities.streaming = True
                        
                        if hasattr(capabilities, 'PTZ') and capabilities.PTZ:
                            device_info.capabilities.ptz = True
                        
                        if hasattr(capabilities, 'Analytics') and capabilities.Analytics:
                            device_info.capabilities.motion_detection = True
                        
                        if hasattr(capabilities, 'Device') and capabilities.Device:
                            if hasattr(capabilities.Device, 'System') and capabilities.Device.System:
                                if hasattr(capabilities.Device.System, 'SupportedVersions') and capabilities.Device.System.SupportedVersions:
                                    device_info.custom_attributes['onvif_versions'] = capabilities.Device.System.SupportedVersions
                    except Exception as e:
                        logger.warning(f"Failed to get detailed information for ONVIF device at {ip_address}: {str(e)}")
                    
                    discovered.append(device_info)
                except Exception as e:
                    logger.warning(f"Failed to process ONVIF device: {str(e)}")
            
            return discovered
        except Exception as e:
            logger.error(f"Error discovering ONVIF devices: {str(e)}")
            return []
    
    def _discover_upnp(self, timeout: int) -> List[DeviceInfo]:
        """
        Discover UPnP devices.
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            List of discovered devices
        """
        try:
            # Check if upnpy module is available
            try:
                import upnpy
            except ImportError:
                logger.warning("UPnPy module not available, skipping UPnP discovery")
                return []
            
            logger.info("Discovering UPnP devices")
            
            # Create UPnP client
            upnp_client = upnpy.UPnP()
            
            # Discover devices
            devices = upnp_client.discover(timeout=timeout)
            
            discovered = []
            
            for device in devices:
                try:
                    # Extract device information
                    device_type = DeviceType.UNKNOWN
                    
                    # Determine device type based on device type string
                    device_type_str = device.device_type
                    if "camera" in device_type_str.lower():
                        device_type = DeviceType.CAMERA
                    elif "sensor" in device_type_str.lower():
                        if "motion" in device_type_str.lower():
                            device_type = DeviceType.MOTION_SENSOR
                        elif "temperature" in device_type_str.lower():
                            device_type = DeviceType.TEMPERATURE_SENSOR
                        elif "humidity" in device_type_str.lower():
                            device_type = DeviceType.HUMIDITY_SENSOR
                        elif "light" in device_type_str.lower():
                            device_type = DeviceType.LIGHT_SENSOR
                    
                    # Extract IP address from URL
                    ip_match = re.search(r'http://([^:/]+)', device.location)
                    if not ip_match:
                        continue
                    
                    ip_address = ip_match.group(1)
                    
                    # Create device info
                    device_id = str(uuid.uuid4())
                    device_info = DeviceInfo(
                        id=device_id,
                        name=device.friendly_name,
                        type=device_type,
                        model=device.model_name,
                        manufacturer=device.manufacturer,
                        ip_address=ip_address,
                        connection_type=ConnectionType.WIRED,
                        status=DeviceStatus.ONLINE,
                        last_seen=time.time(),
                        custom_attributes={
                            "upnp_device_type": device.device_type,
                            "upnp_udn": device.udn
                        }
                    )
                    
                    # Set capabilities based on device type
                    if device_type == DeviceType.CAMERA:
                        device_info.capabilities.video = True
                        device_info.capabilities.streaming = True
                    elif device_type == DeviceType.MOTION_SENSOR:
                        device_info.capabilities.motion_detection = True
                    elif device_type == DeviceType.TEMPERATURE_SENSOR:
                        device_info.capabilities.temperature_sensing = True
                    elif device_type == DeviceType.HUMIDITY_SENSOR:
                        device_info.capabilities.humidity_sensing = True
                    elif device_type == DeviceType.LIGHT_SENSOR:
                        device_info.capabilities.light_sensing = True
                    
                    discovered.append(device_info)
                except Exception as e:
                    logger.warning(f"Failed to process UPnP device: {str(e)}")
            
            return discovered
        except Exception as e:
            logger.error(f"Error discovering UPnP devices: {str(e)}")
            return []
    
    def _discover_mdns(self, timeout: int) -> List[DeviceInfo]:
        """
        Discover mDNS/Bonjour devices.
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            List of discovered devices
        """
        try:
            # Check if zeroconf module is available
            try:
                from zeroconf import ServiceBrowser, Zeroconf
            except ImportError:
                logger.warning("Zeroconf module not available, skipping mDNS discovery")
                return []
            
            logger.info("Discovering mDNS devices")
            
            # Create listener for mDNS services
            class MDNSListener:
                def __init__(self):
                    self.devices = []
                
                def add_service(self, zeroconf, service_type, name):
                    info = zeroconf.get_service_info(service_type, name)
                    if info:
                        try:
                            # Extract IP address
                            ip_address = socket.inet_ntoa(info.addresses[0]) if info.addresses else None
                            
                            if not ip_address:
                                return
                            
                            # Determine device type based on service type
                            device_type = DeviceType.UNKNOWN
                            
                            if "_camera" in service_type or "_rtsp" in service_type:
                                device_type = DeviceType.CAMERA
                            elif "_sensor" in service_type:
                                if "_motion" in service_type:
                                    device_type = DeviceType.MOTION_SENSOR
                                elif "_temperature" in service_type:
                                    device_type = DeviceType.TEMPERATURE_SENSOR
                                elif "_humidity" in service_type:
                                    device_type = DeviceType.HUMIDITY_SENSOR
                                elif "_light" in service_type:
                                    device_type = DeviceType.LIGHT_SENSOR
                            
                            # Create device info
                            device_id = str(uuid.uuid4())
                            device_info = DeviceInfo(
                                id=device_id,
                                name=name.split(".")[0],
                                type=device_type,
                                ip_address=ip_address,
                                connection_type=ConnectionType.WIFI,
                                status=DeviceStatus.ONLINE,
                                last_seen=time.time(),
                                custom_attributes={
                                    "mdns_service_type": service_type,
                                    "mdns_port": info.port
                                }
                            )
                            
                            # Set capabilities based on device type
                            if device_type == DeviceType.CAMERA:
                                device_info.capabilities.video = True
                                device_info.capabilities.streaming = True
                            elif device_type == DeviceType.MOTION_SENSOR:
                                device_info.capabilities.motion_detection = True
                            elif device_type == DeviceType.TEMPERATURE_SENSOR:
                                device_info.capabilities.temperature_sensing = True
                            elif device_type == DeviceType.HUMIDITY_SENSOR:
                                device_info.capabilities.humidity_sensing = True
                            elif device_type == DeviceType.LIGHT_SENSOR:
                                device_info.capabilities.light_sensing = True
                            
                            self.devices.append(device_info)
                        except Exception as e:
                            logger.warning(f"Failed to process mDNS device: {str(e)}")
                
                def remove_service(self, zeroconf, service_type, name):
                    pass
                
                def update_service(self, zeroconf, service_type, name):
                    pass
            
            # Create Zeroconf instance
            zeroconf = Zeroconf()
            
            # Create listener
            listener = MDNSListener()
            
            # Service types to browse
            service_types = [
                "_rtsp._tcp.local.",
                "_http._tcp.local.",
                "_camera._tcp.local.",
                "_sensor._tcp.local.",
                "_motion._tcp.local.",
                "_temperature._tcp.local.",
                "_humidity._tcp.local.",
                "_light._tcp.local."
            ]
            
            # Create browsers for each service type
            browsers = [ServiceBrowser(zeroconf, service_type, listener) for service_type in service_types]
            
            # Wait for discovery
            time.sleep(timeout)
            
            # Close Zeroconf
            zeroconf.close()
            
            return listener.devices
        except Exception as e:
            logger.error(f"Error discovering mDNS devices: {str(e)}")
            return []
    
    def _discover_ping_sweep(self, timeout: int) -> List[DeviceInfo]:
        """
        Discover devices using ping sweep.
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            List of discovered devices
        """
        try:
            logger.info("Discovering devices using ping sweep")
            
            # Get IP ranges to scan
            ip_ranges = self.config.get("ip_ranges", [])
            
            # If no IP ranges specified, try to determine local network
            if not ip_ranges:
                ip_ranges = self._get_local_networks()
            
            if not ip_ranges:
                logger.warning("No IP ranges specified for ping sweep")
                return []
            
            logger.info(f"Scanning IP ranges: {ip_ranges}")
            
            # Ping sweep each range
            discovered = []
            
            for ip_range in ip_ranges:
                try:
                    # Parse IP range
                    network = ipaddress.ip_network(ip_range, strict=False)
                    
                    # Limit number of hosts to scan
                    max_hosts = 256
                    hosts = list(network.hosts())[:max_hosts]
                    
                    # Create thread pool for parallel scanning
                    threads = []
                    thread_results = {}
                    
                    for host in hosts:
                        thread = threading.Thread(
                            target=self._ping_host,
                            args=(str(host), thread_results, timeout)
                        )
                        thread.daemon = True
                        threads.append(thread)
                    
                    # Start threads in batches to avoid overwhelming the system
                    batch_size = 20
                    for i in range(0, len(threads), batch_size):
                        batch = threads[i:i+batch_size]
                        for thread in batch:
                            thread.start()
                        for thread in batch:
                            thread.join(timeout + 1)  # Add 1 second buffer
                    
                    # Process results
                    for ip_address, is_alive in thread_results.items():
                        if is_alive:
                            # Try to get MAC address
                            mac_address = self._get_mac_address(ip_address)
                            
                            # Try to identify device type
                            device_type, device_info = self._identify_device(ip_address, mac_address)
                            
                            # Create device info
                            device_id = str(uuid.uuid4())
                            device_info = DeviceInfo(
                                id=device_id,
                                name=f"Device ({ip_address})",
                                type=device_type,
                                ip_address=ip_address,
                                mac_address=mac_address,
                                connection_type=ConnectionType.UNKNOWN,
                                status=DeviceStatus.ONLINE,
                                last_seen=time.time()
                            )
                            
                            # Update with identified info
                            if device_info:
                                device_info = self._merge_device_info(device_info, device_info)
                            
                            discovered.append(device_info)
                except Exception as e:
                    logger.warning(f"Failed to scan IP range {ip_range}: {str(e)}")
            
            return discovered
        except Exception as e:
            logger.error(f"Error discovering devices using ping sweep: {str(e)}")
            return []
    
    def _ping_host(self, ip_address: str, results: Dict[str, bool], timeout: int):
        """
        Ping a host and store result.
        
        Args:
            ip_address: IP address to ping
            results: Dictionary to store results
            timeout: Timeout in seconds
        """
        try:
            # Use ping command
            if os.name == "nt":  # Windows
                ping_cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip_address]
            else:  # Linux/Mac
                ping_cmd = ["ping", "-c", "1", "-W", str(timeout), ip_address]
            
            result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            
            # Check if ping was successful
            is_alive = result.returncode == 0
            
            results[ip_address] = is_alive
        except Exception:
            results[ip_address] = False
    
    def _get_mac_address(self, ip_address: str) -> str:
        """
        Get MAC address for an IP address.
        
        Args:
            ip_address: IP address
            
        Returns:
            MAC address if found, empty string otherwise
        """
        try:
            # Use ARP to get MAC address
            if os.name == "nt":  # Windows
                arp_cmd = ["arp", "-a", ip_address]
            else:  # Linux/Mac
                arp_cmd = ["arp", "-n", ip_address]
            
            result = subprocess.run(arp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Parse output
            if os.name == "nt":  # Windows
                match = re.search(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})', result.stdout)
            else:  # Linux/Mac
                match = re.search(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', result.stdout)
            
            if match:
                return match.group(1)
            
            return ""
        except Exception:
            return ""
    
    def _identify_device(self, ip_address: str, mac_address: str) -> Tuple[DeviceType, Optional[DeviceInfo]]:
        """
        Identify device type based on IP and MAC address.
        
        Args:
            ip_address: IP address
            mac_address: MAC address
            
        Returns:
            Tuple of (device_type, device_info)
        """
        # Check MAC address against fingerprints
        if mac_address:
            mac_prefix = mac_address[:8].upper()
            
            for fingerprint in self.device_fingerprints.get("mac_prefixes", []):
                if mac_prefix.startswith(fingerprint.get("prefix", "").upper()):
                    device_type_str = fingerprint.get("type", "unknown")
                    try:
                        device_type = DeviceType(device_type_str)
                    except ValueError:
                        device_type = DeviceType.UNKNOWN
                    
                    # Create basic device info
                    device_info = DeviceInfo(
                        id=str(uuid.uuid4()),
                        name=fingerprint.get("name", f"Device ({ip_address})"),
                        type=device_type,
                        manufacturer=fingerprint.get("manufacturer", ""),
                        model=fingerprint.get("model", ""),
                        ip_address=ip_address,
                        mac_address=mac_address,
                        status=DeviceStatus.ONLINE,
                        last_seen=time.time()
                    )
                    
                    return device_type, device_info
        
        # Try to identify using port scanning
        try:
            # Check common ports
            camera_ports = [80, 443, 554, 8000, 8080, 8554, 8888, 9000]
            
            for port in camera_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((ip_address, port))
                    sock.close()
                    
                    if result == 0:  # Port is open
                        # If port 554 (RTSP) is open, likely a camera
                        if port == 554:
                            return DeviceType.CAMERA, None
                        
                        # If HTTP/HTTPS ports are open, try to get more info
                        if port in [80, 443, 8000, 8080, 8888]:
                            # Try to get HTTP response
                            protocol = "https" if port == 443 else "http"
                            url = f"{protocol}://{ip_address}:{port}"
                            
                            try:
                                import requests
                                response = requests.get(url, timeout=2)
                                
                                # Check response for camera-related keywords
                                if "camera" in response.text.lower() or "ipcam" in response.text.lower() or "webcam" in response.text.lower():
                                    return DeviceType.CAMERA, None
                            except Exception:
                                pass
                except Exception:
                    pass
        except Exception:
            pass
        
        return DeviceType.UNKNOWN, None
    
    def _discover_arp_scan(self, timeout: int) -> List[DeviceInfo]:
        """
        Discover devices using ARP scan.
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            List of discovered devices
        """
        try:
            logger.info("Discovering devices using ARP scan")
            
            # Get network interfaces to scan
            interfaces = self.config.get("network_interfaces", [])
            
            # If no interfaces specified, try to determine local interfaces
            if not interfaces:
                interfaces = self._get_network_interfaces()
            
            if not interfaces:
                logger.warning("No network interfaces specified for ARP scan")
                return []
            
            logger.info(f"Scanning network interfaces: {interfaces}")
            
            # ARP scan each interface
            discovered = []
            
            for interface in interfaces:
                try:
                    # Use arp-scan command if available
                    try:
                        arp_cmd = ["arp-scan", "--interface", interface, "--localnet"]
                        result = subprocess.run(arp_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
                        
                        # Parse output
                        for line in result.stdout.splitlines():
                            # Look for lines with IP and MAC addresses
                            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', line)
                            
                            if match:
                                ip_address = match.group(1)
                                mac_address = match.group(2)
                                
                                # Try to identify device type
                                device_type, device_info = self._identify_device(ip_address, mac_address)
                                
                                # Create device info
                                if not device_info:
                                    device_id = str(uuid.uuid4())
                                    device_info = DeviceInfo(
                                        id=device_id,
                                        name=f"Device ({ip_address})",
                                        type=device_type,
                                        ip_address=ip_address,
                                        mac_address=mac_address,
                                        connection_type=ConnectionType.UNKNOWN,
                                        status=DeviceStatus.ONLINE,
                                        last_seen=time.time()
                                    )
                                
                                discovered.append(device_info)
                    except (subprocess.SubprocessError, FileNotFoundError):
                        logger.warning("arp-scan command not available, falling back to alternative method")
                        
                        # Alternative: use ip neighbor show
                        try:
                            ip_cmd = ["ip", "neighbor", "show", "dev", interface]
                            result = subprocess.run(ip_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
                            
                            # Parse output
                            for line in result.stdout.splitlines():
                                # Look for lines with IP and MAC addresses
                                match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+\w+\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', line)
                                
                                if match:
                                    ip_address = match.group(1)
                                    mac_address = match.group(2)
                                    
                                    # Try to identify device type
                                    device_type, device_info = self._identify_device(ip_address, mac_address)
                                    
                                    # Create device info
                                    if not device_info:
                                        device_id = str(uuid.uuid4())
                                        device_info = DeviceInfo(
                                            id=device_id,
                                            name=f"Device ({ip_address})",
                                            type=device_type,
                                            ip_address=ip_address,
                                            mac_address=mac_address,
                                            connection_type=ConnectionType.UNKNOWN,
                                            status=DeviceStatus.ONLINE,
                                            last_seen=time.time()
                                        )
                                    
                                    discovered.append(device_info)
                        except (subprocess.SubprocessError, FileNotFoundError):
                            logger.warning("ip neighbor command not available, skipping interface")
                except Exception as e:
                    logger.warning(f"Failed to scan interface {interface}: {str(e)}")
            
            return discovered
        except Exception as e:
            logger.error(f"Error discovering devices using ARP scan: {str(e)}")
            return []
    
    def _get_local_networks(self) -> List[str]:
        """
        Get local network ranges.
        
        Returns:
            List of network ranges in CIDR notation
        """
        networks = []
        
        try:
            # Get network interfaces
            interfaces = self._get_network_interfaces()
            
            for interface in interfaces:
                try:
                    # Get IP address and netmask
                    if os.name == "nt":  # Windows
                        ipconfig_cmd = ["ipconfig"]
                        result = subprocess.run(ipconfig_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        
                        # Parse output
                        current_interface = None
                        ip_address = None
                        subnet_mask = None
                        
                        for line in result.stdout.splitlines():
                            if "adapter" in line.lower():
                                current_interface = line.split(":")[0].strip()
                            elif current_interface and interface.lower() in current_interface.lower():
                                if "IPv4 Address" in line:
                                    ip_address = line.split(":")[-1].strip()
                                elif "Subnet Mask" in line:
                                    subnet_mask = line.split(":")[-1].strip()
                        
                        if ip_address and subnet_mask:
                            # Convert to CIDR notation
                            ip_obj = ipaddress.IPv4Address(ip_address)
                            mask_obj = ipaddress.IPv4Address(subnet_mask)
                            prefix_len = bin(int(mask_obj)).count('1')
                            
                            network = f"{ip_address}/{prefix_len}"
                            networks.append(network)
                    else:  # Linux/Mac
                        ip_cmd = ["ip", "addr", "show", interface]
                        result = subprocess.run(ip_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        
                        # Parse output
                        for line in result.stdout.splitlines():
                            if "inet " in line:
                                # Extract IP/CIDR
                                match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', line)
                                if match:
                                    network = match.group(1)
                                    networks.append(network)
                except Exception as e:
                    logger.warning(f"Failed to get network for interface {interface}: {str(e)}")
        except Exception as e:
            logger.warning(f"Failed to get local networks: {str(e)}")
        
        return networks
    
    def _get_network_interfaces(self) -> List[str]:
        """
        Get network interface names.
        
        Returns:
            List of network interface names
        """
        interfaces = []
        
        try:
            if os.name == "nt":  # Windows
                ipconfig_cmd = ["ipconfig"]
                result = subprocess.run(ipconfig_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # Parse output
                for line in result.stdout.splitlines():
                    if "adapter" in line.lower():
                        interface = line.split(":")[0].strip()
                        interfaces.append(interface)
            else:  # Linux/Mac
                ip_cmd = ["ip", "link", "show"]
                result = subprocess.run(ip_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                # Parse output
                for line in result.stdout.splitlines():
                    if ": " in line:
                        match = re.search(r'\d+:\s+([^:@]+)[:@]', line)
                        if match:
                            interface = match.group(1).strip()
                            # Skip loopback
                            if interface != "lo":
                                interfaces.append(interface)
        except Exception as e:
            logger.warning(f"Failed to get network interfaces: {str(e)}")
        
        return interfaces


class DeviceManager:
    """
    Manages devices for the Viztron Homebase Module.
    
    This class provides methods to discover, add, remove, and monitor
    devices connected to the system.
    """
    
    def __init__(self, config_path: str = "/etc/viztron/device_manager.json", db_path: str = "/var/lib/viztron/devices.json"):
        """
        Initialize the device manager.
        
        Args:
            config_path: Path to the device manager configuration file
            db_path: Path to the device database file
        """
        self.config_path = config_path
        self.db_path = db_path
        self.config = self._load_config()
        
        # Create required directories
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        # Load device database
        self.devices = self._load_devices()
        
        # Device discovery
        self.discovery = DeviceDiscovery()
        
        # Device monitoring thread
        self.monitoring_interval = self.config.get("monitoring_interval", 60)  # seconds
        self.monitoring_thread = None
        self.monitoring_active = False
        
        # Device lock
        self.device_lock = threading.Lock()
        
        # Create PID file
        self._create_pid_file()
        
        logger.info("Device manager initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load device manager configuration from file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                return {
                    "monitoring_interval": 60,
                    "auto_discovery_enabled": True,
                    "auto_discovery_interval": 3600,  # 1 hour
                    "discovery_methods": ["onvif", "upnp", "mdns", "ping_sweep"],
                    "device_timeout": 300  # 5 minutes
                }
        except Exception as e:
            logger.error(f"Failed to load device manager config: {str(e)}")
            return {
                "monitoring_interval": 60,
                "auto_discovery_enabled": True,
                "auto_discovery_interval": 3600,  # 1 hour
                "discovery_methods": ["onvif", "upnp", "mdns", "ping_sweep"],
                "device_timeout": 300  # 5 minutes
            }
    
    def _save_config(self):
        """Save device manager configuration to file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save device manager config: {str(e)}")
    
    def _load_devices(self) -> Dict[str, DeviceInfo]:
        """
        Load devices from database file.
        
        Returns:
            Dictionary mapping device IDs to DeviceInfo objects
        """
        devices = {}
        
        try:
            if os.path.exists(self.db_path):
                with open(self.db_path, 'r') as f:
                    devices_data = json.load(f)
                
                for device_id, device_data in devices_data.items():
                    try:
                        devices[device_id] = DeviceInfo.from_dict(device_data)
                    except Exception as e:
                        logger.error(f"Failed to load device {device_id}: {str(e)}")
            
            logger.info(f"Loaded {len(devices)} devices from database")
        except Exception as e:
            logger.error(f"Failed to load devices from database: {str(e)}")
        
        return devices
    
    def _save_devices(self):
        """Save devices to database file."""
        try:
            # Convert devices to dictionaries
            devices_data = {device_id: device.to_dict() for device_id, device in self.devices.items()}
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            # Write to file
            with open(self.db_path, 'w') as f:
                json.dump(devices_data, f, indent=2)
            
            logger.debug(f"Saved {len(self.devices)} devices to database")
        except Exception as e:
            logger.error(f"Failed to save devices to database: {str(e)}")
    
    def _create_pid_file(self):
        """Create PID file for the device manager."""
        try:
            pid = os.getpid()
            pid_dir = "/var/run/viztron"
            os.makedirs(pid_dir, exist_ok=True)
            
            with open(f"{pid_dir}/device_manager.pid", 'w') as f:
                f.write(str(pid))
            
            logger.debug(f"Created PID file with PID {pid}")
        except Exception as e:
            logger.error(f"Failed to create PID file: {str(e)}")
    
    def discover_devices(self, methods: Optional[List[str]] = None, timeout: Optional[int] = None) -> List[DeviceInfo]:
        """
        Discover devices on the network.
        
        Args:
            methods: List of discovery methods to use (if None, uses configured methods)
            timeout: Timeout in seconds for discovery (if None, uses configured timeout)
            
        Returns:
            List of discovered devices
        """
        # Use configured methods if not specified
        if methods is None:
            methods = self.config.get("discovery_methods", ["onvif", "upnp", "mdns", "ping_sweep"])
        
        # Use configured timeout if not specified
        if timeout is None:
            timeout = self.config.get("scan_timeout", 5)
        
        logger.info(f"Discovering devices using methods: {methods}")
        
        # Discover devices
        discovered_devices = self.discovery.discover_devices(methods, timeout)
        
        # Add or update devices
        with self.device_lock:
            for device in discovered_devices:
                # Check if device already exists
                existing_device = None
                
                # Try to match by MAC address
                if device.mac_address:
                    for existing_id, existing in self.devices.items():
                        if existing.mac_address and existing.mac_address == device.mac_address:
                            existing_device = existing
                            break
                
                # If not found, try to match by IP address
                if not existing_device and device.ip_address:
                    for existing_id, existing in self.devices.items():
                        if existing.ip_address and existing.ip_address == device.ip_address:
                            existing_device = existing
                            break
                
                # If device exists, update it
                if existing_device:
                    # Update device info
                    updated_device = self._merge_device_info(existing_device, device)
                    
                    # Update in devices dictionary
                    self.devices[existing_device.id] = updated_device
                    
                    logger.debug(f"Updated device {existing_device.id}: {updated_device.name}")
                else:
                    # Add new device
                    self.devices[device.id] = device
                    
                    logger.info(f"Added new device {device.id}: {device.name}")
            
            # Save devices to database
            self._save_devices()
        
        return discovered_devices
    
    def _merge_device_info(self, device1: DeviceInfo, device2: DeviceInfo) -> DeviceInfo:
        """
        Merge information from two device instances.
        
        Args:
            device1: First device
            device2: Second device
            
        Returns:
            Merged device info
        """
        # Convert to dictionaries
        dict1 = device1.to_dict()
        dict2 = device2.to_dict()
        
        # Merge dictionaries, preferring non-empty values from dict2
        merged = dict1.copy()
        
        for key, value in dict2.items():
            # Skip empty values
            if value is None or value == "" or value == 0 or value == {}:
                continue
            
            # For capabilities, merge instead of replace
            if key == "capabilities" and isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = {**merged[key], **value}
                continue
            
            # For custom_attributes, merge instead of replace
            if key == "custom_attributes" and isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = {**merged[key], **value}
                continue
            
            # For other fields, prefer non-default values
            if key not in merged or merged[key] is None or merged[key] == "" or merged[key] == 0:
                merged[key] = value
        
        # Always update last_seen
        merged["last_seen"] = max(dict1.get("last_seen", 0), dict2.get("last_seen", 0))
        
        # Always update status if device2 is online
        if dict2.get("status") == DeviceStatus.ONLINE.value:
            merged["status"] = dict2.get("status")
        
        # Convert back to DeviceInfo
        return DeviceInfo.from_dict(merged)
    
    def get_devices(self, device_type: Optional[DeviceType] = None, status: Optional[DeviceStatus] = None) -> List[DeviceInfo]:
        """
        Get all devices, optionally filtered by type and status.
        
        Args:
            device_type: Filter by device type
            status: Filter by device status
            
        Returns:
            List of devices
        """
        with self.device_lock:
            devices = list(self.devices.values())
        
        # Filter by type
        if device_type is not None:
            devices = [device for device in devices if device.type == device_type]
        
        # Filter by status
        if status is not None:
            devices = [device for device in devices if device.status == status]
        
        return devices
    
    def get_device(self, device_id: str) -> Optional[DeviceInfo]:
        """
        Get a device by ID.
        
        Args:
            device_id: Device ID
            
        Returns:
            DeviceInfo if found, None otherwise
        """
        with self.device_lock:
            return self.devices.get(device_id)
    
    def add_device(self, device: DeviceInfo) -> bool:
        """
        Add a new device.
        
        Args:
            device: Device to add
            
        Returns:
            True if successful, False otherwise
        """
        with self.device_lock:
            # Check if device already exists
            if device.id in self.devices:
                logger.warning(f"Device {device.id} already exists")
                return False
            
            # Add device
            self.devices[device.id] = device
            
            # Save devices to database
            self._save_devices()
            
            logger.info(f"Added device {device.id}: {device.name}")
            return True
    
    def update_device(self, device_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update a device.
        
        Args:
            device_id: Device ID
            updates: Dictionary of updates to apply
            
        Returns:
            True if successful, False otherwise
        """
        with self.device_lock:
            # Check if device exists
            if device_id not in self.devices:
                logger.warning(f"Device {device_id} not found")
                return False
            
            # Get current device info
            device = self.devices[device_id]
            
            # Convert to dictionary
            device_dict = device.to_dict()
            
            # Apply updates
            for key, value in updates.items():
                if key == "capabilities" and isinstance(value, dict) and isinstance(device_dict.get("capabilities"), dict):
                    # Merge capabilities
                    device_dict["capabilities"] = {**device_dict["capabilities"], **value}
                elif key == "custom_attributes" and isinstance(value, dict) and isinstance(device_dict.get("custom_attributes"), dict):
                    # Merge custom attributes
                    device_dict["custom_attributes"] = {**device_dict["custom_attributes"], **value}
                else:
                    # Update other fields
                    device_dict[key] = value
            
            # Convert back to DeviceInfo
            updated_device = DeviceInfo.from_dict(device_dict)
            
            # Update device
            self.devices[device_id] = updated_device
            
            # Save devices to database
            self._save_devices()
            
            logger.info(f"Updated device {device_id}: {updated_device.name}")
            return True
    
    def remove_device(self, device_id: str) -> bool:
        """
        Remove a device.
        
        Args:
            device_id: Device ID
            
        Returns:
            True if successful, False otherwise
        """
        with self.device_lock:
            # Check if device exists
            if device_id not in self.devices:
                logger.warning(f"Device {device_id} not found")
                return False
            
            # Get device info for logging
            device = self.devices[device_id]
            
            # Remove device
            del self.devices[device_id]
            
            # Save devices to database
            self._save_devices()
            
            logger.info(f"Removed device {device_id}: {device.name}")
            return True
    
    def start_monitoring(self):
        """Start the device monitoring thread."""
        if not self.monitoring_active:
            logger.info("Starting device monitoring")
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop)
            self.monitoring_thread.daemon = True
            self.monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop the device monitoring thread."""
        if self.monitoring_active:
            logger.info("Stopping device monitoring")
            self.monitoring_active = False
            if self.monitoring_thread:
                self.monitoring_thread.join(timeout=5.0)
    
    def _monitoring_loop(self):
        """Main monitoring loop that runs in a separate thread."""
        logger.info(f"Device monitoring loop started with interval {self.monitoring_interval} seconds")
        
        # Time of last auto discovery
        last_auto_discovery = 0
        
        while self.monitoring_active:
            try:
                # Check device status
                self._check_device_status()
                
                # Run auto discovery if enabled
                if self.config.get("auto_discovery_enabled", True):
                    auto_discovery_interval = self.config.get("auto_discovery_interval", 3600)  # 1 hour
                    
                    if time.time() - last_auto_discovery >= auto_discovery_interval:
                        logger.info("Running automatic device discovery")
                        self.discover_devices()
                        last_auto_discovery = time.time()
                
                # Sleep for monitoring interval
                # Use shorter sleep intervals to allow for clean shutdown
                for _ in range(self.monitoring_interval):
                    if not self.monitoring_active:
                        break
                    time.sleep(1)
            except Exception as e:
                logger.error(f"Error in device monitoring loop: {str(e)}")
                time.sleep(10)  # Sleep briefly before retrying
    
    def _check_device_status(self):
        """Check status of all devices."""
        with self.device_lock:
            # Get current time
            current_time = time.time()
            
            # Get device timeout
            device_timeout = self.config.get("device_timeout", 300)  # 5 minutes
            
            # Check each device
            for device_id, device in list(self.devices.items()):
                try:
                    # Skip devices without IP address
                    if not device.ip_address:
                        continue
                    
                    # Check if device is online
                    is_online = self._ping_device(device.ip_address)
                    
                    # Update device status
                    if is_online:
                        # Device is online
                        if device.status != DeviceStatus.ONLINE:
                            logger.info(f"Device {device_id} ({device.name}) is now online")
                            self.update_device(device_id, {"status": DeviceStatus.ONLINE.value, "last_seen": current_time})
                        else:
                            # Just update last_seen
                            self.update_device(device_id, {"last_seen": current_time})
                    else:
                        # Device is offline
                        if device.status == DeviceStatus.ONLINE:
                            # Check if device has been offline for longer than timeout
                            if current_time - device.last_seen > device_timeout:
                                logger.info(f"Device {device_id} ({device.name}) is now offline")
                                self.update_device(device_id, {"status": DeviceStatus.OFFLINE.value})
                except Exception as e:
                    logger.warning(f"Error checking status of device {device_id}: {str(e)}")
    
    def _ping_device(self, ip_address: str) -> bool:
        """
        Ping a device to check if it's online.
        
        Args:
            ip_address: IP address of the device
            
        Returns:
            True if device is online, False otherwise
        """
        try:
            # Use ping command with short timeout
            if os.name == "nt":  # Windows
                ping_cmd = ["ping", "-n", "1", "-w", "1000", ip_address]
            else:  # Linux/Mac
                ping_cmd = ["ping", "-c", "1", "-W", "1", ip_address]
            
            result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=2)
            
            # Check if ping was successful
            return result.returncode == 0
        except Exception:
            return False
    
    def enable_auto_discovery(self, enabled: bool = True):
        """
        Enable or disable automatic device discovery.
        
        Args:
            enabled: Whether to enable automatic discovery
        """
        logger.info(f"{'Enabling' if enabled else 'Disabling'} automatic device discovery")
        
        self.config["auto_discovery_enabled"] = enabled
        self._save_config()
    
    def set_auto_discovery_interval(self, interval: int):
        """
        Set automatic discovery interval.
        
        Args:
            interval: Discovery interval in seconds
        """
        logger.info(f"Setting automatic discovery interval to {interval} seconds")
        
        self.config["auto_discovery_interval"] = interval
        self._save_config()
    
    def set_monitoring_interval(self, interval: int):
        """
        Set device monitoring interval.
        
        Args:
            interval: Monitoring interval in seconds
        """
        logger.info(f"Setting device monitoring interval to {interval} seconds")
        
        self.monitoring_interval = interval
        self.config["monitoring_interval"] = interval
        self._save_config()
    
    def shutdown(self):
        """Perform a graceful shutdown of the device manager."""
        logger.info("Shutting down device manager")
        
        # Stop monitoring thread
        self.stop_monitoring()
        
        # Save devices to database
        with self.device_lock:
            self._save_devices()
        
        # Remove PID file
        try:
            pid_file = "/var/run/viztron/device_manager.pid"
            if os.path.exists(pid_file):
                os.remove(pid_file)
        except Exception as e:
            logger.error(f"Failed to remove PID file: {str(e)}")
        
        logger.info("Device manager shutdown complete")


# Example usage
if __name__ == "__main__":
    # Create device manager
    device_manager = DeviceManager()
    
    try:
        # Start device monitoring
        device_manager.start_monitoring()
        
        # Discover devices
        print("Discovering devices...")
        discovered_devices = device_manager.discover_devices()
        print(f"Discovered {len(discovered_devices)} devices")
        
        # Get all devices
        devices = device_manager.get_devices()
        print(f"Total devices: {len(devices)}")
        
        for device in devices:
            print(f"  {device.name} ({device.type.value}): {device.status.value}")
        
        # Run for a while
        print("\nDevice manager running. Press Ctrl+C to exit.")
        
        # Main loop
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        # Shutdown
        device_manager.shutdown()
