#!/usr/bin/env python3
"""
System Manager for Viztron Homebase Module

This module implements the core system management functionality for the
Viztron Homebase Module, handling system resources, hardware interfaces,
power management, and system monitoring.

Author: Viztron System Team
Date: April 20, 2025
"""

import os
import sys
import time
import logging
import threading
import subprocess
import json
import psutil
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import signal

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/viztron/system_manager.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('system_manager')

class HardwareMonitor:
    """
    Monitors hardware components and resources of the BeagleBoard Y-AI.
    
    This class provides methods to monitor CPU, memory, storage, temperature,
    and other hardware metrics.
    """
    
    def __init__(self, config_path: str = "/etc/viztron/hardware_config.json"):
        """
        Initialize the hardware monitor.
        
        Args:
            config_path: Path to the hardware configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        self.temp_sensors = self._discover_temp_sensors()
        self.last_readings = {}
        self.reading_history = {}
        self.alert_thresholds = self.config.get("alert_thresholds", {
            "cpu_temp": 80.0,  # Celsius
            "cpu_usage": 90.0,  # Percent
            "memory_usage": 90.0,  # Percent
            "storage_usage": 90.0,  # Percent
        })
        
        logger.info("Hardware monitor initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load hardware configuration from file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                return {}
        except Exception as e:
            logger.error(f"Failed to load hardware config: {str(e)}")
            return {}
    
    def _discover_temp_sensors(self) -> Dict[str, str]:
        """Discover temperature sensors in the system."""
        sensors = {}
        
        # Check for thermal zones in sysfs
        thermal_path = Path("/sys/class/thermal")
        if thermal_path.exists():
            for zone in thermal_path.glob("thermal_zone*"):
                try:
                    # Get zone type
                    with open(zone / "type", 'r') as f:
                        zone_type = f.read().strip()
                    
                    # Add to sensors dict
                    sensors[zone_type] = str(zone / "temp")
                    logger.debug(f"Discovered temperature sensor: {zone_type} at {zone / 'temp'}")
                except Exception as e:
                    logger.warning(f"Failed to read thermal zone {zone}: {str(e)}")
        
        # If no sensors found, use default
        if not sensors:
            logger.warning("No temperature sensors found, using CPU thermal zone as fallback")
            sensors["cpu"] = "/sys/class/thermal/thermal_zone0/temp"
        
        return sensors
    
    def get_cpu_usage(self) -> float:
        """
        Get current CPU usage as a percentage.
        
        Returns:
            CPU usage percentage (0-100)
        """
        try:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            self.last_readings["cpu_usage"] = cpu_percent
            
            # Add to history
            if "cpu_usage" not in self.reading_history:
                self.reading_history["cpu_usage"] = []
            
            self.reading_history["cpu_usage"].append((time.time(), cpu_percent))
            
            # Keep only last 1000 readings
            if len(self.reading_history["cpu_usage"]) > 1000:
                self.reading_history["cpu_usage"].pop(0)
            
            return cpu_percent
        except Exception as e:
            logger.error(f"Failed to get CPU usage: {str(e)}")
            return -1.0
    
    def get_memory_usage(self) -> Dict[str, float]:
        """
        Get current memory usage statistics.
        
        Returns:
            Dictionary containing:
            - total: Total memory in MB
            - used: Used memory in MB
            - free: Free memory in MB
            - percent: Usage percentage (0-100)
        """
        try:
            mem = psutil.virtual_memory()
            
            # Convert to MB
            total_mb = mem.total / (1024 * 1024)
            used_mb = mem.used / (1024 * 1024)
            free_mb = mem.free / (1024 * 1024)
            
            result = {
                "total": total_mb,
                "used": used_mb,
                "free": free_mb,
                "percent": mem.percent
            }
            
            self.last_readings["memory_usage"] = mem.percent
            
            # Add to history
            if "memory_usage" not in self.reading_history:
                self.reading_history["memory_usage"] = []
            
            self.reading_history["memory_usage"].append((time.time(), mem.percent))
            
            # Keep only last 1000 readings
            if len(self.reading_history["memory_usage"]) > 1000:
                self.reading_history["memory_usage"].pop(0)
            
            return result
        except Exception as e:
            logger.error(f"Failed to get memory usage: {str(e)}")
            return {
                "total": -1.0,
                "used": -1.0,
                "free": -1.0,
                "percent": -1.0
            }
    
    def get_storage_usage(self, path: str = "/") -> Dict[str, float]:
        """
        Get storage usage statistics for a given path.
        
        Args:
            path: Path to check storage usage for
            
        Returns:
            Dictionary containing:
            - total: Total storage in GB
            - used: Used storage in GB
            - free: Free storage in GB
            - percent: Usage percentage (0-100)
        """
        try:
            disk = psutil.disk_usage(path)
            
            # Convert to GB
            total_gb = disk.total / (1024 * 1024 * 1024)
            used_gb = disk.used / (1024 * 1024 * 1024)
            free_gb = disk.free / (1024 * 1024 * 1024)
            
            result = {
                "total": total_gb,
                "used": used_gb,
                "free": free_gb,
                "percent": disk.percent
            }
            
            self.last_readings["storage_usage"] = disk.percent
            
            # Add to history
            if "storage_usage" not in self.reading_history:
                self.reading_history["storage_usage"] = []
            
            self.reading_history["storage_usage"].append((time.time(), disk.percent))
            
            # Keep only last 1000 readings
            if len(self.reading_history["storage_usage"]) > 1000:
                self.reading_history["storage_usage"].pop(0)
            
            return result
        except Exception as e:
            logger.error(f"Failed to get storage usage for {path}: {str(e)}")
            return {
                "total": -1.0,
                "used": -1.0,
                "free": -1.0,
                "percent": -1.0
            }
    
    def get_temperature(self, sensor: str = "cpu") -> float:
        """
        Get temperature from a specific sensor.
        
        Args:
            sensor: Sensor name (e.g., "cpu")
            
        Returns:
            Temperature in Celsius
        """
        try:
            # Get sensor path
            sensor_path = self.temp_sensors.get(sensor)
            if not sensor_path:
                logger.warning(f"Temperature sensor {sensor} not found")
                return -1.0
            
            # Read temperature
            with open(sensor_path, 'r') as f:
                temp_raw = f.read().strip()
            
            # Convert to Celsius (value is in milliCelsius)
            temp_celsius = float(temp_raw) / 1000.0
            
            self.last_readings[f"{sensor}_temp"] = temp_celsius
            
            # Add to history
            history_key = f"{sensor}_temp"
            if history_key not in self.reading_history:
                self.reading_history[history_key] = []
            
            self.reading_history[history_key].append((time.time(), temp_celsius))
            
            # Keep only last 1000 readings
            if len(self.reading_history[history_key]) > 1000:
                self.reading_history[history_key].pop(0)
            
            return temp_celsius
        except Exception as e:
            logger.error(f"Failed to get temperature for sensor {sensor}: {str(e)}")
            return -1.0
    
    def get_network_stats(self) -> Dict[str, Dict[str, float]]:
        """
        Get network statistics for all interfaces.
        
        Returns:
            Dictionary mapping interface names to stats:
            - bytes_sent: Bytes sent
            - bytes_recv: Bytes received
            - packets_sent: Packets sent
            - packets_recv: Packets received
            - errin: Input errors
            - errout: Output errors
        """
        try:
            net_stats = {}
            net_io = psutil.net_io_counters(pernic=True)
            
            for interface, stats in net_io.items():
                net_stats[interface] = {
                    "bytes_sent": stats.bytes_sent,
                    "bytes_recv": stats.bytes_recv,
                    "packets_sent": stats.packets_sent,
                    "packets_recv": stats.packets_recv,
                    "errin": stats.errin,
                    "errout": stats.errout
                }
            
            return net_stats
        except Exception as e:
            logger.error(f"Failed to get network stats: {str(e)}")
            return {}
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """
        Get all hardware metrics in a single call.
        
        Returns:
            Dictionary containing all metrics
        """
        metrics = {
            "timestamp": time.time(),
            "cpu": {
                "usage": self.get_cpu_usage()
            },
            "memory": self.get_memory_usage(),
            "storage": self.get_storage_usage(),
            "temperature": {},
            "network": self.get_network_stats()
        }
        
        # Get temperatures for all sensors
        for sensor in self.temp_sensors.keys():
            metrics["temperature"][sensor] = self.get_temperature(sensor)
        
        return metrics
    
    def check_alerts(self) -> List[Dict[str, Any]]:
        """
        Check for any metrics that exceed alert thresholds.
        
        Returns:
            List of alert dictionaries
        """
        alerts = []
        
        # Check CPU usage
        if "cpu_usage" in self.last_readings and self.last_readings["cpu_usage"] > self.alert_thresholds.get("cpu_usage", 90.0):
            alerts.append({
                "type": "cpu_usage",
                "value": self.last_readings["cpu_usage"],
                "threshold": self.alert_thresholds.get("cpu_usage", 90.0),
                "message": f"CPU usage is high: {self.last_readings['cpu_usage']:.1f}%"
            })
        
        # Check memory usage
        if "memory_usage" in self.last_readings and self.last_readings["memory_usage"] > self.alert_thresholds.get("memory_usage", 90.0):
            alerts.append({
                "type": "memory_usage",
                "value": self.last_readings["memory_usage"],
                "threshold": self.alert_thresholds.get("memory_usage", 90.0),
                "message": f"Memory usage is high: {self.last_readings['memory_usage']:.1f}%"
            })
        
        # Check storage usage
        if "storage_usage" in self.last_readings and self.last_readings["storage_usage"] > self.alert_thresholds.get("storage_usage", 90.0):
            alerts.append({
                "type": "storage_usage",
                "value": self.last_readings["storage_usage"],
                "threshold": self.alert_thresholds.get("storage_usage", 90.0),
                "message": f"Storage usage is high: {self.last_readings['storage_usage']:.1f}%"
            })
        
        # Check CPU temperature
        if "cpu_temp" in self.last_readings and self.last_readings["cpu_temp"] > self.alert_thresholds.get("cpu_temp", 80.0):
            alerts.append({
                "type": "cpu_temp",
                "value": self.last_readings["cpu_temp"],
                "threshold": self.alert_thresholds.get("cpu_temp", 80.0),
                "message": f"CPU temperature is high: {self.last_readings['cpu_temp']:.1f}°C"
            })
        
        return alerts


class PowerManager:
    """
    Manages power-related functionality for the Viztron Homebase Module.
    
    This class handles power state monitoring, battery backup management,
    and power-saving features.
    """
    
    def __init__(self, config_path: str = "/etc/viztron/power_config.json"):
        """
        Initialize the power manager.
        
        Args:
            config_path: Path to the power configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        self.battery_status = {
            "present": False,
            "charging": False,
            "level": 0.0,
            "time_remaining": 0.0
        }
        self.power_source = "AC"  # "AC" or "BATTERY"
        self.power_save_mode = False
        self.last_power_event = None
        
        # Set up battery monitoring if available
        self.battery_path = self.config.get("battery_path", "/sys/class/power_supply/BAT0")
        
        # Initialize power state
        self._update_power_state()
        
        logger.info("Power manager initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load power configuration from file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                return {}
        except Exception as e:
            logger.error(f"Failed to load power config: {str(e)}")
            return {}
    
    def _update_power_state(self):
        """Update current power state information."""
        try:
            # Check if battery is present
            battery_present = os.path.exists(self.battery_path)
            
            if battery_present:
                # Read battery status
                with open(os.path.join(self.battery_path, "status"), 'r') as f:
                    status = f.read().strip()
                
                # Read battery level
                with open(os.path.join(self.battery_path, "capacity"), 'r') as f:
                    capacity = float(f.read().strip())
                
                # Determine if charging
                charging = status.lower() == "charging"
                
                # Determine power source
                power_source = "AC" if charging or status.lower() == "full" else "BATTERY"
                
                # Calculate time remaining (if on battery)
                time_remaining = 0.0
                if power_source == "BATTERY":
                    # Read current power consumption
                    try:
                        with open(os.path.join(self.battery_path, "current_now"), 'r') as f:
                            current = float(f.read().strip()) / 1000000.0  # Convert to A
                        
                        with open(os.path.join(self.battery_path, "voltage_now"), 'r') as f:
                            voltage = float(f.read().strip()) / 1000000.0  # Convert to V
                        
                        # Calculate power in W
                        power = current * voltage
                        
                        # Read battery energy
                        with open(os.path.join(self.battery_path, "energy_now"), 'r') as f:
                            energy = float(f.read().strip()) / 1000000.0  # Convert to Wh
                        
                        # Calculate time remaining in hours
                        if power > 0:
                            time_remaining = energy / power
                        else:
                            time_remaining = 0.0
                    except Exception as e:
                        logger.warning(f"Failed to calculate battery time remaining: {str(e)}")
                        time_remaining = 0.0
                
                # Update battery status
                self.battery_status = {
                    "present": True,
                    "charging": charging,
                    "level": capacity,
                    "time_remaining": time_remaining
                }
                
                # Update power source
                self.power_source = power_source
                
                # Check for power source change
                if self.power_source != self.last_power_event:
                    logger.info(f"Power source changed to {self.power_source}")
                    self.last_power_event = self.power_source
                    
                    # Enable power save mode if on battery
                    if self.power_source == "BATTERY":
                        self.enable_power_save_mode()
                    else:
                        self.disable_power_save_mode()
            else:
                # No battery present
                self.battery_status = {
                    "present": False,
                    "charging": False,
                    "level": 0.0,
                    "time_remaining": 0.0
                }
                self.power_source = "AC"
        except Exception as e:
            logger.error(f"Failed to update power state: {str(e)}")
    
    def get_power_status(self) -> Dict[str, Any]:
        """
        Get current power status.
        
        Returns:
            Dictionary containing power status information
        """
        # Update power state
        self._update_power_state()
        
        return {
            "power_source": self.power_source,
            "battery": self.battery_status,
            "power_save_mode": self.power_save_mode
        }
    
    def enable_power_save_mode(self):
        """Enable power save mode to conserve battery."""
        if not self.power_save_mode:
            logger.info("Enabling power save mode")
            self.power_save_mode = True
            
            # Implement power-saving measures
            try:
                # Reduce CPU frequency
                if os.path.exists("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"):
                    for cpu in range(4):  # Assuming 4 CPU cores
                        governor_path = f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor"
                        if os.path.exists(governor_path):
                            with open(governor_path, 'w') as f:
                                f.write("powersave")
                
                # Reduce screen brightness if applicable
                backlight_path = "/sys/class/backlight/backlight/brightness"
                if os.path.exists(backlight_path):
                    with open(backlight_path, 'r') as f:
                        current_brightness = int(f.read().strip())
                    
                    # Save current brightness
                    self.saved_brightness = current_brightness
                    
                    # Set to 30% of max brightness
                    with open("/sys/class/backlight/backlight/max_brightness", 'r') as f:
                        max_brightness = int(f.read().strip())
                    
                    new_brightness = max(1, int(max_brightness * 0.3))
                    
                    with open(backlight_path, 'w') as f:
                        f.write(str(new_brightness))
                
                # Notify system components about power save mode
                # This would typically be done through a message bus or API
                
                logger.info("Power save mode enabled")
            except Exception as e:
                logger.error(f"Failed to enable power save mode: {str(e)}")
    
    def disable_power_save_mode(self):
        """Disable power save mode when on AC power."""
        if self.power_save_mode:
            logger.info("Disabling power save mode")
            self.power_save_mode = False
            
            # Restore normal power settings
            try:
                # Restore CPU frequency
                if os.path.exists("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"):
                    for cpu in range(4):  # Assuming 4 CPU cores
                        governor_path = f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor"
                        if os.path.exists(governor_path):
                            with open(governor_path, 'w') as f:
                                f.write("ondemand")
                
                # Restore screen brightness if applicable
                backlight_path = "/sys/class/backlight/backlight/brightness"
                if os.path.exists(backlight_path) and hasattr(self, 'saved_brightness'):
                    with open(backlight_path, 'w') as f:
                        f.write(str(self.saved_brightness))
                
                # Notify system components about normal power mode
                # This would typically be done through a message bus or API
                
                logger.info("Power save mode disabled")
            except Exception as e:
                logger.error(f"Failed to disable power save mode: {str(e)}")
    
    def handle_low_battery(self):
        """Handle low battery condition."""
        # Get current battery status
        power_status = self.get_power_status()
        
        # Check if on battery and level is low
        if power_status["power_source"] == "BATTERY":
            battery_level = power_status["battery"]["level"]
            
            # Critical battery level (10%)
            if battery_level <= 10.0:
                logger.critical(f"Critical battery level: {battery_level:.1f}%")
                
                # Initiate emergency shutdown
                self._initiate_shutdown()
            
            # Low battery level (20%)
            elif battery_level <= 20.0:
                logger.warning(f"Low battery level: {battery_level:.1f}%")
                
                # Enable extreme power saving
                self._enable_extreme_power_save()
    
    def _enable_extreme_power_save(self):
        """Enable extreme power saving measures."""
        logger.info("Enabling extreme power saving measures")
        
        try:
            # Set CPU to lowest frequency
            if os.path.exists("/sys/devices/system/cpu/cpu0/cpufreq/scaling_setspeed"):
                # Get available frequencies
                with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_frequencies", 'r') as f:
                    freqs = f.read().strip().split()
                
                # Set to lowest frequency
                lowest_freq = min([int(f) for f in freqs])
                
                for cpu in range(4):  # Assuming 4 CPU cores
                    # Set governor to userspace
                    governor_path = f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor"
                    if os.path.exists(governor_path):
                        with open(governor_path, 'w') as f:
                            f.write("userspace")
                    
                    # Set frequency
                    setspeed_path = f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_setspeed"
                    if os.path.exists(setspeed_path):
                        with open(setspeed_path, 'w') as f:
                            f.write(str(lowest_freq))
            
            # Disable non-essential services
            # This would typically be done through systemd or other service manager
            
            # Notify system components about extreme power save mode
            # This would typically be done through a message bus or API
            
            logger.info("Extreme power saving measures enabled")
        except Exception as e:
            logger.error(f"Failed to enable extreme power saving: {str(e)}")
    
    def _initiate_shutdown(self):
        """Initiate system shutdown due to critical battery level."""
        logger.critical("Initiating system shutdown due to critical battery level")
        
        try:
            # Notify system components about imminent shutdown
            # This would typically be done through a message bus or API
            
            # Sync file systems
            subprocess.run(["sync"], check=True)
            
            # Initiate shutdown
            subprocess.run(["shutdown", "-h", "now"], check=True)
        except Exception as e:
            logger.error(f"Failed to initiate shutdown: {str(e)}")


class SystemManager:
    """
    Main system manager for the Viztron Homebase Module.
    
    This class coordinates system-wide operations, manages hardware and power,
    and provides interfaces for other components to interact with the system.
    """
    
    def __init__(self, config_path: str = "/etc/viztron/system_config.json"):
        """
        Initialize the system manager.
        
        Args:
            config_path: Path to the system configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        
        # Create required directories
        os.makedirs("/var/log/viztron", exist_ok=True)
        os.makedirs("/var/run/viztron", exist_ok=True)
        
        # Initialize components
        self.hardware_monitor = HardwareMonitor()
        self.power_manager = PowerManager()
        
        # Set up monitoring thread
        self.monitoring_interval = self.config.get("monitoring_interval", 60)  # seconds
        self.monitoring_thread = None
        self.monitoring_active = False
        
        # Set up signal handlers
        signal.signal(signal.SIGTERM, self._handle_sigterm)
        signal.signal(signal.SIGINT, self._handle_sigterm)
        
        # Create PID file
        self._create_pid_file()
        
        logger.info("System manager initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load system configuration from file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                return {}
        except Exception as e:
            logger.error(f"Failed to load system config: {str(e)}")
            return {}
    
    def _create_pid_file(self):
        """Create PID file for the system manager."""
        try:
            pid = os.getpid()
            with open("/var/run/viztron/system_manager.pid", 'w') as f:
                f.write(str(pid))
            logger.debug(f"Created PID file with PID {pid}")
        except Exception as e:
            logger.error(f"Failed to create PID file: {str(e)}")
    
    def _handle_sigterm(self, signum, frame):
        """Handle SIGTERM signal for graceful shutdown."""
        logger.info(f"Received signal {signum}, shutting down")
        self.shutdown()
        sys.exit(0)
    
    def start_monitoring(self):
        """Start the system monitoring thread."""
        if not self.monitoring_active:
            logger.info("Starting system monitoring")
            self.monitoring_active = True
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop)
            self.monitoring_thread.daemon = True
            self.monitoring_thread.start()
    
    def stop_monitoring(self):
        """Stop the system monitoring thread."""
        if self.monitoring_active:
            logger.info("Stopping system monitoring")
            self.monitoring_active = False
            if self.monitoring_thread:
                self.monitoring_thread.join(timeout=5.0)
    
    def _monitoring_loop(self):
        """Main monitoring loop that runs in a separate thread."""
        logger.info(f"Monitoring loop started with interval {self.monitoring_interval} seconds")
        
        while self.monitoring_active:
            try:
                # Get hardware metrics
                metrics = self.hardware_monitor.get_all_metrics()
                
                # Check for alerts
                alerts = self.hardware_monitor.check_alerts()
                for alert in alerts:
                    logger.warning(f"Hardware alert: {alert['message']}")
                    # Here you would typically send alerts to other system components
                
                # Check power status
                power_status = self.power_manager.get_power_status()
                
                # Handle low battery if needed
                if power_status["power_source"] == "BATTERY":
                    self.power_manager.handle_low_battery()
                
                # Log system status periodically
                logger.info(f"System status: CPU {metrics['cpu']['usage']:.1f}%, "
                           f"Memory {metrics['memory']['percent']:.1f}%, "
                           f"Storage {metrics['storage']['percent']:.1f}%, "
                           f"Power: {power_status['power_source']}")
                
                # Sleep for the monitoring interval
                time.sleep(self.monitoring_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(5.0)  # Sleep briefly before retrying
    
    def get_system_status(self) -> Dict[str, Any]:
        """
        Get comprehensive system status.
        
        Returns:
            Dictionary containing system status information
        """
        try:
            # Get hardware metrics
            hardware_metrics = self.hardware_monitor.get_all_metrics()
            
            # Get power status
            power_status = self.power_manager.get_power_status()
            
            # Get system uptime
            uptime = time.time() - psutil.boot_time()
            
            # Get system load
            load_avg = os.getloadavg()
            
            # Combine into system status
            system_status = {
                "timestamp": time.time(),
                "uptime": uptime,
                "load_average": {
                    "1min": load_avg[0],
                    "5min": load_avg[1],
                    "15min": load_avg[2]
                },
                "hardware": hardware_metrics,
                "power": power_status
            }
            
            return system_status
        except Exception as e:
            logger.error(f"Failed to get system status: {str(e)}")
            return {
                "timestamp": time.time(),
                "error": str(e)
            }
    
    def shutdown(self):
        """Perform a graceful system shutdown."""
        logger.info("Initiating system shutdown")
        
        try:
            # Stop monitoring
            self.stop_monitoring()
            
            # Perform cleanup
            logger.info("Cleaning up before shutdown")
            
            # Remove PID file
            if os.path.exists("/var/run/viztron/system_manager.pid"):
                os.remove("/var/run/viztron/system_manager.pid")
            
            logger.info("System manager shutdown complete")
        except Exception as e:
            logger.error(f"Error during shutdown: {str(e)}")
    
    def reboot(self):
        """Perform a system reboot."""
        logger.info("Initiating system reboot")
        
        try:
            # Stop monitoring
            self.stop_monitoring()
            
            # Perform cleanup
            logger.info("Cleaning up before reboot")
            
            # Remove PID file
            if os.path.exists("/var/run/viztron/system_manager.pid"):
                os.remove("/var/run/viztron/system_manager.pid")
            
            # Sync file systems
            subprocess.run(["sync"], check=True)
            
            # Initiate reboot
            subprocess.run(["reboot"], check=True)
        except Exception as e:
            logger.error(f"Error during reboot: {str(e)}")


# Example usage
if __name__ == "__main__":
    # Create system manager
    system_manager = SystemManager()
    
    try:
        # Start monitoring
        system_manager.start_monitoring()
        
        # Run for a while
        logger.info("System manager running. Press Ctrl+C to exit.")
        
        # Main loop
        while True:
            # Get system status
            status = system_manager.get_system_status()
            
            # Print summary
            print(f"System Status:")
            print(f"  CPU: {status['hardware']['cpu']['usage']:.1f}%")
            print(f"  Memory: {status['hardware']['memory']['percent']:.1f}%")
            print(f"  Storage: {status['hardware']['storage']['percent']:.1f}%")
            print(f"  Power: {status['power']['power_source']}")
            if status['power']['battery']['present']:
                print(f"  Battery: {status['power']['battery']['level']:.1f}%")
                if status['power']['battery']['charging']:
                    print(f"  Charging: Yes")
                else:
                    print(f"  Time Remaining: {status['power']['battery']['time_remaining']:.1f} hours")
            
            # Sleep for a while
            time.sleep(10)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down")
    finally:
        # Shutdown
        system_manager.shutdown()
