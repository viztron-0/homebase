#!/usr/bin/env python3
"""
Update Manager for Viztron Homebase Module

This module implements the update management functionality for the
Viztron Homebase Module, handling OTA updates, package management,
and system upgrades.

Author: Viztron System Team
Date: April 20, 2025
"""

import os
import sys
import time
import logging
import json
import subprocess
import threading
import requests
import hashlib
import tarfile
import shutil
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/viztron/update_manager.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('update_manager')

class PackageManager:
    """
    Manages system packages and dependencies.
    
    This class provides methods to install, update, and remove
    system packages using apt and pip.
    """
    
    def __init__(self, config_path: str = "/etc/viztron/package_config.json"):
        """
        Initialize the package manager.
        
        Args:
            config_path: Path to the package configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        
        # Required packages
        self.required_packages = self.config.get("required_packages", {
            "apt": [],
            "pip": []
        })
        
        # Package sources
        self.package_sources = self.config.get("package_sources", {
            "apt": [],
            "pip": []
        })
        
        # Update lock file
        self.lock_file = "/var/run/viztron/package_update.lock"
        
        logger.info("Package manager initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load package configuration from file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                return {
                    "required_packages": {
                        "apt": [],
                        "pip": []
                    },
                    "package_sources": {
                        "apt": [],
                        "pip": []
                    }
                }
        except Exception as e:
            logger.error(f"Failed to load package config: {str(e)}")
            return {
                "required_packages": {
                    "apt": [],
                    "pip": []
                },
                "package_sources": {
                    "apt": [],
                    "pip": []
                }
            }
    
    def _acquire_lock(self) -> bool:
        """
        Acquire lock for package operations.
        
        Returns:
            True if lock acquired, False otherwise
        """
        try:
            # Check if lock file exists
            if os.path.exists(self.lock_file):
                # Check if lock is stale (older than 1 hour)
                lock_time = os.path.getmtime(self.lock_file)
                if time.time() - lock_time < 3600:  # 1 hour
                    logger.warning("Package update lock is held by another process")
                    return False
                else:
                    logger.warning("Removing stale package update lock")
                    os.remove(self.lock_file)
            
            # Create lock file
            with open(self.lock_file, 'w') as f:
                f.write(str(os.getpid()))
            
            logger.debug("Acquired package update lock")
            return True
        except Exception as e:
            logger.error(f"Failed to acquire package update lock: {str(e)}")
            return False
    
    def _release_lock(self):
        """Release lock for package operations."""
        try:
            if os.path.exists(self.lock_file):
                os.remove(self.lock_file)
            logger.debug("Released package update lock")
        except Exception as e:
            logger.error(f"Failed to release package update lock: {str(e)}")
    
    def update_package_lists(self) -> bool:
        """
        Update package lists from repositories.
        
        Returns:
            True if successful, False otherwise
        """
        if not self._acquire_lock():
            return False
        
        try:
            logger.info("Updating package lists")
            
            # Update apt package lists
            result = subprocess.run(
                ["apt-get", "update", "-y"],
                capture_output=True,
                text=True,
                check=True
            )
            
            logger.info("Package lists updated successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to update package lists: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Failed to update package lists: {str(e)}")
            return False
        finally:
            self._release_lock()
    
    def install_package(self, package_name: str, package_type: str = "apt") -> bool:
        """
        Install a package.
        
        Args:
            package_name: Name of the package
            package_type: Type of package manager to use ("apt" or "pip")
            
        Returns:
            True if successful, False otherwise
        """
        if not self._acquire_lock():
            return False
        
        try:
            logger.info(f"Installing {package_type} package: {package_name}")
            
            if package_type == "apt":
                # Install apt package
                result = subprocess.run(
                    ["apt-get", "install", "-y", package_name],
                    capture_output=True,
                    text=True,
                    check=True
                )
            elif package_type == "pip":
                # Install pip package
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", package_name],
                    capture_output=True,
                    text=True,
                    check=True
                )
            else:
                logger.error(f"Unknown package type: {package_type}")
                return False
            
            logger.info(f"Package {package_name} installed successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install package {package_name}: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Failed to install package {package_name}: {str(e)}")
            return False
        finally:
            self._release_lock()
    
    def upgrade_package(self, package_name: str, package_type: str = "apt") -> bool:
        """
        Upgrade a package.
        
        Args:
            package_name: Name of the package
            package_type: Type of package manager to use ("apt" or "pip")
            
        Returns:
            True if successful, False otherwise
        """
        if not self._acquire_lock():
            return False
        
        try:
            logger.info(f"Upgrading {package_type} package: {package_name}")
            
            if package_type == "apt":
                # Upgrade apt package
                result = subprocess.run(
                    ["apt-get", "install", "--only-upgrade", "-y", package_name],
                    capture_output=True,
                    text=True,
                    check=True
                )
            elif package_type == "pip":
                # Upgrade pip package
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", "--upgrade", package_name],
                    capture_output=True,
                    text=True,
                    check=True
                )
            else:
                logger.error(f"Unknown package type: {package_type}")
                return False
            
            logger.info(f"Package {package_name} upgraded successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to upgrade package {package_name}: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Failed to upgrade package {package_name}: {str(e)}")
            return False
        finally:
            self._release_lock()
    
    def remove_package(self, package_name: str, package_type: str = "apt") -> bool:
        """
        Remove a package.
        
        Args:
            package_name: Name of the package
            package_type: Type of package manager to use ("apt" or "pip")
            
        Returns:
            True if successful, False otherwise
        """
        if not self._acquire_lock():
            return False
        
        try:
            logger.info(f"Removing {package_type} package: {package_name}")
            
            if package_type == "apt":
                # Remove apt package
                result = subprocess.run(
                    ["apt-get", "remove", "-y", package_name],
                    capture_output=True,
                    text=True,
                    check=True
                )
            elif package_type == "pip":
                # Remove pip package
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "uninstall", "-y", package_name],
                    capture_output=True,
                    text=True,
                    check=True
                )
            else:
                logger.error(f"Unknown package type: {package_type}")
                return False
            
            logger.info(f"Package {package_name} removed successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to remove package {package_name}: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Failed to remove package {package_name}: {str(e)}")
            return False
        finally:
            self._release_lock()
    
    def upgrade_all_packages(self) -> bool:
        """
        Upgrade all installed packages.
        
        Returns:
            True if successful, False otherwise
        """
        if not self._acquire_lock():
            return False
        
        try:
            logger.info("Upgrading all packages")
            
            # Update package lists first
            self.update_package_lists()
            
            # Upgrade apt packages
            apt_result = subprocess.run(
                ["apt-get", "upgrade", "-y"],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Upgrade pip packages
            pip_result = subprocess.run(
                [sys.executable, "-m", "pip", "list", "--outdated", "--format=json"],
                capture_output=True,
                text=True,
                check=True
            )
            
            # Parse pip output
            pip_outdated = json.loads(pip_result.stdout)
            
            for package in pip_outdated:
                package_name = package["name"]
                logger.info(f"Upgrading pip package: {package_name}")
                
                try:
                    upgrade_result = subprocess.run(
                        [sys.executable, "-m", "pip", "install", "--upgrade", package_name],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                except Exception as e:
                    logger.error(f"Failed to upgrade pip package {package_name}: {str(e)}")
            
            logger.info("All packages upgraded successfully")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to upgrade all packages: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Failed to upgrade all packages: {str(e)}")
            return False
        finally:
            self._release_lock()
    
    def install_required_packages(self) -> bool:
        """
        Install all required packages.
        
        Returns:
            True if successful, False otherwise
        """
        if not self._acquire_lock():
            return False
        
        try:
            logger.info("Installing required packages")
            
            # Update package lists first
            self.update_package_lists()
            
            # Install apt packages
            for package in self.required_packages.get("apt", []):
                try:
                    logger.info(f"Installing apt package: {package}")
                    result = subprocess.run(
                        ["apt-get", "install", "-y", package],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                except Exception as e:
                    logger.error(f"Failed to install apt package {package}: {str(e)}")
            
            # Install pip packages
            for package in self.required_packages.get("pip", []):
                try:
                    logger.info(f"Installing pip package: {package}")
                    result = subprocess.run(
                        [sys.executable, "-m", "pip", "install", package],
                        capture_output=True,
                        text=True,
                        check=True
                    )
                except Exception as e:
                    logger.error(f"Failed to install pip package {package}: {str(e)}")
            
            logger.info("Required packages installed successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to install required packages: {str(e)}")
            return False
        finally:
            self._release_lock()
    
    def add_package_source(self, source: str, source_type: str = "apt") -> bool:
        """
        Add a package source.
        
        Args:
            source: Source URL or repository
            source_type: Type of package manager to use ("apt" or "pip")
            
        Returns:
            True if successful, False otherwise
        """
        if not self._acquire_lock():
            return False
        
        try:
            logger.info(f"Adding {source_type} package source: {source}")
            
            if source_type == "apt":
                # Add apt repository
                result = subprocess.run(
                    ["add-apt-repository", "-y", source],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                # Update package lists
                self.update_package_lists()
            elif source_type == "pip":
                # Add pip index URL to pip.conf
                pip_conf_dir = Path.home() / ".pip"
                pip_conf_file = pip_conf_dir / "pip.conf"
                
                # Create directory if it doesn't exist
                pip_conf_dir.mkdir(exist_ok=True)
                
                # Read existing config
                if pip_conf_file.exists():
                    with open(pip_conf_file, 'r') as f:
                        pip_conf = f.read()
                else:
                    pip_conf = "[global]\n"
                
                # Add index URL if not already present
                if f"extra-index-url={source}" not in pip_conf:
                    if "extra-index-url" in pip_conf:
                        # Append to existing extra-index-url
                        pip_conf = pip_conf.replace(
                            "extra-index-url=",
                            f"extra-index-url={source} "
                        )
                    else:
                        # Add new extra-index-url
                        pip_conf += f"extra-index-url={source}\n"
                    
                    # Write updated config
                    with open(pip_conf_file, 'w') as f:
                        f.write(pip_conf)
            else:
                logger.error(f"Unknown package source type: {source_type}")
                return False
            
            logger.info(f"Package source {source} added successfully")
            
            # Add to config
            if source not in self.package_sources.get(source_type, []):
                self.package_sources.setdefault(source_type, []).append(source)
                
                # Save config
                with open(self.config_path, 'w') as f:
                    json.dump(self.config, f, indent=2)
            
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to add package source {source}: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Failed to add package source {source}: {str(e)}")
            return False
        finally:
            self._release_lock()
    
    def remove_package_source(self, source: str, source_type: str = "apt") -> bool:
        """
        Remove a package source.
        
        Args:
            source: Source URL or repository
            source_type: Type of package manager to use ("apt" or "pip")
            
        Returns:
            True if successful, False otherwise
        """
        if not self._acquire_lock():
            return False
        
        try:
            logger.info(f"Removing {source_type} package source: {source}")
            
            if source_type == "apt":
                # Remove apt repository
                result = subprocess.run(
                    ["add-apt-repository", "-y", "-r", source],
                    capture_output=True,
                    text=True,
                    check=True
                )
                
                # Update package lists
                self.update_package_lists()
            elif source_type == "pip":
                # Remove pip index URL from pip.conf
                pip_conf_dir = Path.home() / ".pip"
                pip_conf_file = pip_conf_dir / "pip.conf"
                
                # Read existing config
                if pip_conf_file.exists():
                    with open(pip_conf_file, 'r') as f:
                        pip_conf = f.read()
                    
                    # Remove index URL
                    pip_conf = pip_conf.replace(f"extra-index-url={source} ", "extra-index-url=")
                    pip_conf = pip_conf.replace(f"extra-index-url={source}\n", "")
                    
                    # Write updated config
                    with open(pip_conf_file, 'w') as f:
                        f.write(pip_conf)
            else:
                logger.error(f"Unknown package source type: {source_type}")
                return False
            
            logger.info(f"Package source {source} removed successfully")
            
            # Remove from config
            if source in self.package_sources.get(source_type, []):
                self.package_sources[source_type].remove(source)
                
                # Save config
                with open(self.config_path, 'w') as f:
                    json.dump(self.config, f, indent=2)
            
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to remove package source {source}: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Failed to remove package source {source}: {str(e)}")
            return False
        finally:
            self._release_lock()


class FirmwareManager:
    """
    Manages firmware updates for the Viztron Homebase Module.
    
    This class provides methods to check for, download, and apply
    firmware updates for the system.
    """
    
    def __init__(self, config_path: str = "/etc/viztron/firmware_config.json"):
        """
        Initialize the firmware manager.
        
        Args:
            config_path: Path to the firmware configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        
        # Firmware update server
        self.update_server = self.config.get("update_server", "https://updates.viztron.com")
        
        # Current firmware version
        self.current_version = self._get_current_version()
        
        # Update check interval
        self.update_check_interval = self.config.get("update_check_interval", 86400)  # 24 hours
        
        # Last update check time
        self.last_update_check = self.config.get("last_update_check", 0)
        
        # Download directory
        self.download_dir = self.config.get("download_dir", "/var/cache/viztron/firmware")
        
        # Create download directory if it doesn't exist
        os.makedirs(self.download_dir, exist_ok=True)
        
        # Update lock file
        self.lock_file = "/var/run/viztron/firmware_update.lock"
        
        logger.info(f"Firmware manager initialized with version {self.current_version}")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load firmware configuration from file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                return {
                    "update_server": "https://updates.viztron.com",
                    "update_check_interval": 86400,
                    "last_update_check": 0,
                    "download_dir": "/var/cache/viztron/firmware"
                }
        except Exception as e:
            logger.error(f"Failed to load firmware config: {str(e)}")
            return {
                "update_server": "https://updates.viztron.com",
                "update_check_interval": 86400,
                "last_update_check": 0,
                "download_dir": "/var/cache/viztron/firmware"
            }
    
    def _save_config(self):
        """Save firmware configuration to file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save firmware config: {str(e)}")
    
    def _get_current_version(self) -> str:
        """
        Get current firmware version.
        
        Returns:
            Current firmware version string
        """
        try:
            # Try to read version from file
            version_file = "/etc/viztron/version"
            if os.path.exists(version_file):
                with open(version_file, 'r') as f:
                    return f.read().strip()
            else:
                # Default version if file doesn't exist
                return "0.0.0"
        except Exception as e:
            logger.error(f"Failed to get current firmware version: {str(e)}")
            return "0.0.0"
    
    def _set_current_version(self, version: str):
        """
        Set current firmware version.
        
        Args:
            version: New firmware version string
        """
        try:
            # Write version to file
            version_file = "/etc/viztron/version"
            with open(version_file, 'w') as f:
                f.write(version)
            
            # Update in-memory version
            self.current_version = version
            
            logger.info(f"Current firmware version set to {version}")
        except Exception as e:
            logger.error(f"Failed to set current firmware version: {str(e)}")
    
    def _acquire_lock(self) -> bool:
        """
        Acquire lock for firmware operations.
        
        Returns:
            True if lock acquired, False otherwise
        """
        try:
            # Check if lock file exists
            if os.path.exists(self.lock_file):
                # Check if lock is stale (older than 1 hour)
                lock_time = os.path.getmtime(self.lock_file)
                if time.time() - lock_time < 3600:  # 1 hour
                    logger.warning("Firmware update lock is held by another process")
                    return False
                else:
                    logger.warning("Removing stale firmware update lock")
                    os.remove(self.lock_file)
            
            # Create lock file
            with open(self.lock_file, 'w') as f:
                f.write(str(os.getpid()))
            
            logger.debug("Acquired firmware update lock")
            return True
        except Exception as e:
            logger.error(f"Failed to acquire firmware update lock: {str(e)}")
            return False
    
    def _release_lock(self):
        """Release lock for firmware operations."""
        try:
            if os.path.exists(self.lock_file):
                os.remove(self.lock_file)
            logger.debug("Released firmware update lock")
        except Exception as e:
            logger.error(f"Failed to release firmware update lock: {str(e)}")
    
    def check_for_updates(self, force: bool = False) -> Optional[Dict[str, Any]]:
        """
        Check for firmware updates.
        
        Args:
            force: Whether to force check even if interval hasn't elapsed
            
        Returns:
            Update information dictionary if update available, None otherwise
        """
        # Check if update check interval has elapsed
        if not force and time.time() - self.last_update_check < self.update_check_interval:
            logger.debug("Update check interval hasn't elapsed, skipping check")
            return None
        
        try:
            logger.info("Checking for firmware updates")
            
            # Update last check time
            self.last_update_check = time.time()
            self.config["last_update_check"] = self.last_update_check
            self._save_config()
            
            # Build request URL
            url = f"{self.update_server}/api/v1/updates"
            params = {
                "current_version": self.current_version,
                "device_type": "homebase",
                "hardware_id": self._get_hardware_id()
            }
            
            # Send request
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            
            # Parse response
            update_info = response.json()
            
            if update_info.get("update_available", False):
                logger.info(f"Firmware update available: {update_info.get('version')}")
                return update_info
            else:
                logger.info("No firmware updates available")
                return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to check for firmware updates: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Failed to check for firmware updates: {str(e)}")
            return None
    
    def _get_hardware_id(self) -> str:
        """
        Get unique hardware ID for this device.
        
        Returns:
            Hardware ID string
        """
        try:
            # Try to read hardware ID from file
            hw_id_file = "/etc/viztron/hardware_id"
            if os.path.exists(hw_id_file):
                with open(hw_id_file, 'r') as f:
                    return f.read().strip()
            else:
                # Generate hardware ID based on MAC address or CPU ID
                # First try to get MAC address
                try:
                    # Get MAC address of first network interface
                    with open("/sys/class/net/eth0/address", 'r') as f:
                        mac = f.read().strip()
                    
                    # Generate ID from MAC
                    hw_id = hashlib.sha256(mac.encode()).hexdigest()[:16]
                except Exception:
                    # Fallback to CPU ID
                    try:
                        with open("/proc/cpuinfo", 'r') as f:
                            cpu_info = f.read()
                        
                        # Extract serial or CPU ID
                        for line in cpu_info.split("\n"):
                            if "Serial" in line or "CPU serial" in line:
                                serial = line.split(":")[-1].strip()
                                hw_id = hashlib.sha256(serial.encode()).hexdigest()[:16]
                                break
                        else:
                            # If no serial found, use hash of entire CPU info
                            hw_id = hashlib.sha256(cpu_info.encode()).hexdigest()[:16]
                    except Exception:
                        # Last resort: random ID
                        import random
                        hw_id = ''.join(random.choice('0123456789abcdef') for _ in range(16))
                
                # Save hardware ID to file
                with open(hw_id_file, 'w') as f:
                    f.write(hw_id)
                
                return hw_id
        except Exception as e:
            logger.error(f"Failed to get hardware ID: {str(e)}")
            # Return a fallback ID
            return "unknown_hardware"
    
    def download_update(self, update_info: Dict[str, Any]) -> Optional[str]:
        """
        Download firmware update.
        
        Args:
            update_info: Update information dictionary from check_for_updates()
            
        Returns:
            Path to downloaded update file if successful, None otherwise
        """
        if not self._acquire_lock():
            return None
        
        try:
            logger.info(f"Downloading firmware update {update_info.get('version')}")
            
            # Get download URL
            download_url = update_info.get("download_url")
            if not download_url:
                logger.error("No download URL in update info")
                return None
            
            # Get version
            version = update_info.get("version")
            if not version:
                logger.error("No version in update info")
                return None
            
            # Get checksum
            checksum = update_info.get("checksum")
            checksum_type = update_info.get("checksum_type", "sha256")
            
            # Create download path
            download_path = os.path.join(self.download_dir, f"viztron-homebase-{version}.tar.gz")
            
            # Download file
            response = requests.get(download_url, stream=True, timeout=300)
            response.raise_for_status()
            
            with open(download_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            logger.info(f"Firmware update downloaded to {download_path}")
            
            # Verify checksum if provided
            if checksum:
                logger.info(f"Verifying {checksum_type} checksum")
                
                if checksum_type == "sha256":
                    file_hash = hashlib.sha256()
                elif checksum_type == "md5":
                    file_hash = hashlib.md5()
                else:
                    logger.warning(f"Unsupported checksum type: {checksum_type}")
                    return download_path
                
                with open(download_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        file_hash.update(chunk)
                
                calculated_checksum = file_hash.hexdigest()
                
                if calculated_checksum != checksum:
                    logger.error(f"Checksum verification failed: expected {checksum}, got {calculated_checksum}")
                    os.remove(download_path)
                    return None
                
                logger.info("Checksum verification successful")
            
            return download_path
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to download firmware update: {str(e)}")
            return None
        except Exception as e:
            logger.error(f"Failed to download firmware update: {str(e)}")
            return None
        finally:
            self._release_lock()
    
    def verify_update(self, update_file: str) -> bool:
        """
        Verify firmware update file.
        
        Args:
            update_file: Path to update file
            
        Returns:
            True if verification successful, False otherwise
        """
        if not self._acquire_lock():
            return False
        
        try:
            logger.info(f"Verifying firmware update file: {update_file}")
            
            # Check if file exists
            if not os.path.exists(update_file):
                logger.error(f"Update file not found: {update_file}")
                return False
            
            # Check if file is a valid tar.gz archive
            if not tarfile.is_tarfile(update_file):
                logger.error(f"Update file is not a valid tar archive: {update_file}")
                return False
            
            # Extract version info from filename
            filename = os.path.basename(update_file)
            if filename.startswith("viztron-homebase-") and filename.endswith(".tar.gz"):
                version = filename[len("viztron-homebase-"):-len(".tar.gz")]
            else:
                logger.error(f"Invalid update filename format: {filename}")
                return False
            
            # Open archive and check for required files
            with tarfile.open(update_file, 'r:gz') as tar:
                # Check for manifest file
                try:
                    manifest_info = tar.getmember("manifest.json")
                except KeyError:
                    logger.error("Update archive missing manifest.json")
                    return False
                
                # Extract and parse manifest
                manifest_file = tar.extractfile(manifest_info)
                if not manifest_file:
                    logger.error("Failed to extract manifest.json")
                    return False
                
                try:
                    manifest = json.loads(manifest_file.read().decode('utf-8'))
                except json.JSONDecodeError:
                    logger.error("Invalid manifest.json format")
                    return False
                
                # Check manifest version
                if manifest.get("version") != version:
                    logger.error(f"Version mismatch: filename {version} vs manifest {manifest.get('version')}")
                    return False
                
                # Check for required files in manifest
                required_files = manifest.get("files", [])
                for file_info in required_files:
                    file_path = file_info.get("path")
                    if not file_path:
                        continue
                    
                    try:
                        tar.getmember(file_path)
                    except KeyError:
                        logger.error(f"Required file missing from archive: {file_path}")
                        return False
            
            logger.info("Firmware update verification successful")
            return True
        except Exception as e:
            logger.error(f"Failed to verify firmware update: {str(e)}")
            return False
        finally:
            self._release_lock()
    
    def apply_update(self, update_file: str) -> bool:
        """
        Apply firmware update.
        
        Args:
            update_file: Path to update file
            
        Returns:
            True if update applied successfully, False otherwise
        """
        if not self._acquire_lock():
            return False
        
        try:
            logger.info(f"Applying firmware update: {update_file}")
            
            # Verify update file first
            if not self.verify_update(update_file):
                logger.error("Update verification failed, aborting update")
                return False
            
            # Extract version from filename
            filename = os.path.basename(update_file)
            version = filename[len("viztron-homebase-"):-len(".tar.gz")]
            
            # Create temporary directory for extraction
            temp_dir = os.path.join(self.download_dir, f"update-{version}")
            os.makedirs(temp_dir, exist_ok=True)
            
            # Extract archive
            with tarfile.open(update_file, 'r:gz') as tar:
                tar.extractall(path=temp_dir)
            
            logger.info(f"Extracted update to {temp_dir}")
            
            # Load manifest
            manifest_path = os.path.join(temp_dir, "manifest.json")
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)
            
            # Check for pre-update script
            pre_update_script = os.path.join(temp_dir, "pre_update.sh")
            if os.path.exists(pre_update_script):
                logger.info("Running pre-update script")
                os.chmod(pre_update_script, 0o755)  # Make executable
                
                result = subprocess.run(
                    [pre_update_script],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    logger.error(f"Pre-update script failed: {result.stderr}")
                    return False
            
            # Install files
            for file_info in manifest.get("files", []):
                src_path = os.path.join(temp_dir, file_info.get("path", ""))
                dst_path = file_info.get("install_path", "")
                
                if not src_path or not dst_path or not os.path.exists(src_path):
                    logger.warning(f"Skipping invalid file: {file_info}")
                    continue
                
                # Create destination directory if it doesn't exist
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                
                # Copy file
                logger.info(f"Installing file: {dst_path}")
                shutil.copy2(src_path, dst_path)
                
                # Set permissions if specified
                if "permissions" in file_info:
                    os.chmod(dst_path, int(file_info["permissions"], 8))
                
                # Set owner if specified
                if "owner" in file_info:
                    owner = file_info["owner"]
                    if ":" in owner:
                        user, group = owner.split(":", 1)
                        shutil.chown(dst_path, user, group)
            
            # Check for post-update script
            post_update_script = os.path.join(temp_dir, "post_update.sh")
            if os.path.exists(post_update_script):
                logger.info("Running post-update script")
                os.chmod(post_update_script, 0o755)  # Make executable
                
                result = subprocess.run(
                    [post_update_script],
                    cwd=temp_dir,
                    capture_output=True,
                    text=True
                )
                
                if result.returncode != 0:
                    logger.error(f"Post-update script failed: {result.stderr}")
                    # Continue anyway, as files are already installed
            
            # Update version
            self._set_current_version(version)
            
            # Clean up
            shutil.rmtree(temp_dir)
            
            logger.info(f"Firmware update to version {version} applied successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to apply firmware update: {str(e)}")
            return False
        finally:
            self._release_lock()
    
    def rollback_update(self) -> bool:
        """
        Rollback to previous firmware version.
        
        Returns:
            True if rollback successful, False otherwise
        """
        if not self._acquire_lock():
            return False
        
        try:
            logger.info("Rolling back firmware update")
            
            # Check if rollback is available
            rollback_file = "/etc/viztron/rollback_version"
            if not os.path.exists(rollback_file):
                logger.error("No rollback version available")
                return False
            
            # Read rollback version
            with open(rollback_file, 'r') as f:
                rollback_version = f.read().strip()
            
            # Check if rollback image exists
            rollback_image = os.path.join(self.download_dir, f"viztron-homebase-{rollback_version}.tar.gz")
            if not os.path.exists(rollback_image):
                logger.error(f"Rollback image not found: {rollback_image}")
                return False
            
            # Apply rollback image
            if not self.apply_update(rollback_image):
                logger.error("Failed to apply rollback image")
                return False
            
            logger.info(f"Rolled back to version {rollback_version}")
            return True
        except Exception as e:
            logger.error(f"Failed to rollback update: {str(e)}")
            return False
        finally:
            self._release_lock()
    
    def create_backup(self) -> Optional[str]:
        """
        Create backup of current system.
        
        Returns:
            Path to backup file if successful, None otherwise
        """
        if not self._acquire_lock():
            return None
        
        try:
            logger.info("Creating system backup")
            
            # Create backup filename
            backup_file = os.path.join(
                self.download_dir,
                f"viztron-backup-{self.current_version}-{int(time.time())}.tar.gz"
            )
            
            # Create temporary directory for backup
            temp_dir = os.path.join(self.download_dir, "backup-temp")
            os.makedirs(temp_dir, exist_ok=True)
            
            # Create manifest
            manifest = {
                "version": self.current_version,
                "backup_time": int(time.time()),
                "files": []
            }
            
            # Define files to backup
            backup_paths = [
                "/etc/viztron",
                "/opt/viztron/config",
                "/var/lib/viztron/data"
            ]
            
            # Create tar archive
            with tarfile.open(backup_file, 'w:gz') as tar:
                # Add manifest
                manifest_path = os.path.join(temp_dir, "manifest.json")
                with open(manifest_path, 'w') as f:
                    json.dump(manifest, f, indent=2)
                
                tar.add(manifest_path, arcname="manifest.json")
                
                # Add backup files
                for path in backup_paths:
                    if os.path.exists(path):
                        tar.add(path, arcname=os.path.basename(path))
                        manifest["files"].append({
                            "path": os.path.basename(path),
                            "source": path
                        })
            
            # Update manifest with final file list
            with open(manifest_path, 'w') as f:
                json.dump(manifest, f, indent=2)
            
            # Update tar archive with updated manifest
            with tarfile.open(backup_file, 'r:gz') as src, \
                 tarfile.open(backup_file + ".tmp", 'w:gz') as dst:
                
                # Add updated manifest
                dst.add(manifest_path, arcname="manifest.json")
                
                # Copy all other files
                for member in src.getmembers():
                    if member.name != "manifest.json":
                        dst.addfile(member, src.extractfile(member))
            
            # Replace original with updated archive
            os.replace(backup_file + ".tmp", backup_file)
            
            # Clean up
            shutil.rmtree(temp_dir)
            
            logger.info(f"System backup created: {backup_file}")
            return backup_file
        except Exception as e:
            logger.error(f"Failed to create system backup: {str(e)}")
            return None
        finally:
            self._release_lock()
    
    def restore_backup(self, backup_file: str) -> bool:
        """
        Restore system from backup.
        
        Args:
            backup_file: Path to backup file
            
        Returns:
            True if restore successful, False otherwise
        """
        if not self._acquire_lock():
            return False
        
        try:
            logger.info(f"Restoring system from backup: {backup_file}")
            
            # Check if file exists
            if not os.path.exists(backup_file):
                logger.error(f"Backup file not found: {backup_file}")
                return False
            
            # Create temporary directory for extraction
            temp_dir = os.path.join(self.download_dir, "restore-temp")
            os.makedirs(temp_dir, exist_ok=True)
            
            # Extract archive
            with tarfile.open(backup_file, 'r:gz') as tar:
                tar.extractall(path=temp_dir)
            
            # Load manifest
            manifest_path = os.path.join(temp_dir, "manifest.json")
            if not os.path.exists(manifest_path):
                logger.error("Invalid backup: missing manifest.json")
                shutil.rmtree(temp_dir)
                return False
            
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)
            
            # Restore files
            for file_info in manifest.get("files", []):
                src_path = os.path.join(temp_dir, file_info.get("path", ""))
                dst_path = file_info.get("source", "")
                
                if not src_path or not dst_path or not os.path.exists(src_path):
                    logger.warning(f"Skipping invalid file: {file_info}")
                    continue
                
                # Create destination directory if it doesn't exist
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                
                # Copy directory or file
                logger.info(f"Restoring: {dst_path}")
                if os.path.isdir(src_path):
                    # Remove existing directory if it exists
                    if os.path.exists(dst_path):
                        shutil.rmtree(dst_path)
                    
                    # Copy directory
                    shutil.copytree(src_path, dst_path)
                else:
                    # Copy file
                    shutil.copy2(src_path, dst_path)
            
            # Update version
            backup_version = manifest.get("version", "0.0.0")
            self._set_current_version(backup_version)
            
            # Clean up
            shutil.rmtree(temp_dir)
            
            logger.info(f"System restored from backup to version {backup_version}")
            return True
        except Exception as e:
            logger.error(f"Failed to restore system from backup: {str(e)}")
            return False
        finally:
            self._release_lock()


class UpdateManager:
    """
    Main update manager for the Viztron Homebase Module.
    
    This class coordinates package and firmware updates,
    providing a unified interface for update operations.
    """
    
    def __init__(self, config_path: str = "/etc/viztron/update_config.json"):
        """
        Initialize the update manager.
        
        Args:
            config_path: Path to the update configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        
        # Create required directories
        os.makedirs("/var/log/viztron", exist_ok=True)
        os.makedirs("/var/run/viztron", exist_ok=True)
        os.makedirs("/var/cache/viztron/firmware", exist_ok=True)
        
        # Initialize managers
        self.package_manager = PackageManager()
        self.firmware_manager = FirmwareManager()
        
        # Auto update settings
        self.auto_update_enabled = self.config.get("auto_update_enabled", False)
        self.auto_update_interval = self.config.get("auto_update_interval", 86400)  # 24 hours
        self.last_auto_update = self.config.get("last_auto_update", 0)
        
        # Auto update thread
        self.auto_update_thread = None
        self.auto_update_active = False
        
        # Create PID file
        self._create_pid_file()
        
        logger.info("Update manager initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load update configuration from file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                return {
                    "auto_update_enabled": False,
                    "auto_update_interval": 86400,
                    "last_auto_update": 0
                }
        except Exception as e:
            logger.error(f"Failed to load update config: {str(e)}")
            return {
                "auto_update_enabled": False,
                "auto_update_interval": 86400,
                "last_auto_update": 0
            }
    
    def _save_config(self):
        """Save update configuration to file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save update config: {str(e)}")
    
    def _create_pid_file(self):
        """Create PID file for the update manager."""
        try:
            pid = os.getpid()
            with open("/var/run/viztron/update_manager.pid", 'w') as f:
                f.write(str(pid))
            logger.debug(f"Created PID file with PID {pid}")
        except Exception as e:
            logger.error(f"Failed to create PID file: {str(e)}")
    
    def enable_auto_update(self, enabled: bool = True):
        """
        Enable or disable automatic updates.
        
        Args:
            enabled: Whether to enable automatic updates
        """
        logger.info(f"{'Enabling' if enabled else 'Disabling'} automatic updates")
        
        self.auto_update_enabled = enabled
        self.config["auto_update_enabled"] = enabled
        self._save_config()
        
        if enabled and not self.auto_update_active:
            self.start_auto_update()
        elif not enabled and self.auto_update_active:
            self.stop_auto_update()
    
    def set_auto_update_interval(self, interval: int):
        """
        Set automatic update interval.
        
        Args:
            interval: Update interval in seconds
        """
        logger.info(f"Setting automatic update interval to {interval} seconds")
        
        self.auto_update_interval = interval
        self.config["auto_update_interval"] = interval
        self._save_config()
    
    def start_auto_update(self):
        """Start the automatic update thread."""
        if not self.auto_update_active and self.auto_update_enabled:
            logger.info("Starting automatic update thread")
            self.auto_update_active = True
            self.auto_update_thread = threading.Thread(target=self._auto_update_loop)
            self.auto_update_thread.daemon = True
            self.auto_update_thread.start()
    
    def stop_auto_update(self):
        """Stop the automatic update thread."""
        if self.auto_update_active:
            logger.info("Stopping automatic update thread")
            self.auto_update_active = False
            if self.auto_update_thread:
                self.auto_update_thread.join(timeout=5.0)
    
    def _auto_update_loop(self):
        """Main automatic update loop that runs in a separate thread."""
        logger.info(f"Automatic update loop started with interval {self.auto_update_interval} seconds")
        
        while self.auto_update_active:
            try:
                # Check if update interval has elapsed
                if time.time() - self.last_auto_update >= self.auto_update_interval:
                    logger.info("Performing automatic update check")
                    
                    # Update last update time
                    self.last_auto_update = time.time()
                    self.config["last_auto_update"] = self.last_auto_update
                    self._save_config()
                    
                    # Check for package updates
                    self.package_manager.update_package_lists()
                    
                    # Check for firmware updates
                    update_info = self.firmware_manager.check_for_updates()
                    if update_info:
                        # Download and apply update
                        update_file = self.firmware_manager.download_update(update_info)
                        if update_file and self.firmware_manager.verify_update(update_file):
                            # Create backup before applying update
                            self.firmware_manager.create_backup()
                            
                            # Apply update
                            self.firmware_manager.apply_update(update_file)
                
                # Sleep for a while before checking again
                # Use shorter sleep intervals to allow for clean shutdown
                for _ in range(60):  # Check every minute if we should exit
                    if not self.auto_update_active:
                        break
                    time.sleep(60)
            except Exception as e:
                logger.error(f"Error in automatic update loop: {str(e)}")
                time.sleep(300)  # Sleep for 5 minutes before retrying
    
    def check_for_updates(self) -> Dict[str, Any]:
        """
        Check for all available updates.
        
        Returns:
            Dictionary containing update information
        """
        logger.info("Checking for all available updates")
        
        result = {
            "package_updates": False,
            "firmware_update": None
        }
        
        # Check for package updates
        try:
            self.package_manager.update_package_lists()
            
            # Check for upgradable packages
            apt_result = subprocess.run(
                ["apt-get", "upgrade", "--dry-run"],
                capture_output=True,
                text=True,
                check=True
            )
            
            if "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded." not in apt_result.stdout:
                result["package_updates"] = True
        except Exception as e:
            logger.error(f"Failed to check for package updates: {str(e)}")
        
        # Check for firmware updates
        try:
            update_info = self.firmware_manager.check_for_updates(force=True)
            result["firmware_update"] = update_info
        except Exception as e:
            logger.error(f"Failed to check for firmware updates: {str(e)}")
        
        return result
    
    def apply_all_updates(self) -> Dict[str, bool]:
        """
        Apply all available updates.
        
        Returns:
            Dictionary containing update results
        """
        logger.info("Applying all available updates")
        
        result = {
            "package_updates": False,
            "firmware_update": False
        }
        
        # Create backup before applying updates
        backup_file = self.firmware_manager.create_backup()
        if not backup_file:
            logger.warning("Failed to create backup before updates")
        
        # Apply package updates
        try:
            result["package_updates"] = self.package_manager.upgrade_all_packages()
        except Exception as e:
            logger.error(f"Failed to apply package updates: {str(e)}")
        
        # Apply firmware update
        try:
            update_info = self.firmware_manager.check_for_updates(force=True)
            if update_info:
                update_file = self.firmware_manager.download_update(update_info)
                if update_file and self.firmware_manager.verify_update(update_file):
                    result["firmware_update"] = self.firmware_manager.apply_update(update_file)
        except Exception as e:
            logger.error(f"Failed to apply firmware update: {str(e)}")
        
        return result
    
    def shutdown(self):
        """Perform a graceful shutdown of the update manager."""
        logger.info("Shutting down update manager")
        
        # Stop auto update thread
        self.stop_auto_update()
        
        # Remove PID file
        if os.path.exists("/var/run/viztron/update_manager.pid"):
            os.remove("/var/run/viztron/update_manager.pid")
        
        logger.info("Update manager shutdown complete")


# Example usage
if __name__ == "__main__":
    # Create update manager
    update_manager = UpdateManager()
    
    try:
        # Enable automatic updates
        update_manager.enable_auto_update(True)
        
        # Check for updates
        updates = update_manager.check_for_updates()
        print("Update check results:")
        print(f"  Package updates available: {updates['package_updates']}")
        if updates['firmware_update']:
            print(f"  Firmware update available: {updates['firmware_update']['version']}")
        else:
            print("  No firmware updates available")
        
        # Run for a while
        print("\nUpdate manager running. Press Ctrl+C to exit.")
        
        # Main loop
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        # Shutdown
        update_manager.shutdown()
