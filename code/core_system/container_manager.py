#!/usr/bin/env python3
"""
Container Manager for Viztron Homebase Module

This module implements the container management functionality for the
Viztron Homebase Module, handling Docker and LXC containers for the
microservices architecture.

Author: Viztron System Team
Date: April 20, 2025
"""

import os
import sys
import time
import logging
import json
import subprocess
import docker
import lxc
from typing import Dict, List, Any, Optional, Tuple
import yaml
import threading
import socket

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/viztron/container_manager.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('container_manager')

class DockerManager:
    """
    Manages Docker containers for application services.
    
    This class provides methods to create, start, stop, and monitor
    Docker containers for the Viztron Homebase Module.
    """
    
    def __init__(self, config_path: str = "/etc/viztron/docker_config.json"):
        """
        Initialize the Docker manager.
        
        Args:
            config_path: Path to the Docker configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        
        # Initialize Docker client
        try:
            self.client = docker.from_env()
            logger.info("Docker client initialized")
        except Exception as e:
            logger.error(f"Failed to initialize Docker client: {str(e)}")
            self.client = None
        
        # Container definitions
        self.container_defs = self.config.get("containers", {})
        
        # Active containers
        self.active_containers = {}
        
        # Container health check thread
        self.health_check_interval = self.config.get("health_check_interval", 60)  # seconds
        self.health_check_thread = None
        self.health_check_active = False
        
        logger.info("Docker manager initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load Docker configuration from file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                return {"containers": {}}
        except Exception as e:
            logger.error(f"Failed to load Docker config: {str(e)}")
            return {"containers": {}}
    
    def is_docker_available(self) -> bool:
        """Check if Docker is available and running."""
        if not self.client:
            return False
        
        try:
            self.client.ping()
            return True
        except Exception as e:
            logger.error(f"Docker is not available: {str(e)}")
            return False
    
    def list_containers(self) -> List[Dict[str, Any]]:
        """
        List all Docker containers managed by Viztron.
        
        Returns:
            List of container information dictionaries
        """
        if not self.is_docker_available():
            return []
        
        try:
            containers = self.client.containers.list(all=True)
            
            result = []
            for container in containers:
                # Check if this is a Viztron container
                if "viztron.service" in container.labels:
                    result.append({
                        "id": container.id,
                        "name": container.name,
                        "image": container.image.tags[0] if container.image.tags else container.image.id,
                        "status": container.status,
                        "service": container.labels.get("viztron.service", "unknown"),
                        "created": container.attrs["Created"],
                        "ports": container.ports
                    })
            
            return result
        except Exception as e:
            logger.error(f"Failed to list containers: {str(e)}")
            return []
    
    def get_container_status(self, container_name: str) -> Dict[str, Any]:
        """
        Get status of a specific container.
        
        Args:
            container_name: Name of the container
            
        Returns:
            Container status dictionary
        """
        if not self.is_docker_available():
            return {"status": "unknown", "error": "Docker not available"}
        
        try:
            container = self.client.containers.get(container_name)
            
            # Get container stats
            stats = container.stats(stream=False)
            
            # Calculate CPU usage
            cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - stats["precpu_stats"]["cpu_usage"]["total_usage"]
            system_delta = stats["cpu_stats"]["system_cpu_usage"] - stats["precpu_stats"]["system_cpu_usage"]
            cpu_usage = (cpu_delta / system_delta) * 100.0 if system_delta > 0 else 0.0
            
            # Calculate memory usage
            memory_usage = stats["memory_stats"]["usage"] / (1024 * 1024)  # MB
            memory_limit = stats["memory_stats"]["limit"] / (1024 * 1024)  # MB
            memory_percent = (memory_usage / memory_limit) * 100.0 if memory_limit > 0 else 0.0
            
            return {
                "id": container.id,
                "name": container.name,
                "image": container.image.tags[0] if container.image.tags else container.image.id,
                "status": container.status,
                "service": container.labels.get("viztron.service", "unknown"),
                "created": container.attrs["Created"],
                "ports": container.ports,
                "cpu_usage": cpu_usage,
                "memory_usage": memory_usage,
                "memory_percent": memory_percent,
                "restarts": container.attrs["RestartCount"] if "RestartCount" in container.attrs else 0
            }
        except docker.errors.NotFound:
            return {"status": "not_found", "error": f"Container {container_name} not found"}
        except Exception as e:
            logger.error(f"Failed to get container status for {container_name}: {str(e)}")
            return {"status": "error", "error": str(e)}
    
    def create_container(self, service_name: str) -> bool:
        """
        Create a Docker container for a service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_docker_available():
            return False
        
        # Check if service definition exists
        if service_name not in self.container_defs:
            logger.error(f"Service definition for {service_name} not found")
            return False
        
        # Get service definition
        service_def = self.container_defs[service_name]
        
        # Check if container already exists
        container_name = service_def.get("container_name", f"viztron-{service_name}")
        try:
            existing = self.client.containers.get(container_name)
            logger.warning(f"Container {container_name} already exists, removing it")
            existing.remove(force=True)
        except docker.errors.NotFound:
            pass  # Container doesn't exist, which is what we want
        except Exception as e:
            logger.error(f"Failed to remove existing container {container_name}: {str(e)}")
            return False
        
        try:
            # Pull image if needed
            image = service_def.get("image")
            if not image:
                logger.error(f"No image specified for service {service_name}")
                return False
            
            logger.info(f"Pulling image {image} for service {service_name}")
            self.client.images.pull(image)
            
            # Prepare container configuration
            container_config = {
                "name": container_name,
                "image": image,
                "detach": True,
                "restart_policy": {"Name": service_def.get("restart_policy", "unless-stopped")},
                "labels": {
                    "viztron.service": service_name,
                    "viztron.managed": "true"
                }
            }
            
            # Add environment variables
            if "environment" in service_def:
                container_config["environment"] = service_def["environment"]
            
            # Add ports
            if "ports" in service_def:
                container_config["ports"] = service_def["ports"]
            
            # Add volumes
            if "volumes" in service_def:
                container_config["volumes"] = service_def["volumes"]
            
            # Add network
            if "network" in service_def:
                container_config["network"] = service_def["network"]
            
            # Add resource limits
            if "resources" in service_def:
                resources = service_def["resources"]
                container_config["mem_limit"] = resources.get("memory_limit", "512m")
                container_config["mem_reservation"] = resources.get("memory_reservation", "256m")
                container_config["cpu_period"] = resources.get("cpu_period", 100000)
                container_config["cpu_quota"] = resources.get("cpu_quota", 50000)  # 50% of CPU
            
            # Create container
            logger.info(f"Creating container for service {service_name}")
            container = self.client.containers.create(**container_config)
            
            # Store in active containers
            self.active_containers[service_name] = container.id
            
            logger.info(f"Container {container_name} created for service {service_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create container for service {service_name}: {str(e)}")
            return False
    
    def start_container(self, service_name: str) -> bool:
        """
        Start a Docker container for a service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_docker_available():
            return False
        
        # Check if service definition exists
        if service_name not in self.container_defs:
            logger.error(f"Service definition for {service_name} not found")
            return False
        
        # Get container name
        container_name = self.container_defs[service_name].get("container_name", f"viztron-{service_name}")
        
        try:
            # Get container
            container = self.client.containers.get(container_name)
            
            # Start container
            logger.info(f"Starting container {container_name} for service {service_name}")
            container.start()
            
            # Wait for container to be running
            for _ in range(10):  # Wait up to 10 seconds
                container.reload()
                if container.status == "running":
                    logger.info(f"Container {container_name} started successfully")
                    return True
                time.sleep(1)
            
            logger.warning(f"Container {container_name} started but not running after 10 seconds")
            return False
        except docker.errors.NotFound:
            logger.error(f"Container {container_name} not found, creating it first")
            if self.create_container(service_name):
                return self.start_container(service_name)
            return False
        except Exception as e:
            logger.error(f"Failed to start container for service {service_name}: {str(e)}")
            return False
    
    def stop_container(self, service_name: str, timeout: int = 10) -> bool:
        """
        Stop a Docker container for a service.
        
        Args:
            service_name: Name of the service
            timeout: Timeout in seconds before killing the container
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_docker_available():
            return False
        
        # Check if service definition exists
        if service_name not in self.container_defs:
            logger.error(f"Service definition for {service_name} not found")
            return False
        
        # Get container name
        container_name = self.container_defs[service_name].get("container_name", f"viztron-{service_name}")
        
        try:
            # Get container
            container = self.client.containers.get(container_name)
            
            # Stop container
            logger.info(f"Stopping container {container_name} for service {service_name}")
            container.stop(timeout=timeout)
            
            # Wait for container to be stopped
            for _ in range(timeout + 5):  # Wait a bit longer than the timeout
                container.reload()
                if container.status == "exited":
                    logger.info(f"Container {container_name} stopped successfully")
                    return True
                time.sleep(1)
            
            logger.warning(f"Container {container_name} not stopped after {timeout} seconds, forcing")
            container.kill()
            return True
        except docker.errors.NotFound:
            logger.warning(f"Container {container_name} not found, nothing to stop")
            return True
        except Exception as e:
            logger.error(f"Failed to stop container for service {service_name}: {str(e)}")
            return False
    
    def restart_container(self, service_name: str, timeout: int = 10) -> bool:
        """
        Restart a Docker container for a service.
        
        Args:
            service_name: Name of the service
            timeout: Timeout in seconds before killing the container
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_docker_available():
            return False
        
        # Check if service definition exists
        if service_name not in self.container_defs:
            logger.error(f"Service definition for {service_name} not found")
            return False
        
        # Get container name
        container_name = self.container_defs[service_name].get("container_name", f"viztron-{service_name}")
        
        try:
            # Get container
            container = self.client.containers.get(container_name)
            
            # Restart container
            logger.info(f"Restarting container {container_name} for service {service_name}")
            container.restart(timeout=timeout)
            
            # Wait for container to be running
            for _ in range(10):  # Wait up to 10 seconds
                container.reload()
                if container.status == "running":
                    logger.info(f"Container {container_name} restarted successfully")
                    return True
                time.sleep(1)
            
            logger.warning(f"Container {container_name} restarted but not running after 10 seconds")
            return False
        except docker.errors.NotFound:
            logger.error(f"Container {container_name} not found, creating and starting it")
            if self.create_container(service_name):
                return self.start_container(service_name)
            return False
        except Exception as e:
            logger.error(f"Failed to restart container for service {service_name}: {str(e)}")
            return False
    
    def remove_container(self, service_name: str, force: bool = False) -> bool:
        """
        Remove a Docker container for a service.
        
        Args:
            service_name: Name of the service
            force: Whether to force removal of a running container
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_docker_available():
            return False
        
        # Check if service definition exists
        if service_name not in self.container_defs:
            logger.error(f"Service definition for {service_name} not found")
            return False
        
        # Get container name
        container_name = self.container_defs[service_name].get("container_name", f"viztron-{service_name}")
        
        try:
            # Get container
            container = self.client.containers.get(container_name)
            
            # Remove container
            logger.info(f"Removing container {container_name} for service {service_name}")
            container.remove(force=force)
            
            # Remove from active containers
            if service_name in self.active_containers:
                del self.active_containers[service_name]
            
            logger.info(f"Container {container_name} removed successfully")
            return True
        except docker.errors.NotFound:
            logger.warning(f"Container {container_name} not found, nothing to remove")
            return True
        except Exception as e:
            logger.error(f"Failed to remove container for service {service_name}: {str(e)}")
            return False
    
    def start_health_check(self):
        """Start the container health check thread."""
        if not self.health_check_active:
            logger.info("Starting container health check")
            self.health_check_active = True
            self.health_check_thread = threading.Thread(target=self._health_check_loop)
            self.health_check_thread.daemon = True
            self.health_check_thread.start()
    
    def stop_health_check(self):
        """Stop the container health check thread."""
        if self.health_check_active:
            logger.info("Stopping container health check")
            self.health_check_active = False
            if self.health_check_thread:
                self.health_check_thread.join(timeout=5.0)
    
    def _health_check_loop(self):
        """Main health check loop that runs in a separate thread."""
        logger.info(f"Health check loop started with interval {self.health_check_interval} seconds")
        
        while self.health_check_active:
            try:
                # Check all active containers
                for service_name, container_id in list(self.active_containers.items()):
                    try:
                        # Get container
                        container = self.client.containers.get(container_id)
                        
                        # Check container status
                        container.reload()
                        if container.status != "running":
                            logger.warning(f"Container for service {service_name} is not running (status: {container.status})")
                            
                            # Restart container if it should be running
                            if self.container_defs.get(service_name, {}).get("auto_restart", True):
                                logger.info(f"Auto-restarting container for service {service_name}")
                                self.restart_container(service_name)
                        else:
                            # Container is running, check health if available
                            if "Health" in container.attrs["State"]:
                                health_status = container.attrs["State"]["Health"]["Status"]
                                if health_status != "healthy":
                                    logger.warning(f"Container for service {service_name} is not healthy (health: {health_status})")
                                    
                                    # Restart container if it should be healthy
                                    if self.container_defs.get(service_name, {}).get("auto_restart", True):
                                        logger.info(f"Auto-restarting unhealthy container for service {service_name}")
                                        self.restart_container(service_name)
                    except docker.errors.NotFound:
                        logger.warning(f"Container {container_id} for service {service_name} not found")
                        
                        # Remove from active containers
                        if service_name in self.active_containers:
                            del self.active_containers[service_name]
                        
                        # Recreate container if it should be running
                        if self.container_defs.get(service_name, {}).get("auto_restart", True):
                            logger.info(f"Auto-creating container for service {service_name}")
                            if self.create_container(service_name):
                                self.start_container(service_name)
                    except Exception as e:
                        logger.error(f"Error checking container for service {service_name}: {str(e)}")
                
                # Sleep for the health check interval
                time.sleep(self.health_check_interval)
            except Exception as e:
                logger.error(f"Error in health check loop: {str(e)}")
                time.sleep(5.0)  # Sleep briefly before retrying


class LXCManager:
    """
    Manages LXC containers for system services.
    
    This class provides methods to create, start, stop, and monitor
    LXC containers for the Viztron Homebase Module.
    """
    
    def __init__(self, config_path: str = "/etc/viztron/lxc_config.json"):
        """
        Initialize the LXC manager.
        
        Args:
            config_path: Path to the LXC configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        
        # Container definitions
        self.container_defs = self.config.get("containers", {})
        
        # Active containers
        self.active_containers = {}
        
        # Container health check thread
        self.health_check_interval = self.config.get("health_check_interval", 60)  # seconds
        self.health_check_thread = None
        self.health_check_active = False
        
        logger.info("LXC manager initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load LXC configuration from file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                return {"containers": {}}
        except Exception as e:
            logger.error(f"Failed to load LXC config: {str(e)}")
            return {"containers": {}}
    
    def is_lxc_available(self) -> bool:
        """Check if LXC is available and running."""
        try:
            # Check if lxc-ls command is available
            result = subprocess.run(["lxc-ls", "--version"], capture_output=True, text=True, check=True)
            logger.debug(f"LXC version: {result.stdout.strip()}")
            return True
        except Exception as e:
            logger.error(f"LXC is not available: {str(e)}")
            return False
    
    def list_containers(self) -> List[Dict[str, Any]]:
        """
        List all LXC containers managed by Viztron.
        
        Returns:
            List of container information dictionaries
        """
        if not self.is_lxc_available():
            return []
        
        try:
            # Get list of containers
            result = subprocess.run(["lxc-ls", "-f"], capture_output=True, text=True, check=True)
            
            # Parse output
            lines = result.stdout.strip().split("\n")
            if len(lines) < 2:
                return []
            
            # Skip header line
            lines = lines[1:]
            
            containers = []
            for line in lines:
                parts = line.split()
                if len(parts) >= 3:
                    name = parts[0]
                    state = parts[1]
                    
                    # Check if this is a Viztron container
                    if name.startswith("viztron-"):
                        service_name = name[8:]  # Remove "viztron-" prefix
                        
                        containers.append({
                            "name": name,
                            "state": state,
                            "service": service_name
                        })
            
            return containers
        except Exception as e:
            logger.error(f"Failed to list LXC containers: {str(e)}")
            return []
    
    def get_container_status(self, container_name: str) -> Dict[str, Any]:
        """
        Get status of a specific container.
        
        Args:
            container_name: Name of the container
            
        Returns:
            Container status dictionary
        """
        if not self.is_lxc_available():
            return {"state": "unknown", "error": "LXC not available"}
        
        try:
            # Get container info
            result = subprocess.run(["lxc-info", "-n", container_name], capture_output=True, text=True, check=True)
            
            # Parse output
            lines = result.stdout.strip().split("\n")
            
            status = {}
            for line in lines:
                if ":" in line:
                    key, value = line.split(":", 1)
                    status[key.strip().lower()] = value.strip()
            
            # Add service name if this is a Viztron container
            if container_name.startswith("viztron-"):
                service_name = container_name[8:]  # Remove "viztron-" prefix
                status["service"] = service_name
            
            return status
        except subprocess.CalledProcessError:
            return {"state": "not_found", "error": f"Container {container_name} not found"}
        except Exception as e:
            logger.error(f"Failed to get LXC container status for {container_name}: {str(e)}")
            return {"state": "error", "error": str(e)}
    
    def create_container(self, service_name: str) -> bool:
        """
        Create an LXC container for a service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_lxc_available():
            return False
        
        # Check if service definition exists
        if service_name not in self.container_defs:
            logger.error(f"Service definition for {service_name} not found")
            return False
        
        # Get service definition
        service_def = self.container_defs[service_name]
        
        # Get container name
        container_name = service_def.get("container_name", f"viztron-{service_name}")
        
        try:
            # Check if container already exists
            result = subprocess.run(["lxc-ls"], capture_output=True, text=True, check=True)
            if container_name in result.stdout.split():
                logger.warning(f"Container {container_name} already exists, destroying it")
                subprocess.run(["lxc-destroy", "-f", "-n", container_name], check=True)
            
            # Create container
            logger.info(f"Creating LXC container {container_name} for service {service_name}")
            
            # Get template
            template = service_def.get("template", "ubuntu")
            
            # Get template options
            template_options = service_def.get("template_options", "")
            
            # Create container
            create_cmd = ["lxc-create", "-t", template, "-n", container_name]
            if template_options:
                create_cmd.extend(["--", *template_options.split()])
            
            subprocess.run(create_cmd, check=True)
            
            # Configure container
            config_path = f"/var/lib/lxc/{container_name}/config"
            
            # Add network configuration
            if "network" in service_def:
                network = service_def["network"]
                with open(config_path, 'a') as f:
                    f.write(f"\n# Network configuration\n")
                    f.write(f"lxc.net.0.type = {network.get('type', 'veth')}\n")
                    f.write(f"lxc.net.0.link = {network.get('link', 'lxcbr0')}\n")
                    f.write(f"lxc.net.0.flags = {network.get('flags', 'up')}\n")
                    if "ipv4" in network:
                        f.write(f"lxc.net.0.ipv4.address = {network['ipv4']}\n")
                    if "ipv4_gateway" in network:
                        f.write(f"lxc.net.0.ipv4.gateway = {network['ipv4_gateway']}\n")
            
            # Add resource limits
            if "resources" in service_def:
                resources = service_def["resources"]
                with open(config_path, 'a') as f:
                    f.write(f"\n# Resource limits\n")
                    if "cpu_shares" in resources:
                        f.write(f"lxc.cgroup.cpu.shares = {resources['cpu_shares']}\n")
                    if "memory_limit" in resources:
                        f.write(f"lxc.cgroup.memory.limit_in_bytes = {resources['memory_limit']}\n")
                    if "cpuset_cpus" in resources:
                        f.write(f"lxc.cgroup.cpuset.cpus = {resources['cpuset_cpus']}\n")
            
            # Add autostart
            if service_def.get("autostart", True):
                with open(config_path, 'a') as f:
                    f.write(f"\n# Autostart\n")
                    f.write(f"lxc.start.auto = 1\n")
                    f.write(f"lxc.start.delay = {service_def.get('autostart_delay', 0)}\n")
            
            # Store in active containers
            self.active_containers[service_name] = container_name
            
            logger.info(f"LXC container {container_name} created for service {service_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create LXC container for service {service_name}: {str(e)}")
            return False
    
    def start_container(self, service_name: str) -> bool:
        """
        Start an LXC container for a service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_lxc_available():
            return False
        
        # Check if service definition exists
        if service_name not in self.container_defs:
            logger.error(f"Service definition for {service_name} not found")
            return False
        
        # Get container name
        container_name = self.container_defs[service_name].get("container_name", f"viztron-{service_name}")
        
        try:
            # Check if container exists
            result = subprocess.run(["lxc-ls"], capture_output=True, text=True, check=True)
            if container_name not in result.stdout.split():
                logger.error(f"Container {container_name} not found, creating it first")
                if not self.create_container(service_name):
                    return False
            
            # Start container
            logger.info(f"Starting LXC container {container_name} for service {service_name}")
            subprocess.run(["lxc-start", "-n", container_name], check=True)
            
            # Wait for container to be running
            for _ in range(10):  # Wait up to 10 seconds
                status = self.get_container_status(container_name)
                if status.get("state") == "RUNNING":
                    logger.info(f"LXC container {container_name} started successfully")
                    return True
                time.sleep(1)
            
            logger.warning(f"LXC container {container_name} started but not running after 10 seconds")
            return False
        except Exception as e:
            logger.error(f"Failed to start LXC container for service {service_name}: {str(e)}")
            return False
    
    def stop_container(self, service_name: str, timeout: int = 30) -> bool:
        """
        Stop an LXC container for a service.
        
        Args:
            service_name: Name of the service
            timeout: Timeout in seconds before killing the container
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_lxc_available():
            return False
        
        # Check if service definition exists
        if service_name not in self.container_defs:
            logger.error(f"Service definition for {service_name} not found")
            return False
        
        # Get container name
        container_name = self.container_defs[service_name].get("container_name", f"viztron-{service_name}")
        
        try:
            # Check if container exists and is running
            status = self.get_container_status(container_name)
            if status.get("state") != "RUNNING":
                logger.warning(f"LXC container {container_name} is not running, nothing to stop")
                return True
            
            # Stop container
            logger.info(f"Stopping LXC container {container_name} for service {service_name}")
            subprocess.run(["lxc-stop", "-t", str(timeout), "-n", container_name], check=True)
            
            # Wait for container to be stopped
            for _ in range(timeout + 5):  # Wait a bit longer than the timeout
                status = self.get_container_status(container_name)
                if status.get("state") == "STOPPED":
                    logger.info(f"LXC container {container_name} stopped successfully")
                    return True
                time.sleep(1)
            
            logger.warning(f"LXC container {container_name} not stopped after {timeout} seconds, forcing")
            subprocess.run(["lxc-stop", "-k", "-n", container_name], check=True)
            return True
        except Exception as e:
            logger.error(f"Failed to stop LXC container for service {service_name}: {str(e)}")
            return False
    
    def restart_container(self, service_name: str, timeout: int = 30) -> bool:
        """
        Restart an LXC container for a service.
        
        Args:
            service_name: Name of the service
            timeout: Timeout in seconds before killing the container
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_lxc_available():
            return False
        
        # Check if service definition exists
        if service_name not in self.container_defs:
            logger.error(f"Service definition for {service_name} not found")
            return False
        
        # Get container name
        container_name = self.container_defs[service_name].get("container_name", f"viztron-{service_name}")
        
        try:
            # Check if container exists
            result = subprocess.run(["lxc-ls"], capture_output=True, text=True, check=True)
            if container_name not in result.stdout.split():
                logger.error(f"Container {container_name} not found, creating and starting it")
                if self.create_container(service_name):
                    return self.start_container(service_name)
                return False
            
            # Restart container
            logger.info(f"Restarting LXC container {container_name} for service {service_name}")
            
            # Stop container first
            if not self.stop_container(service_name, timeout):
                logger.warning(f"Failed to stop LXC container {container_name}, trying to start anyway")
            
            # Start container
            return self.start_container(service_name)
        except Exception as e:
            logger.error(f"Failed to restart LXC container for service {service_name}: {str(e)}")
            return False
    
    def remove_container(self, service_name: str, force: bool = False) -> bool:
        """
        Remove an LXC container for a service.
        
        Args:
            service_name: Name of the service
            force: Whether to force removal of a running container
            
        Returns:
            True if successful, False otherwise
        """
        if not self.is_lxc_available():
            return False
        
        # Check if service definition exists
        if service_name not in self.container_defs:
            logger.error(f"Service definition for {service_name} not found")
            return False
        
        # Get container name
        container_name = self.container_defs[service_name].get("container_name", f"viztron-{service_name}")
        
        try:
            # Check if container exists
            result = subprocess.run(["lxc-ls"], capture_output=True, text=True, check=True)
            if container_name not in result.stdout.split():
                logger.warning(f"LXC container {container_name} not found, nothing to remove")
                return True
            
            # Stop container if it's running and force is True
            status = self.get_container_status(container_name)
            if status.get("state") == "RUNNING":
                if force:
                    logger.info(f"Stopping LXC container {container_name} before removal")
                    if not self.stop_container(service_name):
                        logger.warning(f"Failed to stop LXC container {container_name}, forcing removal")
                else:
                    logger.error(f"LXC container {container_name} is running, cannot remove without force")
                    return False
            
            # Remove container
            logger.info(f"Removing LXC container {container_name} for service {service_name}")
            subprocess.run(["lxc-destroy", "-n", container_name], check=True)
            
            # Remove from active containers
            if service_name in self.active_containers:
                del self.active_containers[service_name]
            
            logger.info(f"LXC container {container_name} removed successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to remove LXC container for service {service_name}: {str(e)}")
            return False
    
    def start_health_check(self):
        """Start the container health check thread."""
        if not self.health_check_active:
            logger.info("Starting LXC container health check")
            self.health_check_active = True
            self.health_check_thread = threading.Thread(target=self._health_check_loop)
            self.health_check_thread.daemon = True
            self.health_check_thread.start()
    
    def stop_health_check(self):
        """Stop the container health check thread."""
        if self.health_check_active:
            logger.info("Stopping LXC container health check")
            self.health_check_active = False
            if self.health_check_thread:
                self.health_check_thread.join(timeout=5.0)
    
    def _health_check_loop(self):
        """Main health check loop that runs in a separate thread."""
        logger.info(f"LXC health check loop started with interval {self.health_check_interval} seconds")
        
        while self.health_check_active:
            try:
                # Check all active containers
                for service_name, container_name in list(self.active_containers.items()):
                    try:
                        # Get container status
                        status = self.get_container_status(container_name)
                        
                        # Check if container is running
                        if status.get("state") != "RUNNING":
                            logger.warning(f"LXC container {container_name} for service {service_name} is not running (state: {status.get('state')})")
                            
                            # Restart container if it should be running
                            if self.container_defs.get(service_name, {}).get("auto_restart", True):
                                logger.info(f"Auto-restarting LXC container for service {service_name}")
                                self.restart_container(service_name)
                    except Exception as e:
                        logger.error(f"Error checking LXC container for service {service_name}: {str(e)}")
                
                # Sleep for the health check interval
                time.sleep(self.health_check_interval)
            except Exception as e:
                logger.error(f"Error in LXC health check loop: {str(e)}")
                time.sleep(5.0)  # Sleep briefly before retrying


class ContainerManager:
    """
    Main container manager for the Viztron Homebase Module.
    
    This class coordinates Docker and LXC container management,
    providing a unified interface for container operations.
    """
    
    def __init__(self, config_path: str = "/etc/viztron/container_config.json"):
        """
        Initialize the container manager.
        
        Args:
            config_path: Path to the container configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        
        # Create required directories
        os.makedirs("/var/log/viztron", exist_ok=True)
        os.makedirs("/var/run/viztron", exist_ok=True)
        
        # Initialize managers
        self.docker_manager = DockerManager()
        self.lxc_manager = LXCManager()
        
        # Service definitions
        self.service_defs = self.config.get("services", {})
        
        # Create PID file
        self._create_pid_file()
        
        logger.info("Container manager initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load container configuration from file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                return {"services": {}}
        except Exception as e:
            logger.error(f"Failed to load container config: {str(e)}")
            return {"services": {}}
    
    def _create_pid_file(self):
        """Create PID file for the container manager."""
        try:
            pid = os.getpid()
            with open("/var/run/viztron/container_manager.pid", 'w') as f:
                f.write(str(pid))
            logger.debug(f"Created PID file with PID {pid}")
        except Exception as e:
            logger.error(f"Failed to create PID file: {str(e)}")
    
    def list_services(self) -> List[Dict[str, Any]]:
        """
        List all services managed by the container manager.
        
        Returns:
            List of service information dictionaries
        """
        services = []
        
        # Get Docker containers
        docker_containers = self.docker_manager.list_containers()
        
        # Get LXC containers
        lxc_containers = self.lxc_manager.list_containers()
        
        # Create service list
        for service_name, service_def in self.service_defs.items():
            container_type = service_def.get("container_type", "docker")
            container_name = service_def.get("container_name", f"viztron-{service_name}")
            
            # Find container status
            status = "unknown"
            container_info = {}
            
            if container_type == "docker":
                for container in docker_containers:
                    if container["name"] == container_name:
                        status = container["status"]
                        container_info = container
                        break
            elif container_type == "lxc":
                for container in lxc_containers:
                    if container["name"] == container_name:
                        status = container["state"]
                        container_info = container
                        break
            
            services.append({
                "name": service_name,
                "container_type": container_type,
                "container_name": container_name,
                "status": status,
                "container_info": container_info,
                "service_def": service_def
            })
        
        return services
    
    def get_service_status(self, service_name: str) -> Dict[str, Any]:
        """
        Get status of a specific service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            Service status dictionary
        """
        # Check if service definition exists
        if service_name not in self.service_defs:
            return {"status": "unknown", "error": f"Service {service_name} not found"}
        
        # Get service definition
        service_def = self.service_defs[service_name]
        container_type = service_def.get("container_type", "docker")
        container_name = service_def.get("container_name", f"viztron-{service_name}")
        
        # Get container status
        if container_type == "docker":
            container_status = self.docker_manager.get_container_status(container_name)
        elif container_type == "lxc":
            container_status = self.lxc_manager.get_container_status(container_name)
        else:
            return {"status": "unknown", "error": f"Unknown container type: {container_type}"}
        
        # Combine with service definition
        return {
            "name": service_name,
            "container_type": container_type,
            "container_name": container_name,
            "container_status": container_status,
            "service_def": service_def
        }
    
    def start_service(self, service_name: str) -> bool:
        """
        Start a service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            True if successful, False otherwise
        """
        # Check if service definition exists
        if service_name not in self.service_defs:
            logger.error(f"Service {service_name} not found")
            return False
        
        # Get service definition
        service_def = self.service_defs[service_name]
        container_type = service_def.get("container_type", "docker")
        
        # Start container
        if container_type == "docker":
            return self.docker_manager.start_container(service_name)
        elif container_type == "lxc":
            return self.lxc_manager.start_container(service_name)
        else:
            logger.error(f"Unknown container type: {container_type}")
            return False
    
    def stop_service(self, service_name: str, timeout: int = 30) -> bool:
        """
        Stop a service.
        
        Args:
            service_name: Name of the service
            timeout: Timeout in seconds before killing the container
            
        Returns:
            True if successful, False otherwise
        """
        # Check if service definition exists
        if service_name not in self.service_defs:
            logger.error(f"Service {service_name} not found")
            return False
        
        # Get service definition
        service_def = self.service_defs[service_name]
        container_type = service_def.get("container_type", "docker")
        
        # Stop container
        if container_type == "docker":
            return self.docker_manager.stop_container(service_name, timeout)
        elif container_type == "lxc":
            return self.lxc_manager.stop_container(service_name, timeout)
        else:
            logger.error(f"Unknown container type: {container_type}")
            return False
    
    def restart_service(self, service_name: str, timeout: int = 30) -> bool:
        """
        Restart a service.
        
        Args:
            service_name: Name of the service
            timeout: Timeout in seconds before killing the container
            
        Returns:
            True if successful, False otherwise
        """
        # Check if service definition exists
        if service_name not in self.service_defs:
            logger.error(f"Service {service_name} not found")
            return False
        
        # Get service definition
        service_def = self.service_defs[service_name]
        container_type = service_def.get("container_type", "docker")
        
        # Restart container
        if container_type == "docker":
            return self.docker_manager.restart_container(service_name, timeout)
        elif container_type == "lxc":
            return self.lxc_manager.restart_container(service_name, timeout)
        else:
            logger.error(f"Unknown container type: {container_type}")
            return False
    
    def remove_service(self, service_name: str, force: bool = False) -> bool:
        """
        Remove a service.
        
        Args:
            service_name: Name of the service
            force: Whether to force removal of a running container
            
        Returns:
            True if successful, False otherwise
        """
        # Check if service definition exists
        if service_name not in self.service_defs:
            logger.error(f"Service {service_name} not found")
            return False
        
        # Get service definition
        service_def = self.service_defs[service_name]
        container_type = service_def.get("container_type", "docker")
        
        # Remove container
        if container_type == "docker":
            return self.docker_manager.remove_container(service_name, force)
        elif container_type == "lxc":
            return self.lxc_manager.remove_container(service_name, force)
        else:
            logger.error(f"Unknown container type: {container_type}")
            return False
    
    def start_all_services(self) -> Dict[str, bool]:
        """
        Start all services.
        
        Returns:
            Dictionary mapping service names to success status
        """
        results = {}
        
        # Start services in dependency order
        for service_name in self._get_service_start_order():
            logger.info(f"Starting service {service_name}")
            results[service_name] = self.start_service(service_name)
        
        return results
    
    def stop_all_services(self, timeout: int = 30) -> Dict[str, bool]:
        """
        Stop all services.
        
        Args:
            timeout: Timeout in seconds before killing containers
            
        Returns:
            Dictionary mapping service names to success status
        """
        results = {}
        
        # Stop services in reverse dependency order
        for service_name in reversed(self._get_service_start_order()):
            logger.info(f"Stopping service {service_name}")
            results[service_name] = self.stop_service(service_name, timeout)
        
        return results
    
    def _get_service_start_order(self) -> List[str]:
        """
        Get services in dependency order for starting.
        
        Returns:
            List of service names in order
        """
        # Build dependency graph
        graph = {}
        for service_name, service_def in self.service_defs.items():
            dependencies = service_def.get("depends_on", [])
            graph[service_name] = dependencies
        
        # Topological sort
        visited = set()
        temp_visited = set()
        order = []
        
        def visit(node):
            if node in temp_visited:
                raise ValueError(f"Circular dependency detected: {node}")
            if node in visited:
                return
            
            temp_visited.add(node)
            
            for dependency in graph.get(node, []):
                visit(dependency)
            
            temp_visited.remove(node)
            visited.add(node)
            order.append(node)
        
        # Visit all nodes
        for service_name in graph:
            if service_name not in visited:
                visit(service_name)
        
        return order
    
    def start_health_checks(self):
        """Start health checks for all container types."""
        logger.info("Starting container health checks")
        self.docker_manager.start_health_check()
        self.lxc_manager.start_health_check()
    
    def stop_health_checks(self):
        """Stop health checks for all container types."""
        logger.info("Stopping container health checks")
        self.docker_manager.stop_health_check()
        self.lxc_manager.stop_health_check()
    
    def shutdown(self):
        """Perform a graceful shutdown of the container manager."""
        logger.info("Shutting down container manager")
        
        # Stop health checks
        self.stop_health_checks()
        
        # Remove PID file
        if os.path.exists("/var/run/viztron/container_manager.pid"):
            os.remove("/var/run/viztron/container_manager.pid")
        
        logger.info("Container manager shutdown complete")


# Example usage
if __name__ == "__main__":
    # Create container manager
    container_manager = ContainerManager()
    
    try:
        # Start health checks
        container_manager.start_health_checks()
        
        # List services
        services = container_manager.list_services()
        print(f"Services: {len(services)}")
        for service in services:
            print(f"  {service['name']} ({service['container_type']}): {service['status']}")
        
        # Start all services
        print("\nStarting all services...")
        results = container_manager.start_all_services()
        for service_name, success in results.items():
            print(f"  {service_name}: {'Success' if success else 'Failed'}")
        
        # Run for a while
        print("\nContainer manager running. Press Ctrl+C to exit.")
        
        # Main loop
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        # Stop all services
        print("Stopping all services...")
        container_manager.stop_all_services()
        
        # Shutdown
        container_manager.shutdown()
