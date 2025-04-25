#!/usr/bin/env python3
"""
Communication Manager for Viztron Homebase Module

This module implements the communication functionality for the
Viztron Homebase Module, handling various communication protocols
and interfaces.

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
import asyncio
import websockets
import requests
from typing import Dict, List, Any, Optional, Tuple, Set, Union, Callable
from enum import Enum
from datetime import datetime, timedelta
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/viztron/communication_manager.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('communication_manager')

class CommunicationProtocol(Enum):
    """Enumeration of supported communication protocols."""
    HTTP = "http"
    HTTPS = "https"
    MQTT = "mqtt"
    WEBSOCKET = "websocket"
    ZIGBEE = "zigbee"
    ZWAVE = "zwave"
    BLUETOOTH = "bluetooth"
    WIFI = "wifi"
    CELLULAR = "cellular"
    LORA = "lora"


class CommunicationManager:
    """
    Main communication manager for the Viztron Homebase Module.
    
    This class provides a unified interface for communication operations,
    supporting multiple communication protocols and interfaces.
    """
    
    def __init__(self, config_path: str = "/etc/viztron/communication_config.json"):
        """
        Initialize the communication manager.
        
        Args:
            config_path: Path to the communication configuration file
        """
        self.config_path = config_path
        self.config = self._load_config()
        
        # Create required directories
        os.makedirs("/var/log/viztron", exist_ok=True)
        
        # Communication handlers
        self.handlers = {}
        
        # Message queues
        self.outgoing_queue = queue.Queue()
        self.incoming_queue = queue.Queue()
        
        # Active connections
        self.connections = {}
        
        # Connection locks
        self.locks = {}
        
        # Initialize communication handlers
        self._initialize_handlers()
        
        # Create PID file
        self._create_pid_file()
        
        # Start message processing threads
        self.running = True
        self.outgoing_thread = threading.Thread(target=self._process_outgoing_messages)
        self.outgoing_thread.daemon = True
        self.outgoing_thread.start()
        
        self.incoming_thread = threading.Thread(target=self._process_incoming_messages)
        self.incoming_thread.daemon = True
        self.incoming_thread.start()
        
        logger.info("Communication manager initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load communication configuration from file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                return {
                    "protocols": {
                        "http": {
                            "enabled": True,
                            "port": 8080,
                            "ssl": False,
                            "cert_file": "",
                            "key_file": "",
                            "auth_required": True,
                            "rate_limit": 100,  # requests per minute
                            "timeout": 30  # seconds
                        },
                        "mqtt": {
                            "enabled": True,
                            "broker": "localhost",
                            "port": 1883,
                            "ssl": False,
                            "cert_file": "",
                            "key_file": "",
                            "username": "",
                            "password": "",
                            "client_id": "viztron_homebase",
                            "topics": {
                                "publish": "viztron/homebase/out",
                                "subscribe": "viztron/homebase/in",
                                "status": "viztron/homebase/status",
                                "command": "viztron/homebase/command"
                            },
                            "qos": 1,
                            "retain": False
                        },
                        "websocket": {
                            "enabled": True,
                            "host": "0.0.0.0",
                            "port": 8081,
                            "ssl": False,
                            "cert_file": "",
                            "key_file": "",
                            "auth_required": True,
                            "max_connections": 100,
                            "ping_interval": 30,  # seconds
                            "ping_timeout": 10  # seconds
                        },
                        "zigbee": {
                            "enabled": False,
                            "port": "/dev/ttyUSB0",
                            "baud_rate": 115200,
                            "pan_id": "0x1a62",
                            "channel": 15,
                            "security_level": "high"
                        },
                        "zwave": {
                            "enabled": False,
                            "port": "/dev/ttyACM0",
                            "network_key": ""
                        },
                        "bluetooth": {
                            "enabled": False,
                            "adapter": "hci0",
                            "scan_interval": 60,  # seconds
                            "discovery_timeout": 10  # seconds
                        }
                    },
                    "cloud": {
                        "enabled": True,
                        "url": "https://api.viztron.com",
                        "api_key": "",
                        "sync_interval": 300,  # seconds
                        "retry_interval": 60,  # seconds
                        "max_retries": 5
                    },
                    "local_network": {
                        "discovery_enabled": True,
                        "discovery_interval": 300,  # seconds
                        "broadcast_port": 5353,
                        "service_port": 8080
                    },
                    "encryption": {
                        "enabled": True,
                        "algorithm": "AES-256-GCM",
                        "key_rotation_interval": 86400  # 24 hours
                    },
                    "message_handlers": {
                        "event": "EventHandler",
                        "command": "CommandHandler",
                        "status": "StatusHandler",
                        "data": "DataHandler",
                        "media": "MediaHandler",
                        "config": "ConfigHandler"
                    }
                }
        except Exception as e:
            logger.error(f"Failed to load communication config: {str(e)}")
            return {
                "protocols": {
                    "http": {
                        "enabled": True,
                        "port": 8080,
                        "ssl": False
                    },
                    "mqtt": {
                        "enabled": False
                    },
                    "websocket": {
                        "enabled": False
                    }
                },
                "cloud": {
                    "enabled": False
                },
                "local_network": {
                    "discovery_enabled": True
                },
                "encryption": {
                    "enabled": True
                }
            }
    
    def _save_config(self):
        """Save communication configuration to file."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save communication config: {str(e)}")
    
    def _create_pid_file(self):
        """Create PID file for the communication manager."""
        try:
            pid = os.getpid()
            pid_dir = "/var/run/viztron"
            os.makedirs(pid_dir, exist_ok=True)
            
            with open(f"{pid_dir}/communication_manager.pid", 'w') as f:
                f.write(str(pid))
            
            logger.debug(f"Created PID file with PID {pid}")
        except Exception as e:
            logger.error(f"Failed to create PID file: {str(e)}")
    
    def _initialize_handlers(self):
        """Initialize all configured communication handlers."""
        # Initialize HTTP handler
        if self.config.get("protocols", {}).get("http", {}).get("enabled", False):
            self._initialize_http_handler()
        
        # Initialize MQTT handler
        if self.config.get("protocols", {}).get("mqtt", {}).get("enabled", False):
            self._initialize_mqtt_handler()
        
        # Initialize WebSocket handler
        if self.config.get("protocols", {}).get("websocket", {}).get("enabled", False):
            self._initialize_websocket_handler()
        
        # Initialize Zigbee handler
        if self.config.get("protocols", {}).get("zigbee", {}).get("enabled", False):
            self._initialize_zigbee_handler()
        
        # Initialize Z-Wave handler
        if self.config.get("protocols", {}).get("zwave", {}).get("enabled", False):
            self._initialize_zwave_handler()
        
        # Initialize Bluetooth handler
        if self.config.get("protocols", {}).get("bluetooth", {}).get("enabled", False):
            self._initialize_bluetooth_handler()
        
        # Initialize cloud communication
        if self.config.get("cloud", {}).get("enabled", False):
            self._initialize_cloud_handler()
        
        # Initialize local network discovery
        if self.config.get("local_network", {}).get("discovery_enabled", False):
            self._initialize_discovery_handler()
    
    def _initialize_http_handler(self):
        """Initialize HTTP communication handler."""
        try:
            from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
            import threading
            
            # Get HTTP configuration
            http_config = self.config.get("protocols", {}).get("http", {})
            port = http_config.get("port", 8080)
            ssl_enabled = http_config.get("ssl", False)
            cert_file = http_config.get("cert_file", "")
            key_file = http_config.get("key_file", "")
            
            # Create HTTP request handler
            comm_manager = self  # Reference to communication manager for handler
            
            class ViztronHTTPHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    try:
                        # Parse path
                        path = self.path.split('?')[0]
                        
                        # Handle API endpoints
                        if path.startswith('/api/'):
                            # Extract API endpoint
                            endpoint = path[5:]
                            
                            # Check authentication
                            if http_config.get("auth_required", True):
                                auth_header = self.headers.get('Authorization')
                                if not auth_header or not comm_manager._validate_auth_token(auth_header):
                                    self.send_response(401)
                                    self.send_header('Content-Type', 'application/json')
                                    self.end_headers()
                                    self.wfile.write(json.dumps({"error": "Unauthorized"}).encode())
                                    return
                            
                            # Handle different endpoints
                            if endpoint == 'status':
                                # Return system status
                                status = comm_manager._get_system_status()
                                self.send_response(200)
                                self.send_header('Content-Type', 'application/json')
                                self.end_headers()
                                self.wfile.write(json.dumps(status).encode())
                            elif endpoint == 'devices':
                                # Return device list
                                devices = comm_manager._get_devices()
                                self.send_response(200)
                                self.send_header('Content-Type', 'application/json')
                                self.end_headers()
                                self.wfile.write(json.dumps(devices).encode())
                            elif endpoint.startswith('devices/'):
                                # Return specific device
                                device_id = endpoint[8:]
                                device = comm_manager._get_device(device_id)
                                if device:
                                    self.send_response(200)
                                    self.send_header('Content-Type', 'application/json')
                                    self.end_headers()
                                    self.wfile.write(json.dumps(device).encode())
                                else:
                                    self.send_response(404)
                                    self.send_header('Content-Type', 'application/json')
                                    self.end_headers()
                                    self.wfile.write(json.dumps({"error": "Device not found"}).encode())
                            elif endpoint == 'events':
                                # Return events
                                events = comm_manager._get_events()
                                self.send_response(200)
                                self.send_header('Content-Type', 'application/json')
                                self.end_headers()
                                self.wfile.write(json.dumps(events).encode())
                            else:
                                # Unknown endpoint
                                self.send_response(404)
                                self.send_header('Content-Type', 'application/json')
                                self.end_headers()
                                self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode())
                        else:
                            # Serve static files
                            self.send_response(404)
                            self.send_header('Content-Type', 'application/json')
                            self.end_headers()
                            self.wfile.write(json.dumps({"error": "Not found"}).encode())
                    except Exception as e:
                        logger.error(f"HTTP handler error: {str(e)}")
                        self.send_response(500)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": "Internal server error"}).encode())
                
                def do_POST(self):
                    try:
                        # Parse path
                        path = self.path.split('?')[0]
                        
                        # Handle API endpoints
                        if path.startswith('/api/'):
                            # Extract API endpoint
                            endpoint = path[5:]
                            
                            # Check authentication
                            if http_config.get("auth_required", True):
                                auth_header = self.headers.get('Authorization')
                                if not auth_header or not comm_manager._validate_auth_token(auth_header):
                                    self.send_response(401)
                                    self.send_header('Content-Type', 'application/json')
                                    self.end_headers()
                                    self.wfile.write(json.dumps({"error": "Unauthorized"}).encode())
                                    return
                            
                            # Read request body
                            content_length = int(self.headers.get('Content-Length', 0))
                            body = self.rfile.read(content_length).decode('utf-8')
                            
                            try:
                                data = json.loads(body)
                            except json.JSONDecodeError:
                                self.send_response(400)
                                self.send_header('Content-Type', 'application/json')
                                self.end_headers()
                                self.wfile.write(json.dumps({"error": "Invalid JSON"}).encode())
                                return
                            
                            # Handle different endpoints
                            if endpoint == 'command':
                                # Process command
                                result = comm_manager._process_command(data)
                                self.send_response(200)
                                self.send_header('Content-Type', 'application/json')
                                self.end_headers()
                                self.wfile.write(json.dumps(result).encode())
                            elif endpoint == 'config':
                                # Update configuration
                                result = comm_manager._update_config(data)
                                self.send_response(200)
                                self.send_header('Content-Type', 'application/json')
                                self.end_headers()
                                self.wfile.write(json.dumps(result).encode())
                            else:
                                # Unknown endpoint
                                self.send_response(404)
                                self.send_header('Content-Type', 'application/json')
                                self.end_headers()
                                self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode())
                        else:
                            # Not found
                            self.send_response(404)
                            self.send_header('Content-Type', 'application/json')
                            self.end_headers()
                            self.wfile.write(json.dumps({"error": "Not found"}).encode())
                    except Exception as e:
                        logger.error(f"HTTP handler error: {str(e)}")
                        self.send_response(500)
                        self.send_header('Content-Type', 'application/json')
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": "Internal server error"}).encode())
                
                def log_message(self, format, *args):
                    # Override to use our logger
                    logger.debug(f"HTTP: {self.address_string()} - {format % args}")
            
            # Create HTTP server
            server = ThreadingHTTPServer(('0.0.0.0', port), ViztronHTTPHandler)
            
            # Enable SSL if configured
            if ssl_enabled and cert_file and key_file:
                import ssl
                server.socket = ssl.wrap_socket(
                    server.socket,
                    keyfile=key_file,
                    certfile=cert_file,
                    server_side=True
                )
            
            # Start server in a separate thread
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            # Store server and thread
            self.handlers['http'] = {
                'server': server,
                'thread': server_thread
            }
            
            logger.info(f"HTTP handler initialized on port {port}" + (" with SSL" if ssl_enabled else ""))
        except Exception as e:
            logger.error(f"Failed to initialize HTTP handler: {str(e)}")
    
    def _initialize_mqtt_handler(self):
        """Initialize MQTT communication handler."""
        try:
            # Check if paho-mqtt is available
            try:
                import paho.mqtt.client as mqtt
            except ImportError:
                logger.error("paho-mqtt module not available, cannot use MQTT")
                return
            
            # Get MQTT configuration
            mqtt_config = self.config.get("protocols", {}).get("mqtt", {})
            broker = mqtt_config.get("broker", "localhost")
            port = mqtt_config.get("port", 1883)
            ssl_enabled = mqtt_config.get("ssl", False)
            cert_file = mqtt_config.get("cert_file", "")
            key_file = mqtt_config.get("key_file", "")
            username = mqtt_config.get("username", "")
            password = mqtt_config.get("password", "")
            client_id = mqtt_config.get("client_id", f"viztron_homebase_{uuid.uuid4().hex[:8]}")
            topics = mqtt_config.get("topics", {})
            qos = mqtt_config.get("qos", 1)
            retain = mqtt_config.get("retain", False)
            
            # Create MQTT client
            client = mqtt.Client(client_id=client_id)
            
            # Set up callbacks
            def on_connect(client, userdata, flags, rc):
                if rc == 0:
                    logger.info(f"Connected to MQTT broker {broker}:{port}")
                    
                    # Subscribe to topics
                    for topic_type, topic in topics.items():
                        if topic_type.startswith("subscribe") or topic_type == "command":
                            client.subscribe(topic, qos=qos)
                            logger.debug(f"Subscribed to MQTT topic: {topic}")
                    
                    # Publish status
                    status_topic = topics.get("status", "viztron/homebase/status")
                    client.publish(
                        status_topic,
                        json.dumps({"status": "online", "timestamp": int(time.time())}),
                        qos=qos,
                        retain=True
                    )
                else:
                    logger.error(f"Failed to connect to MQTT broker, return code: {rc}")
            
            def on_disconnect(client, userdata, rc):
                if rc != 0:
                    logger.warning(f"Unexpected disconnection from MQTT broker, return code: {rc}")
                else:
                    logger.info("Disconnected from MQTT broker")
            
            def on_message(client, userdata, msg):
                try:
                    # Parse message
                    payload = msg.payload.decode('utf-8')
                    topic = msg.topic
                    
                    logger.debug(f"Received MQTT message on topic {topic}: {payload}")
                    
                    # Process message based on topic
                    if topic == topics.get("command", "viztron/homebase/command"):
                        # Command message
                        try:
                            command = json.loads(payload)
                            self._handle_command(command, source="mqtt")
                        except json.JSONDecodeError:
                            logger.warning(f"Invalid JSON in MQTT command: {payload}")
                    elif topic == topics.get("subscribe", "viztron/homebase/in"):
                        # General message
                        try:
                            message = json.loads(payload)
                            self._handle_message(message, source="mqtt")
                        except json.JSONDecodeError:
                            logger.warning(f"Invalid JSON in MQTT message: {payload}")
                    else:
                        # Other topics
                        logger.debug(f"Unhandled MQTT topic: {topic}")
                except Exception as e:
                    logger.error(f"Error processing MQTT message: {str(e)}")
            
            # Set callbacks
            client.on_connect = on_connect
            client.on_disconnect = on_disconnect
            client.on_message = on_message
            
            # Set up authentication if configured
            if username and password:
                client.username_pw_set(username, password)
            
            # Set up SSL if configured
            if ssl_enabled:
                if cert_file and key_file:
                    client.tls_set(
                        ca_certs=None,
                        certfile=cert_file,
                        keyfile=key_file,
                        cert_reqs=ssl.CERT_NONE,
                        tls_version=ssl.PROTOCOL_TLS,
                        ciphers=None
                    )
                else:
                    client.tls_set(
                        ca_certs=None,
                        cert_reqs=ssl.CERT_NONE,
                        tls_version=ssl.PROTOCOL_TLS,
                        ciphers=None
                    )
                client.tls_insecure_set(True)
            
            # Set up last will and testament
            status_topic = topics.get("status", "viztron/homebase/status")
            client.will_set(
                status_topic,
                json.dumps({"status": "offline", "timestamp": int(time.time())}),
                qos=qos,
                retain=True
            )
            
            # Connect to broker
            try:
                client.connect(broker, port, keepalive=60)
                client.loop_start()
                
                # Store client
                self.handlers['mqtt'] = {
                    'client': client,
                    'config': mqtt_config
                }
                
                logger.info(f"MQTT handler initialized, connected to {broker}:{port}")
            except Exception as e:
                logger.error(f"Failed to connect to MQTT broker: {str(e)}")
                client.loop_stop()
        except Exception as e:
            logger.error(f"Failed to initialize MQTT handler: {str(e)}")
    
    def _initialize_websocket_handler(self):
        """Initialize WebSocket communication handler."""
        try:
            # Check if websockets is available
            try:
                import websockets
                import asyncio
            except ImportError:
                logger.error("websockets module not available, cannot use WebSocket")
                return
            
            # Get WebSocket configuration
            ws_config = self.config.get("protocols", {}).get("websocket", {})
            host = ws_config.get("host", "0.0.0.0")
            port = ws_config.get("port", 8081)
            ssl_enabled = ws_config.get("ssl", False)
            cert_file = ws_config.get("cert_file", "")
            key_file = ws_config.get("key_file", "")
            auth_required = ws_config.get("auth_required", True)
            max_connections = ws_config.get("max_connections", 100)
            ping_interval = ws_config.get("ping_interval", 30)
            ping_timeout = ws_config.get("ping_timeout", 10)
            
            # Store active connections
            active_connections = set()
            
            # Create WebSocket server
            async def handler(websocket, path):
                # Handle new connection
                client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
                logger.debug(f"New WebSocket connection from {client_info}")
                
                # Check if max connections reached
                if len(active_connections) >= max_connections:
                    logger.warning(f"Max WebSocket connections reached, rejecting {client_info}")
                    await websocket.close(1013, "Maximum connections reached")
                    return
                
                # Add to active connections
                active_connections.add(websocket)
                
                try:
                    # Authentication
                    if auth_required:
                        # Wait for authentication message
                        auth_timeout = 10  # seconds
                        try:
                            auth_message = await asyncio.wait_for(websocket.recv(), auth_timeout)
                            
                            try:
                                auth_data = json.loads(auth_message)
                                if not self._validate_websocket_auth(auth_data):
                                    logger.warning(f"WebSocket authentication failed for {client_info}")
                                    await websocket.close(1008, "Authentication failed")
                                    return
                            except json.JSONDecodeError:
                                logger.warning(f"Invalid JSON in WebSocket authentication: {auth_message}")
                                await websocket.close(1008, "Invalid authentication format")
                                return
                        except asyncio.TimeoutError:
                            logger.warning(f"WebSocket authentication timeout for {client_info}")
                            await websocket.close(1008, "Authentication timeout")
                            return
                    
                    # Send welcome message
                    await websocket.send(json.dumps({
                        "type": "system",
                        "action": "welcome",
                        "timestamp": int(time.time()),
                        "data": {
                            "message": "Welcome to Viztron Homebase WebSocket API",
                            "version": "1.0.0"
                        }
                    }))
                    
                    # Message handling loop
                    while True:
                        message = await websocket.recv()
                        
                        try:
                            data = json.loads(message)
                            logger.debug(f"Received WebSocket message from {client_info}: {data}")
                            
                            # Process message
                            response = self._handle_websocket_message(data)
                            
                            # Send response if needed
                            if response:
                                await websocket.send(json.dumps(response))
                        except json.JSONDecodeError:
                            logger.warning(f"Invalid JSON in WebSocket message: {message}")
                            await websocket.send(json.dumps({
                                "type": "error",
                                "timestamp": int(time.time()),
                                "data": {
                                    "message": "Invalid JSON format"
                                }
                            }))
                        except Exception as e:
                            logger.error(f"Error processing WebSocket message: {str(e)}")
                            await websocket.send(json.dumps({
                                "type": "error",
                                "timestamp": int(time.time()),
                                "data": {
                                    "message": "Internal server error"
                                }
                            }))
                
                except websockets.exceptions.ConnectionClosed:
                    logger.debug(f"WebSocket connection closed for {client_info}")
                except Exception as e:
                    logger.error(f"WebSocket handler error for {client_info}: {str(e)}")
                finally:
                    # Remove from active connections
                    active_connections.remove(websocket)
            
            # Create SSL context if needed
            ssl_context = None
            if ssl_enabled and cert_file and key_file:
                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ssl_context.load_cert_chain(cert_file, key_file)
            
            # Create server
            start_server = websockets.serve(
                handler,
                host,
                port,
                ssl=ssl_context,
                ping_interval=ping_interval,
                ping_timeout=ping_timeout,
                max_size=10 * 1024 * 1024  # 10 MB max message size
            )
            
            # Create event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Start server
            server = loop.run_until_complete(start_server)
            
            # Create broadcast function
            async def broadcast_message(message):
                if active_connections:
                    await asyncio.wait([
                        connection.send(json.dumps(message))
                        for connection in active_connections
                    ])
            
            # Start event loop in a separate thread
            def run_websocket_server():
                loop.run_forever()
            
            server_thread = threading.Thread(target=run_websocket_server)
            server_thread.daemon = True
            server_thread.start()
            
            # Store server and thread
            self.handlers['websocket'] = {
                'server': server,
                'thread': server_thread,
                'loop': loop,
                'connections': active_connections,
                'broadcast': broadcast_message
            }
            
            logger.info(f"WebSocket handler initialized on {host}:{port}" + (" with SSL" if ssl_enabled else ""))
        except Exception as e:
            logger.error(f"Failed to initialize WebSocket handler: {str(e)}")
    
    def _initialize_zigbee_handler(self):
        """Initialize Zigbee communication handler."""
        try:
            # Check if zigpy is available
            try:
                import zigpy
                import zigpy.application
                import zigpy.config as zigpy_config
                import zigpy.device
                import zigpy.exceptions
                import zigpy.types
                import zigpy.zcl
                import zigpy.zdo
                import zigpy.zdo.types
                import zigpy_xbee
                import zigpy_deconz
                import zigpy_zigate
                import zigpy_znp
            except ImportError:
                logger.error("zigpy modules not available, cannot use Zigbee")
                return
            
            # Get Zigbee configuration
            zigbee_config = self.config.get("protocols", {}).get("zigbee", {})
            port = zigbee_config.get("port", "/dev/ttyUSB0")
            baud_rate = zigbee_config.get("baud_rate", 115200)
            pan_id = zigbee_config.get("pan_id", "0x1a62")
            channel = zigbee_config.get("channel", 15)
            
            # Determine adapter type based on port
            if "xbee" in port.lower():
                adapter = "xbee"
            elif "deconz" in port.lower():
                adapter = "deconz"
            elif "zigate" in port.lower():
                adapter = "zigate"
            elif "znp" in port.lower() or "cc2531" in port.lower():
                adapter = "znp"
            else:
                # Default to ZNP
                adapter = "znp"
            
            # Create configuration
            config = {
                "database_path": "/var/lib/viztron/zigbee.db",
                "device": {
                    "path": port,
                    "baudrate": baud_rate
                },
                "network": {
                    "pan_id": pan_id,
                    "channel": channel,
                    "extended_pan_id": "BD:53:72:F3:4E:A5:C2:99"
                }
            }
            
            # Create application based on adapter type
            if adapter == "xbee":
                app = zigpy_xbee.XBeeCoordinator(config)
            elif adapter == "deconz":
                app = zigpy_deconz.DeconzCoordinator(config)
            elif adapter == "zigate":
                app = zigpy_zigate.ZiGateCoordinator(config)
            elif adapter == "znp":
                app = zigpy_znp.ZNPCoordinator(config)
            else:
                raise ValueError(f"Unsupported Zigbee adapter: {adapter}")
            
            # Start application
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            async def start_zigbee():
                await app.startup(auto_form=True)
                logger.info(f"Zigbee network started on channel {channel}, PAN ID {pan_id}")
                
                # Register callbacks
                app.add_listener(self._zigbee_device_joined)
                app.add_listener(self._zigbee_device_left)
                app.add_listener(self._zigbee_message_received)
                
                # Start permit joining
                await app.permit(60)
                logger.info("Zigbee network is accepting new devices for 60 seconds")
                
                # Keep application running
                while True:
                    await asyncio.sleep(1)
            
            # Start application in a separate thread
            def run_zigbee():
                loop.run_until_complete(start_zigbee())
            
            zigbee_thread = threading.Thread(target=run_zigbee)
            zigbee_thread.daemon = True
            zigbee_thread.start()
            
            # Store application and thread
            self.handlers['zigbee'] = {
                'app': app,
                'thread': zigbee_thread,
                'loop': loop,
                'config': zigbee_config
            }
            
            logger.info(f"Zigbee handler initialized using {adapter} adapter on {port}")
        except Exception as e:
            logger.error(f"Failed to initialize Zigbee handler: {str(e)}")
    
    def _initialize_zwave_handler(self):
        """Initialize Z-Wave communication handler."""
        try:
            # Check if python-openzwave is available
            try:
                import openzwave
                from openzwave.network import ZWaveNetwork
                from openzwave.option import ZWaveOption
                from openzwave.node import ZWaveNode
            except ImportError:
                logger.error("python-openzwave module not available, cannot use Z-Wave")
                return
            
            # Get Z-Wave configuration
            zwave_config = self.config.get("protocols", {}).get("zwave", {})
            port = zwave_config.get("port", "/dev/ttyACM0")
            network_key = zwave_config.get("network_key", "")
            
            # Create options
            options = ZWaveOption(port, config_path="/etc/openzwave/", user_path="/var/lib/viztron/zwave/")
            options.set_console_output(False)
            options.lock()
            
            # Create network
            network = ZWaveNetwork(options, autostart=False)
            
            # Define callbacks
            def network_started(network):
                logger.info("Z-Wave network started")
            
            def network_ready(network):
                logger.info("Z-Wave network is ready")
                
                # Log controller information
                controller = network.controller
                logger.info(f"Z-Wave controller: {controller.node.product_name}")
                logger.info(f"Z-Wave home ID: 0x{network.home_id_str}")
                logger.info(f"Z-Wave node count: {network.nodes_count}")
            
            def network_stopped(network):
                logger.info("Z-Wave network stopped")
            
            def network_failed(network):
                logger.error("Z-Wave network failed to start")
            
            def node_added(network, node):
                logger.info(f"Z-Wave node added: {node.node_id}")
            
            def node_removed(network, node):
                logger.info(f"Z-Wave node removed: {node.node_id}")
            
            def value_changed(network, node, value):
                logger.debug(f"Z-Wave value changed: Node {node.node_id}, Value {value.label} = {value.data}")
                
                # Create message
                message = {
                    "type": "zwave",
                    "action": "value_changed",
                    "timestamp": int(time.time()),
                    "data": {
                        "node_id": node.node_id,
                        "home_id": network.home_id_str,
                        "value_id": value.value_id,
                        "label": value.label,
                        "data": value.data,
                        "units": value.units,
                        "command_class": value.command_class,
                        "genre": value.genre
                    }
                }
                
                # Add to incoming queue
                self.incoming_queue.put(message)
            
            # Add callbacks
            network.add_handler("network_started", network_started)
            network.add_handler("network_ready", network_ready)
            network.add_handler("network_stopped", network_stopped)
            network.add_handler("network_failed", network_failed)
            network.add_handler("node_added", node_added)
            network.add_handler("node_removed", node_removed)
            network.add_handler("value_changed", value_changed)
            
            # Start network
            network.start()
            
            # Store network
            self.handlers['zwave'] = {
                'network': network,
                'options': options,
                'config': zwave_config
            }
            
            logger.info(f"Z-Wave handler initialized on {port}")
        except Exception as e:
            logger.error(f"Failed to initialize Z-Wave handler: {str(e)}")
    
    def _initialize_bluetooth_handler(self):
        """Initialize Bluetooth communication handler."""
        try:
            # Check if bluepy is available
            try:
                from bluepy.btle import Scanner, DefaultDelegate, Peripheral
            except ImportError:
                logger.error("bluepy module not available, cannot use Bluetooth")
                return
            
            # Get Bluetooth configuration
            bt_config = self.config.get("protocols", {}).get("bluetooth", {})
            adapter = bt_config.get("adapter", "hci0")
            scan_interval = bt_config.get("scan_interval", 60)
            discovery_timeout = bt_config.get("discovery_timeout", 10)
            
            # Create scanner delegate
            class ScanDelegate(DefaultDelegate):
                def __init__(self, comm_manager):
                    DefaultDelegate.__init__(self)
                    self.comm_manager = comm_manager
                
                def handleDiscovery(self, dev, isNewDev, isNewData):
                    if isNewDev:
                        logger.debug(f"Discovered new Bluetooth device: {dev.addr}")
                        
                        # Create message
                        message = {
                            "type": "bluetooth",
                            "action": "device_discovered",
                            "timestamp": int(time.time()),
                            "data": {
                                "address": dev.addr,
                                "addr_type": dev.addrType,
                                "rssi": dev.rssi,
                                "connectable": dev.connectable,
                                "scan_data": {key: value for key, value in dev.getScanData()}
                            }
                        }
                        
                        # Add to incoming queue
                        self.comm_manager.incoming_queue.put(message)
                    elif isNewData:
                        logger.debug(f"Received new data from Bluetooth device: {dev.addr}")
            
            # Create scanner
            scanner = Scanner(adapter).withDelegate(ScanDelegate(self))
            
            # Start scanning thread
            def scan_thread():
                while True:
                    try:
                        logger.debug(f"Starting Bluetooth scan on adapter {adapter}")
                        devices = scanner.scan(discovery_timeout)
                        logger.debug(f"Bluetooth scan complete, found {len(devices)} devices")
                        
                        # Sleep until next scan
                        time.sleep(scan_interval)
                    except Exception as e:
                        logger.error(f"Error in Bluetooth scan: {str(e)}")
                        time.sleep(10)  # Sleep for 10 seconds before retrying
            
            # Start thread
            bt_thread = threading.Thread(target=scan_thread)
            bt_thread.daemon = True
            bt_thread.start()
            
            # Store scanner and thread
            self.handlers['bluetooth'] = {
                'scanner': scanner,
                'thread': bt_thread,
                'config': bt_config
            }
            
            logger.info(f"Bluetooth handler initialized on adapter {adapter}")
        except Exception as e:
            logger.error(f"Failed to initialize Bluetooth handler: {str(e)}")
    
    def _initialize_cloud_handler(self):
        """Initialize cloud communication handler."""
        try:
            # Get cloud configuration
            cloud_config = self.config.get("cloud", {})
            url = cloud_config.get("url", "https://api.viztron.com")
            api_key = cloud_config.get("api_key", "")
            sync_interval = cloud_config.get("sync_interval", 300)
            
            if not api_key:
                logger.warning("Cloud API key not configured, cloud communication disabled")
                return
            
            # Create session
            session = requests.Session()
            session.headers.update({
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "Viztron-Homebase/1.0.0"
            })
            
            # Test connection
            try:
                response = session.get(f"{url}/api/v1/status")
                response.raise_for_status()
                logger.info(f"Connected to cloud API at {url}")
            except Exception as e:
                logger.error(f"Failed to connect to cloud API: {str(e)}")
                return
            
            # Start sync thread
            def sync_thread():
                while True:
                    try:
                        logger.debug("Starting cloud sync")
                        
                        # Sync status
                        self._sync_status_to_cloud(session, url)
                        
                        # Sync events
                        self._sync_events_to_cloud(session, url)
                        
                        # Sync devices
                        self._sync_devices_to_cloud(session, url)
                        
                        # Check for commands
                        self._check_cloud_commands(session, url)
                        
                        logger.debug("Cloud sync complete")
                        
                        # Sleep until next sync
                        time.sleep(sync_interval)
                    except Exception as e:
                        logger.error(f"Error in cloud sync: {str(e)}")
                        time.sleep(60)  # Sleep for 1 minute before retrying
            
            # Start thread
            cloud_thread = threading.Thread(target=sync_thread)
            cloud_thread.daemon = True
            cloud_thread.start()
            
            # Store session and thread
            self.handlers['cloud'] = {
                'session': session,
                'thread': cloud_thread,
                'config': cloud_config,
                'url': url
            }
            
            logger.info(f"Cloud handler initialized, connected to {url}")
        except Exception as e:
            logger.error(f"Failed to initialize cloud handler: {str(e)}")
    
    def _initialize_discovery_handler(self):
        """Initialize local network discovery handler."""
        try:
            # Get discovery configuration
            discovery_config = self.config.get("local_network", {})
            discovery_interval = discovery_config.get("discovery_interval", 300)
            broadcast_port = discovery_config.get("broadcast_port", 5353)
            service_port = discovery_config.get("service_port", 8080)
            
            # Create UDP socket for broadcasting
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', broadcast_port))
            
            # Create UDP socket for receiving
            recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            recv_sock.bind(('0.0.0.0', broadcast_port))
            
            # Start discovery thread
            def discovery_thread():
                while True:
                    try:
                        # Broadcast discovery message
                        logger.debug("Broadcasting discovery message")
                        
                        # Get system info
                        system_info = self._get_system_info()
                        
                        # Create discovery message
                        discovery_message = {
                            "type": "discovery",
                            "action": "announce",
                            "timestamp": int(time.time()),
                            "data": {
                                "id": system_info.get("id", ""),
                                "name": system_info.get("name", "Viztron Homebase"),
                                "version": system_info.get("version", "1.0.0"),
                                "ip": self._get_local_ip(),
                                "port": service_port,
                                "services": list(self.handlers.keys())
                            }
                        }
                        
                        # Broadcast message
                        sock.sendto(json.dumps(discovery_message).encode(), ('<broadcast>', broadcast_port))
                        
                        # Sleep until next broadcast
                        time.sleep(discovery_interval)
                    except Exception as e:
                        logger.error(f"Error in discovery broadcast: {str(e)}")
                        time.sleep(60)  # Sleep for 1 minute before retrying
            
            # Start discovery response thread
            def discovery_response_thread():
                while True:
                    try:
                        # Wait for discovery request
                        data, addr = recv_sock.recvfrom(4096)
                        
                        try:
                            # Parse request
                            request = json.loads(data.decode())
                            
                            # Check if it's a discovery request
                            if request.get("type") == "discovery" and request.get("action") == "request":
                                logger.debug(f"Received discovery request from {addr[0]}:{addr[1]}")
                                
                                # Get system info
                                system_info = self._get_system_info()
                                
                                # Create response
                                response = {
                                    "type": "discovery",
                                    "action": "response",
                                    "timestamp": int(time.time()),
                                    "data": {
                                        "id": system_info.get("id", ""),
                                        "name": system_info.get("name", "Viztron Homebase"),
                                        "version": system_info.get("version", "1.0.0"),
                                        "ip": self._get_local_ip(),
                                        "port": service_port,
                                        "services": list(self.handlers.keys())
                                    }
                                }
                                
                                # Send response
                                recv_sock.sendto(json.dumps(response).encode(), addr)
                        except json.JSONDecodeError:
                            logger.warning(f"Invalid JSON in discovery request from {addr[0]}:{addr[1]}")
                        except Exception as e:
                            logger.error(f"Error processing discovery request: {str(e)}")
                    except Exception as e:
                        logger.error(f"Error in discovery response: {str(e)}")
            
            # Start threads
            broadcast_thread = threading.Thread(target=discovery_thread)
            broadcast_thread.daemon = True
            broadcast_thread.start()
            
            response_thread = threading.Thread(target=discovery_response_thread)
            response_thread.daemon = True
            response_thread.start()
            
            # Store sockets and threads
            self.handlers['discovery'] = {
                'broadcast_socket': sock,
                'receive_socket': recv_sock,
                'broadcast_thread': broadcast_thread,
                'response_thread': response_thread,
                'config': discovery_config
            }
            
            logger.info(f"Local network discovery handler initialized on port {broadcast_port}")
        except Exception as e:
            logger.error(f"Failed to initialize discovery handler: {str(e)}")
    
    def _process_outgoing_messages(self):
        """Process outgoing messages from the queue."""
        while self.running:
            try:
                # Get message from queue
                message = self.outgoing_queue.get(timeout=1.0)
                
                # Process message
                self._send_message(message)
                
                # Mark as done
                self.outgoing_queue.task_done()
            except queue.Empty:
                # No messages in queue
                pass
            except Exception as e:
                logger.error(f"Error processing outgoing message: {str(e)}")
    
    def _process_incoming_messages(self):
        """Process incoming messages from the queue."""
        while self.running:
            try:
                # Get message from queue
                message = self.incoming_queue.get(timeout=1.0)
                
                # Process message
                self._handle_message(message)
                
                # Mark as done
                self.incoming_queue.task_done()
            except queue.Empty:
                # No messages in queue
                pass
            except Exception as e:
                logger.error(f"Error processing incoming message: {str(e)}")
    
    def _send_message(self, message: Dict[str, Any]):
        """
        Send a message using the appropriate protocol.
        
        Args:
            message: Message to send
        """
        try:
            # Get message type and destination
            message_type = message.get("type", "event")
            destination = message.get("destination", "all")
            
            # Add timestamp if not present
            if "timestamp" not in message:
                message["timestamp"] = int(time.time())
            
            # Encrypt message if needed
            if self.config.get("encryption", {}).get("enabled", True):
                message = self._encrypt_message(message)
            
            # Send to appropriate destination
            if destination == "cloud" and "cloud" in self.handlers:
                self._send_to_cloud(message)
            elif destination == "mqtt" and "mqtt" in self.handlers:
                self._send_to_mqtt(message)
            elif destination == "websocket" and "websocket" in self.handlers:
                self._send_to_websocket(message)
            elif destination == "http" and "http" in self.handlers:
                # HTTP is pull-based, so we don't send messages directly
                pass
            elif destination == "all":
                # Send to all available protocols
                if "mqtt" in self.handlers:
                    self._send_to_mqtt(message)
                if "websocket" in self.handlers:
                    self._send_to_websocket(message)
                if "cloud" in self.handlers:
                    self._send_to_cloud(message)
            else:
                logger.warning(f"Unknown message destination: {destination}")
        except Exception as e:
            logger.error(f"Failed to send message: {str(e)}")
    
    def _send_to_mqtt(self, message: Dict[str, Any]):
        """
        Send a message via MQTT.
        
        Args:
            message: Message to send
        """
        try:
            # Get MQTT client
            mqtt_handler = self.handlers.get("mqtt")
            if not mqtt_handler:
                logger.warning("MQTT handler not initialized")
                return
            
            client = mqtt_handler.get("client")
            config = mqtt_handler.get("config", {})
            
            # Get topic based on message type
            topics = config.get("topics", {})
            message_type = message.get("type", "event")
            
            if message_type == "event":
                topic = topics.get("publish", "viztron/homebase/out")
            elif message_type == "status":
                topic = topics.get("status", "viztron/homebase/status")
            else:
                topic = topics.get("publish", "viztron/homebase/out")
            
            # Get QoS and retain flag
            qos = config.get("qos", 1)
            retain = config.get("retain", False)
            
            # Publish message
            client.publish(topic, json.dumps(message), qos=qos, retain=retain)
            
            logger.debug(f"Sent message to MQTT topic {topic}")
        except Exception as e:
            logger.error(f"Failed to send message to MQTT: {str(e)}")
    
    def _send_to_websocket(self, message: Dict[str, Any]):
        """
        Send a message via WebSocket.
        
        Args:
            message: Message to send
        """
        try:
            # Get WebSocket handler
            ws_handler = self.handlers.get("websocket")
            if not ws_handler:
                logger.warning("WebSocket handler not initialized")
                return
            
            # Get broadcast function and loop
            broadcast = ws_handler.get("broadcast")
            loop = ws_handler.get("loop")
            
            if not broadcast or not loop:
                logger.warning("WebSocket broadcast function or loop not available")
                return
            
            # Schedule broadcast in the WebSocket event loop
            asyncio.run_coroutine_threadsafe(broadcast(message), loop)
            
            logger.debug("Sent message to WebSocket clients")
        except Exception as e:
            logger.error(f"Failed to send message to WebSocket: {str(e)}")
    
    def _send_to_cloud(self, message: Dict[str, Any]):
        """
        Send a message to the cloud.
        
        Args:
            message: Message to send
        """
        try:
            # Get cloud handler
            cloud_handler = self.handlers.get("cloud")
            if not cloud_handler:
                logger.warning("Cloud handler not initialized")
                return
            
            # Get session and URL
            session = cloud_handler.get("session")
            url = cloud_handler.get("url")
            
            if not session or not url:
                logger.warning("Cloud session or URL not available")
                return
            
            # Determine endpoint based on message type
            message_type = message.get("type", "event")
            
            if message_type == "event":
                endpoint = "/api/v1/events"
            elif message_type == "status":
                endpoint = "/api/v1/status"
            elif message_type == "data":
                endpoint = "/api/v1/data"
            else:
                endpoint = "/api/v1/messages"
            
            # Send message
            response = session.post(f"{url}{endpoint}", json=message)
            response.raise_for_status()
            
            logger.debug(f"Sent message to cloud endpoint {endpoint}")
        except Exception as e:
            logger.error(f"Failed to send message to cloud: {str(e)}")
    
    def _handle_message(self, message: Dict[str, Any], source: str = "internal"):
        """
        Handle an incoming message.
        
        Args:
            message: Message to handle
            source: Source of the message
        """
        try:
            # Decrypt message if needed
            if self.config.get("encryption", {}).get("enabled", True) and message.get("encrypted", False):
                message = self._decrypt_message(message)
            
            # Get message type
            message_type = message.get("type", "event")
            
            # Handle based on message type
            if message_type == "command":
                self._handle_command(message, source)
            elif message_type == "event":
                self._handle_event(message, source)
            elif message_type == "status":
                self._handle_status(message, source)
            elif message_type == "data":
                self._handle_data(message, source)
            elif message_type == "config":
                self._handle_config(message, source)
            else:
                logger.warning(f"Unknown message type: {message_type}")
        except Exception as e:
            logger.error(f"Failed to handle message: {str(e)}")
    
    def _handle_command(self, message: Dict[str, Any], source: str = "internal"):
        """
        Handle a command message.
        
        Args:
            message: Command message
            source: Source of the message
        """
        try:
            # Get command details
            command = message.get("command", "")
            target = message.get("target", "system")
            params = message.get("params", {})
            
            logger.info(f"Received command '{command}' for target '{target}' from {source}")
            
            # Handle system commands
            if target == "system":
                if command == "restart":
                    # Restart system
                    logger.info("Restarting system")
                    # Implement system restart logic
                    pass
                elif command == "shutdown":
                    # Shutdown system
                    logger.info("Shutting down system")
                    # Implement system shutdown logic
                    pass
                elif command == "update":
                    # Update system
                    logger.info("Updating system")
                    # Implement system update logic
                    pass
                elif command == "status":
                    # Get system status
                    status = self._get_system_status()
                    
                    # Send status response
                    response = {
                        "type": "status",
                        "timestamp": int(time.time()),
                        "data": status,
                        "source": "system",
                        "in_response_to": message.get("id", "")
                    }
                    
                    self.outgoing_queue.put(response)
                else:
                    logger.warning(f"Unknown system command: {command}")
            
            # Handle device commands
            elif target == "device" or target.startswith("device:"):
                device_id = target.split(":", 1)[1] if ":" in target else params.get("device_id", "")
                
                if not device_id:
                    logger.warning("Device command missing device ID")
                    return
                
                if command == "status":
                    # Get device status
                    device = self._get_device(device_id)
                    
                    if device:
                        # Send device status response
                        response = {
                            "type": "status",
                            "timestamp": int(time.time()),
                            "data": device,
                            "source": f"device:{device_id}",
                            "in_response_to": message.get("id", "")
                        }
                        
                        self.outgoing_queue.put(response)
                    else:
                        logger.warning(f"Device not found: {device_id}")
                elif command == "control":
                    # Control device
                    action = params.get("action", "")
                    action_params = params.get("params", {})
                    
                    logger.info(f"Controlling device {device_id}, action: {action}")
                    
                    # Implement device control logic
                    pass
                else:
                    logger.warning(f"Unknown device command: {command}")
            
            # Handle zone commands
            elif target == "zone" or target.startswith("zone:"):
                zone_id = target.split(":", 1)[1] if ":" in target else params.get("zone_id", "")
                
                if not zone_id:
                    logger.warning("Zone command missing zone ID")
                    return
                
                if command == "status":
                    # Get zone status
                    zone = self._get_zone(zone_id)
                    
                    if zone:
                        # Send zone status response
                        response = {
                            "type": "status",
                            "timestamp": int(time.time()),
                            "data": zone,
                            "source": f"zone:{zone_id}",
                            "in_response_to": message.get("id", "")
                        }
                        
                        self.outgoing_queue.put(response)
                    else:
                        logger.warning(f"Zone not found: {zone_id}")
                elif command == "arm":
                    # Arm zone
                    mode = params.get("mode", "away")
                    
                    logger.info(f"Arming zone {zone_id}, mode: {mode}")
                    
                    # Implement zone arming logic
                    pass
                elif command == "disarm":
                    # Disarm zone
                    logger.info(f"Disarming zone {zone_id}")
                    
                    # Implement zone disarming logic
                    pass
                else:
                    logger.warning(f"Unknown zone command: {command}")
            
            # Handle camera commands
            elif target == "camera" or target.startswith("camera:"):
                camera_id = target.split(":", 1)[1] if ":" in target else params.get("camera_id", "")
                
                if not camera_id:
                    logger.warning("Camera command missing camera ID")
                    return
                
                if command == "status":
                    # Get camera status
                    camera = self._get_camera(camera_id)
                    
                    if camera:
                        # Send camera status response
                        response = {
                            "type": "status",
                            "timestamp": int(time.time()),
                            "data": camera,
                            "source": f"camera:{camera_id}",
                            "in_response_to": message.get("id", "")
                        }
                        
                        self.outgoing_queue.put(response)
                    else:
                        logger.warning(f"Camera not found: {camera_id}")
                elif command == "snapshot":
                    # Take snapshot
                    logger.info(f"Taking snapshot from camera {camera_id}")
                    
                    # Implement snapshot logic
                    pass
                elif command == "record":
                    # Start/stop recording
                    action = params.get("action", "start")
                    duration = params.get("duration", 60)
                    
                    logger.info(f"{action.capitalize()} recording on camera {camera_id}")
                    
                    # Implement recording logic
                    pass
                else:
                    logger.warning(f"Unknown camera command: {command}")
            
            # Handle AI commands
            elif target == "ai":
                if command == "status":
                    # Get AI status
                    ai_status = self._get_ai_status()
                    
                    # Send AI status response
                    response = {
                        "type": "status",
                        "timestamp": int(time.time()),
                        "data": ai_status,
                        "source": "ai",
                        "in_response_to": message.get("id", "")
                    }
                    
                    self.outgoing_queue.put(response)
                elif command == "analyze":
                    # Analyze data
                    data_type = params.get("data_type", "")
                    data = params.get("data", {})
                    
                    logger.info(f"Analyzing {data_type} data")
                    
                    # Implement AI analysis logic
                    pass
                else:
                    logger.warning(f"Unknown AI command: {command}")
            
            # Handle unknown targets
            else:
                logger.warning(f"Unknown command target: {target}")
        except Exception as e:
            logger.error(f"Failed to handle command: {str(e)}")
    
    def _handle_event(self, message: Dict[str, Any], source: str = "internal"):
        """
        Handle an event message.
        
        Args:
            message: Event message
            source: Source of the message
        """
        try:
            # Get event details
            event_type = message.get("event_type", "")
            event_source = message.get("source", "")
            severity = message.get("severity", "info")
            event_message = message.get("message", "")
            details = message.get("details", "")
            
            logger.info(f"Received {severity} event '{event_type}' from {event_source}: {event_message}")
            
            # Store event in database
            # This would typically call a database module
            
            # Forward event to other systems if needed
            if source != "cloud" and "cloud" in self.handlers:
                self._send_to_cloud(message)
        except Exception as e:
            logger.error(f"Failed to handle event: {str(e)}")
    
    def _handle_status(self, message: Dict[str, Any], source: str = "internal"):
        """
        Handle a status message.
        
        Args:
            message: Status message
            source: Source of the message
        """
        try:
            # Get status details
            status_source = message.get("source", "")
            status_data = message.get("data", {})
            
            logger.debug(f"Received status update from {status_source}")
            
            # Update status in database
            # This would typically call a database module
            
            # Forward status to other systems if needed
            if source != "cloud" and "cloud" in self.handlers:
                self._send_to_cloud(message)
        except Exception as e:
            logger.error(f"Failed to handle status: {str(e)}")
    
    def _handle_data(self, message: Dict[str, Any], source: str = "internal"):
        """
        Handle a data message.
        
        Args:
            message: Data message
            source: Source of the message
        """
        try:
            # Get data details
            data_type = message.get("data_type", "")
            data_source = message.get("source", "")
            data = message.get("data", {})
            
            logger.debug(f"Received {data_type} data from {data_source}")
            
            # Process data based on type
            if data_type == "sensor":
                # Process sensor data
                pass
            elif data_type == "analytics":
                # Process analytics data
                pass
            elif data_type == "metrics":
                # Process metrics data
                pass
            else:
                logger.debug(f"Unknown data type: {data_type}")
            
            # Store data in database
            # This would typically call a database module
            
            # Forward data to other systems if needed
            if source != "cloud" and "cloud" in self.handlers:
                self._send_to_cloud(message)
        except Exception as e:
            logger.error(f"Failed to handle data: {str(e)}")
    
    def _handle_config(self, message: Dict[str, Any], source: str = "internal"):
        """
        Handle a configuration message.
        
        Args:
            message: Configuration message
            source: Source of the message
        """
        try:
            # Get configuration details
            config_type = message.get("config_type", "")
            config_data = message.get("data", {})
            
            logger.info(f"Received {config_type} configuration update")
            
            # Update configuration based on type
            if config_type == "system":
                # Update system configuration
                pass
            elif config_type == "network":
                # Update network configuration
                pass
            elif config_type == "security":
                # Update security configuration
                pass
            elif config_type == "devices":
                # Update devices configuration
                pass
            elif config_type == "zones":
                # Update zones configuration
                pass
            elif config_type == "users":
                # Update users configuration
                pass
            else:
                logger.warning(f"Unknown configuration type: {config_type}")
        except Exception as e:
            logger.error(f"Failed to handle configuration: {str(e)}")
    
    def _handle_websocket_message(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Handle a WebSocket message.
        
        Args:
            message: WebSocket message
            
        Returns:
            Response message if needed, None otherwise
        """
        try:
            # Get message type
            message_type = message.get("type", "")
            
            # Handle based on message type
            if message_type == "command":
                # Add to incoming queue
                self.incoming_queue.put(message)
                
                # Return acknowledgement
                return {
                    "type": "ack",
                    "timestamp": int(time.time()),
                    "data": {
                        "message_id": message.get("id", ""),
                        "status": "received"
                    }
                }
            elif message_type == "ping":
                # Return pong
                return {
                    "type": "pong",
                    "timestamp": int(time.time()),
                    "data": {
                        "echo": message.get("data", {})
                    }
                }
            else:
                # Add to incoming queue
                self.incoming_queue.put(message)
                
                # Return acknowledgement
                return {
                    "type": "ack",
                    "timestamp": int(time.time()),
                    "data": {
                        "message_id": message.get("id", ""),
                        "status": "received"
                    }
                }
        except Exception as e:
            logger.error(f"Failed to handle WebSocket message: {str(e)}")
            
            # Return error
            return {
                "type": "error",
                "timestamp": int(time.time()),
                "data": {
                    "message": "Failed to process message",
                    "error": str(e)
                }
            }
    
    def _validate_auth_token(self, auth_header: str) -> bool:
        """
        Validate an authentication token.
        
        Args:
            auth_header: Authentication header
            
        Returns:
            True if valid, False otherwise
        """
        try:
            # Extract token
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
            else:
                token = auth_header
            
            # Validate token
            # This would typically call a user/auth module
            
            # For now, just return True
            return True
        except Exception as e:
            logger.error(f"Failed to validate auth token: {str(e)}")
            return False
    
    def _validate_websocket_auth(self, auth_data: Dict[str, Any]) -> bool:
        """
        Validate WebSocket authentication.
        
        Args:
            auth_data: Authentication data
            
        Returns:
            True if valid, False otherwise
        """
        try:
            # Extract token
            token = auth_data.get("token", "")
            
            # Validate token
            # This would typically call a user/auth module
            
            # For now, just return True
            return True
        except Exception as e:
            logger.error(f"Failed to validate WebSocket auth: {str(e)}")
            return False
    
    def _encrypt_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt a message.
        
        Args:
            message: Message to encrypt
            
        Returns:
            Encrypted message
        """
        try:
            # Get encryption configuration
            encryption_config = self.config.get("encryption", {})
            algorithm = encryption_config.get("algorithm", "AES-256-GCM")
            
            # For now, just mark as encrypted
            encrypted_message = {
                "encrypted": True,
                "algorithm": algorithm,
                "data": message
            }
            
            return encrypted_message
        except Exception as e:
            logger.error(f"Failed to encrypt message: {str(e)}")
            return message
    
    def _decrypt_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt a message.
        
        Args:
            message: Encrypted message
            
        Returns:
            Decrypted message
        """
        try:
            # Get encrypted data
            encrypted_data = message.get("data", {})
            
            # For now, just return the data
            return encrypted_data
        except Exception as e:
            logger.error(f"Failed to decrypt message: {str(e)}")
            return message
    
    def _get_system_status(self) -> Dict[str, Any]:
        """
        Get system status.
        
        Returns:
            System status
        """
        try:
            # Get system info
            system_info = self._get_system_info()
            
            # Get active handlers
            active_handlers = list(self.handlers.keys())
            
            # Get memory usage
            memory_usage = self._get_memory_usage()
            
            # Get CPU usage
            cpu_usage = self._get_cpu_usage()
            
            # Get disk usage
            disk_usage = self._get_disk_usage()
            
            # Get network status
            network_status = self._get_network_status()
            
            # Create status
            status = {
                "system": system_info,
                "active_handlers": active_handlers,
                "memory": memory_usage,
                "cpu": cpu_usage,
                "disk": disk_usage,
                "network": network_status,
                "timestamp": int(time.time())
            }
            
            return status
        except Exception as e:
            logger.error(f"Failed to get system status: {str(e)}")
            return {
                "error": str(e),
                "timestamp": int(time.time())
            }
    
    def _get_system_info(self) -> Dict[str, Any]:
        """
        Get system information.
        
        Returns:
            System information
        """
        try:
            # Get hostname
            hostname = socket.gethostname()
            
            # Get IP address
            ip_address = self._get_local_ip()
            
            # Get uptime
            uptime = self._get_uptime()
            
            # Create system info
            system_info = {
                "id": self._get_system_id(),
                "name": "Viztron Homebase",
                "version": "1.0.0",
                "hostname": hostname,
                "ip_address": ip_address,
                "uptime": uptime,
                "platform": sys.platform,
                "python_version": sys.version
            }
            
            return system_info
        except Exception as e:
            logger.error(f"Failed to get system info: {str(e)}")
            return {
                "error": str(e)
            }
    
    def _get_system_id(self) -> str:
        """
        Get system ID.
        
        Returns:
            System ID
        """
        try:
            # Check if ID file exists
            id_file = "/etc/viztron/system_id"
            
            if os.path.exists(id_file):
                # Read ID from file
                with open(id_file, 'r') as f:
                    return f.read().strip()
            else:
                # Generate new ID
                system_id = str(uuid.uuid4())
                
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(id_file), exist_ok=True)
                
                # Write ID to file
                with open(id_file, 'w') as f:
                    f.write(system_id)
                
                return system_id
        except Exception as e:
            logger.error(f"Failed to get system ID: {str(e)}")
            return str(uuid.uuid4())
    
    def _get_local_ip(self) -> str:
        """
        Get local IP address.
        
        Returns:
            Local IP address
        """
        try:
            # Create socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Connect to external server
            s.connect(("8.8.8.8", 80))
            
            # Get IP address
            ip_address = s.getsockname()[0]
            
            # Close socket
            s.close()
            
            return ip_address
        except Exception as e:
            logger.error(f"Failed to get local IP: {str(e)}")
            return "127.0.0.1"
    
    def _get_uptime(self) -> int:
        """
        Get system uptime in seconds.
        
        Returns:
            Uptime in seconds
        """
        try:
            # Read uptime from /proc/uptime
            with open("/proc/uptime", 'r') as f:
                uptime_seconds = float(f.readline().split()[0])
            
            return int(uptime_seconds)
        except Exception as e:
            logger.error(f"Failed to get uptime: {str(e)}")
            return 0
    
    def _get_memory_usage(self) -> Dict[str, Any]:
        """
        Get memory usage.
        
        Returns:
            Memory usage information
        """
        try:
            # Read memory info from /proc/meminfo
            mem_info = {}
            
            with open("/proc/meminfo", 'r') as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip()
                        
                        # Extract value and unit
                        if " " in value:
                            value_parts = value.split()
                            value = int(value_parts[0])
                            unit = value_parts[1]
                        else:
                            value = int(value)
                            unit = "kB"
                        
                        mem_info[key] = value
            
            # Calculate memory usage
            total = mem_info.get("MemTotal", 0)
            free = mem_info.get("MemFree", 0)
            buffers = mem_info.get("Buffers", 0)
            cached = mem_info.get("Cached", 0)
            
            used = total - free - buffers - cached
            usage_percent = (used / total) * 100 if total > 0 else 0
            
            # Create memory usage info
            memory_usage = {
                "total": total,
                "used": used,
                "free": free,
                "buffers": buffers,
                "cached": cached,
                "usage_percent": usage_percent
            }
            
            return memory_usage
        except Exception as e:
            logger.error(f"Failed to get memory usage: {str(e)}")
            return {
                "error": str(e)
            }
    
    def _get_cpu_usage(self) -> Dict[str, Any]:
        """
        Get CPU usage.
        
        Returns:
            CPU usage information
        """
        try:
            # Read CPU info from /proc/stat
            with open("/proc/stat", 'r') as f:
                cpu_line = f.readline()
            
            # Parse CPU line
            cpu_parts = cpu_line.split()
            
            # Calculate CPU usage
            user = int(cpu_parts[1])
            nice = int(cpu_parts[2])
            system = int(cpu_parts[3])
            idle = int(cpu_parts[4])
            iowait = int(cpu_parts[5])
            irq = int(cpu_parts[6])
            softirq = int(cpu_parts[7])
            
            total = user + nice + system + idle + iowait + irq + softirq
            used = total - idle - iowait
            
            usage_percent = (used / total) * 100 if total > 0 else 0
            
            # Create CPU usage info
            cpu_usage = {
                "user": user,
                "nice": nice,
                "system": system,
                "idle": idle,
                "iowait": iowait,
                "irq": irq,
                "softirq": softirq,
                "usage_percent": usage_percent
            }
            
            return cpu_usage
        except Exception as e:
            logger.error(f"Failed to get CPU usage: {str(e)}")
            return {
                "error": str(e)
            }
    
    def _get_disk_usage(self) -> Dict[str, Any]:
        """
        Get disk usage.
        
        Returns:
            Disk usage information
        """
        try:
            # Get disk usage for root partition
            total, used, free = shutil.disk_usage("/")
            
            # Calculate usage percentage
            usage_percent = (used / total) * 100 if total > 0 else 0
            
            # Create disk usage info
            disk_usage = {
                "total": total,
                "used": used,
                "free": free,
                "usage_percent": usage_percent
            }
            
            return disk_usage
        except Exception as e:
            logger.error(f"Failed to get disk usage: {str(e)}")
            return {
                "error": str(e)
            }
    
    def _get_network_status(self) -> Dict[str, Any]:
        """
        Get network status.
        
        Returns:
            Network status information
        """
        try:
            # Get network interfaces
            interfaces = {}
            
            # Read network info from /proc/net/dev
            with open("/proc/net/dev", 'r') as f:
                # Skip header lines
                f.readline()
                f.readline()
                
                # Parse interface lines
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        interface = parts[0].strip()
                        stats = parts[1].strip().split()
                        
                        # Create interface stats
                        interfaces[interface] = {
                            "rx_bytes": int(stats[0]),
                            "rx_packets": int(stats[1]),
                            "rx_errors": int(stats[2]),
                            "rx_dropped": int(stats[3]),
                            "tx_bytes": int(stats[8]),
                            "tx_packets": int(stats[9]),
                            "tx_errors": int(stats[10]),
                            "tx_dropped": int(stats[11])
                        }
            
            # Create network status info
            network_status = {
                "interfaces": interfaces,
                "ip_address": self._get_local_ip()
            }
            
            return network_status
        except Exception as e:
            logger.error(f"Failed to get network status: {str(e)}")
            return {
                "error": str(e)
            }
    
    def _get_devices(self) -> List[Dict[str, Any]]:
        """
        Get list of devices.
        
        Returns:
            List of devices
        """
        try:
            # This would typically call a device manager module
            # For now, return an empty list
            return []
        except Exception as e:
            logger.error(f"Failed to get devices: {str(e)}")
            return []
    
    def _get_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a device by ID.
        
        Args:
            device_id: Device ID
            
        Returns:
            Device information if found, None otherwise
        """
        try:
            # This would typically call a device manager module
            # For now, return None
            return None
        except Exception as e:
            logger.error(f"Failed to get device {device_id}: {str(e)}")
            return None
    
    def _get_zone(self, zone_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a zone by ID.
        
        Args:
            zone_id: Zone ID
            
        Returns:
            Zone information if found, None otherwise
        """
        try:
            # This would typically call a zone manager module
            # For now, return None
            return None
        except Exception as e:
            logger.error(f"Failed to get zone {zone_id}: {str(e)}")
            return None
    
    def _get_camera(self, camera_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a camera by ID.
        
        Args:
            camera_id: Camera ID
            
        Returns:
            Camera information if found, None otherwise
        """
        try:
            # This would typically call a camera manager module
            # For now, return None
            return None
        except Exception as e:
            logger.error(f"Failed to get camera {camera_id}: {str(e)}")
            return None
    
    def _get_events(self) -> List[Dict[str, Any]]:
        """
        Get list of events.
        
        Returns:
            List of events
        """
        try:
            # This would typically call a database module
            # For now, return an empty list
            return []
        except Exception as e:
            logger.error(f"Failed to get events: {str(e)}")
            return []
    
    def _get_ai_status(self) -> Dict[str, Any]:
        """
        Get AI status.
        
        Returns:
            AI status information
        """
        try:
            # This would typically call an AI manager module
            # For now, return a placeholder
            return {
                "status": "running",
                "models": [
                    {
                        "name": "object_detection",
                        "status": "running",
                        "version": "1.0.0"
                    },
                    {
                        "name": "face_recognition",
                        "status": "running",
                        "version": "1.0.0"
                    }
                ]
            }
        except Exception as e:
            logger.error(f"Failed to get AI status: {str(e)}")
            return {
                "error": str(e)
            }
    
    def _process_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a command.
        
        Args:
            command: Command to process
            
        Returns:
            Command result
        """
        try:
            # Add command to incoming queue
            self.incoming_queue.put({
                "type": "command",
                **command
            })
            
            # Return acknowledgement
            return {
                "status": "accepted",
                "message": "Command accepted for processing",
                "command_id": command.get("id", str(uuid.uuid4()))
            }
        except Exception as e:
            logger.error(f"Failed to process command: {str(e)}")
            return {
                "status": "error",
                "message": f"Failed to process command: {str(e)}",
                "command_id": command.get("id", "")
            }
    
    def _update_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update configuration.
        
        Args:
            config: Configuration to update
            
        Returns:
            Update result
        """
        try:
            # Add config to incoming queue
            self.incoming_queue.put({
                "type": "config",
                "data": config
            })
            
            # Return acknowledgement
            return {
                "status": "accepted",
                "message": "Configuration update accepted for processing"
            }
        except Exception as e:
            logger.error(f"Failed to update config: {str(e)}")
            return {
                "status": "error",
                "message": f"Failed to update configuration: {str(e)}"
            }
    
    def _sync_status_to_cloud(self, session: requests.Session, url: str):
        """
        Sync status to cloud.
        
        Args:
            session: Requests session
            url: Cloud API URL
        """
        try:
            # Get system status
            status = self._get_system_status()
            
            # Send status to cloud
            response = session.post(f"{url}/api/v1/status", json=status)
            response.raise_for_status()
            
            logger.debug("Synced status to cloud")
        except Exception as e:
            logger.error(f"Failed to sync status to cloud: {str(e)}")
    
    def _sync_events_to_cloud(self, session: requests.Session, url: str):
        """
        Sync events to cloud.
        
        Args:
            session: Requests session
            url: Cloud API URL
        """
        try:
            # Get events
            events = self._get_events()
            
            if not events:
                return
            
            # Send events to cloud
            response = session.post(f"{url}/api/v1/events/batch", json={"events": events})
            response.raise_for_status()
            
            logger.debug(f"Synced {len(events)} events to cloud")
        except Exception as e:
            logger.error(f"Failed to sync events to cloud: {str(e)}")
    
    def _sync_devices_to_cloud(self, session: requests.Session, url: str):
        """
        Sync devices to cloud.
        
        Args:
            session: Requests session
            url: Cloud API URL
        """
        try:
            # Get devices
            devices = self._get_devices()
            
            if not devices:
                return
            
            # Send devices to cloud
            response = session.post(f"{url}/api/v1/devices/batch", json={"devices": devices})
            response.raise_for_status()
            
            logger.debug(f"Synced {len(devices)} devices to cloud")
        except Exception as e:
            logger.error(f"Failed to sync devices to cloud: {str(e)}")
    
    def _check_cloud_commands(self, session: requests.Session, url: str):
        """
        Check for commands from cloud.
        
        Args:
            session: Requests session
            url: Cloud API URL
        """
        try:
            # Get commands
            response = session.get(f"{url}/api/v1/commands/pending")
            response.raise_for_status()
            
            # Parse response
            data = response.json()
            commands = data.get("commands", [])
            
            if not commands:
                return
            
            logger.debug(f"Received {len(commands)} commands from cloud")
            
            # Process commands
            for command in commands:
                # Add to incoming queue
                self.incoming_queue.put({
                    "type": "command",
                    "source": "cloud",
                    **command
                })
                
                # Mark command as received
                command_id = command.get("id", "")
                if command_id:
                    session.post(f"{url}/api/v1/commands/{command_id}/received")
        except Exception as e:
            logger.error(f"Failed to check cloud commands: {str(e)}")
    
    def _zigbee_device_joined(self, device):
        """
        Handle Zigbee device joined event.
        
        Args:
            device: Zigbee device
        """
        try:
            logger.info(f"Zigbee device joined: {device.ieee}")
            
            # Create message
            message = {
                "type": "event",
                "event_type": "device_joined",
                "source": "zigbee",
                "severity": "info",
                "timestamp": int(time.time()),
                "data": {
                    "ieee": str(device.ieee),
                    "nwk": device.nwk,
                    "manufacturer": device.manufacturer,
                    "model": device.model
                }
            }
            
            # Add to incoming queue
            self.incoming_queue.put(message)
        except Exception as e:
            logger.error(f"Failed to handle Zigbee device joined: {str(e)}")
    
    def _zigbee_device_left(self, device):
        """
        Handle Zigbee device left event.
        
        Args:
            device: Zigbee device
        """
        try:
            logger.info(f"Zigbee device left: {device.ieee}")
            
            # Create message
            message = {
                "type": "event",
                "event_type": "device_left",
                "source": "zigbee",
                "severity": "info",
                "timestamp": int(time.time()),
                "data": {
                    "ieee": str(device.ieee),
                    "nwk": device.nwk
                }
            }
            
            # Add to incoming queue
            self.incoming_queue.put(message)
        except Exception as e:
            logger.error(f"Failed to handle Zigbee device left: {str(e)}")
    
    def _zigbee_message_received(self, device, cluster, message):
        """
        Handle Zigbee message received event.
        
        Args:
            device: Zigbee device
            cluster: Zigbee cluster
            message: Zigbee message
        """
        try:
            logger.debug(f"Zigbee message received from {device.ieee}, cluster: {cluster}")
            
            # Create message
            event_message = {
                "type": "data",
                "data_type": "zigbee",
                "source": "zigbee",
                "timestamp": int(time.time()),
                "data": {
                    "ieee": str(device.ieee),
                    "nwk": device.nwk,
                    "cluster": cluster,
                    "message": str(message)
                }
            }
            
            # Add to incoming queue
            self.incoming_queue.put(event_message)
        except Exception as e:
            logger.error(f"Failed to handle Zigbee message: {str(e)}")
    
    def send_message(self, message_type: str, data: Dict[str, Any], destination: str = "all"):
        """
        Send a message.
        
        Args:
            message_type: Type of message
            data: Message data
            destination: Message destination
        """
        try:
            # Create message
            message = {
                "type": message_type,
                "timestamp": int(time.time()),
                "data": data,
                "destination": destination
            }
            
            # Add to outgoing queue
            self.outgoing_queue.put(message)
        except Exception as e:
            logger.error(f"Failed to send message: {str(e)}")
    
    def send_event(self, event_type: str, source: str, severity: str, message: str, details: Optional[str] = None):
        """
        Send an event.
        
        Args:
            event_type: Type of event
            source: Source of event
            severity: Severity of event
            message: Event message
            details: Additional details
        """
        try:
            # Create event
            event = {
                "type": "event",
                "event_type": event_type,
                "source": source,
                "severity": severity,
                "message": message,
                "details": details,
                "timestamp": int(time.time())
            }
            
            # Add to outgoing queue
            self.outgoing_queue.put(event)
        except Exception as e:
            logger.error(f"Failed to send event: {str(e)}")
    
    def send_status(self, source: str, status: Dict[str, Any]):
        """
        Send a status update.
        
        Args:
            source: Source of status
            status: Status data
        """
        try:
            # Create status message
            status_message = {
                "type": "status",
                "source": source,
                "data": status,
                "timestamp": int(time.time())
            }
            
            # Add to outgoing queue
            self.outgoing_queue.put(status_message)
        except Exception as e:
            logger.error(f"Failed to send status: {str(e)}")
    
    def send_command(self, command: str, target: str, params: Dict[str, Any] = None):
        """
        Send a command.
        
        Args:
            command: Command to send
            target: Target of command
            params: Command parameters
        """
        try:
            # Create command message
            command_message = {
                "type": "command",
                "command": command,
                "target": target,
                "params": params or {},
                "id": str(uuid.uuid4()),
                "timestamp": int(time.time())
            }
            
            # Add to outgoing queue
            self.outgoing_queue.put(command_message)
        except Exception as e:
            logger.error(f"Failed to send command: {str(e)}")
    
    def shutdown(self):
        """Perform a graceful shutdown of the communication manager."""
        logger.info("Shutting down communication manager")
        
        # Stop message processing
        self.running = False
        
        # Wait for threads to finish
        if hasattr(self, "outgoing_thread") and self.outgoing_thread:
            self.outgoing_thread.join(timeout=5.0)
        
        if hasattr(self, "incoming_thread") and self.incoming_thread:
            self.incoming_thread.join(timeout=5.0)
        
        # Shutdown handlers
        for handler_name, handler in list(self.handlers.items()):
            try:
                if handler_name == "http":
                    # Shutdown HTTP server
                    server = handler.get("server")
                    if server:
                        server.shutdown()
                elif handler_name == "mqtt":
                    # Disconnect MQTT client
                    client = handler.get("client")
                    if client:
                        # Publish offline status
                        mqtt_config = handler.get("config", {})
                        topics = mqtt_config.get("topics", {})
                        status_topic = topics.get("status", "viztron/homebase/status")
                        qos = mqtt_config.get("qos", 1)
                        
                        client.publish(
                            status_topic,
                            json.dumps({"status": "offline", "timestamp": int(time.time())}),
                            qos=qos,
                            retain=True
                        )
                        
                        client.disconnect()
                        client.loop_stop()
                elif handler_name == "websocket":
                    # Shutdown WebSocket server
                    server = handler.get("server")
                    loop = handler.get("loop")
                    if server and loop:
                        server.close()
                        loop.call_soon_threadsafe(loop.stop)
                elif handler_name == "zwave":
                    # Stop Z-Wave network
                    network = handler.get("network")
                    if network:
                        network.stop()
                elif handler_name == "discovery":
                    # Close discovery sockets
                    broadcast_socket = handler.get("broadcast_socket")
                    receive_socket = handler.get("receive_socket")
                    
                    if broadcast_socket:
                        broadcast_socket.close()
                    
                    if receive_socket:
                        receive_socket.close()
                
                logger.info(f"Shut down {handler_name} handler")
            except Exception as e:
                logger.error(f"Failed to shut down {handler_name} handler: {str(e)}")
        
        # Remove PID file
        try:
            pid_file = "/var/run/viztron/communication_manager.pid"
            if os.path.exists(pid_file):
                os.remove(pid_file)
        except Exception as e:
            logger.error(f"Failed to remove PID file: {str(e)}")
        
        logger.info("Communication manager shutdown complete")


# Example usage
if __name__ == "__main__":
    # Create communication manager
    comm_manager = CommunicationManager()
    
    try:
        # Send a test event
        comm_manager.send_event(
            event_type="system",
            source="communication_manager",
            severity="info",
            message="Communication manager started",
            details="This is a test event"
        )
        
        # Run for a while
        print("\nCommunication manager running. Press Ctrl+C to exit.")
        
        # Main loop
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        # Shutdown
        comm_manager.shutdown()
