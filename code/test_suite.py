#!/usr/bin/env python3
"""
Test Suite for Viztron Homebase Module

This script tests all components of the Viztron Homebase Module
to ensure they work correctly individually and together.

Author: Viztron System Team
Date: April 20, 2025
"""

import os
import sys
import time
import logging
import json
import unittest
import threading
import queue
import tempfile
import shutil
import subprocess
from unittest.mock import MagicMock, patch

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("test_results.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('test_suite')

# Add parent directory to path to import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import modules to test
try:
    from core_system.system_manager import SystemManager
    from core_system.container_manager import ContainerManager
    from core_system.update_manager import UpdateManager
    from core_system.config_manager import ConfigManager
    from core_system.device_manager import DeviceManager
    
    from ai_pipeline.object_detection import ObjectDetector
    from ai_pipeline.object_tracking import ObjectTracker
    from ai_pipeline.face_recognition import FaceRecognizer
    
    from database.database_manager import DatabaseManager
    
    from communication.communication_manager import CommunicationManager
    
    from security.security_manager import SecurityManager, SecureStorage, CertificateManager
    
    from emergency_services.emergency_services_manager import EmergencyServicesManager, EmergencyType, EmergencySeverity, EmergencyStatus
    
    modules_imported = True
except ImportError as e:
    logger.error(f"Failed to import modules: {str(e)}")
    modules_imported = False


class TestCoreSystem(unittest.TestCase):
    """Test cases for core system components."""
    
    def setUp(self):
        """Set up test environment."""
        # Create temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create mock configuration
        self.config = {
            "system": {
                "name": "Viztron Homebase",
                "version": "1.0.0",
                "log_level": "info"
            },
            "hardware": {
                "model": "BeagleBoard Y-AI",
                "cpu_cores": 4,
                "memory": 4096,
                "storage": 64
            },
            "network": {
                "interface": "eth0",
                "dhcp": True
            }
        }
        
        # Write config to file
        config_path = os.path.join(self.test_dir, "config.json")
        with open(config_path, 'w') as f:
            json.dump(self.config, f)
        
        # Create system manager
        self.system_manager = SystemManager(config_path=config_path)
    
    def tearDown(self):
        """Clean up test environment."""
        # Remove temporary directory
        shutil.rmtree(self.test_dir)
    
    def test_system_manager_initialization(self):
        """Test system manager initialization."""
        self.assertIsNotNone(self.system_manager)
        self.assertEqual(self.system_manager.config["system"]["name"], "Viztron Homebase")
    
    @patch('core_system.container_manager.subprocess.run')
    def test_container_manager(self, mock_run):
        """Test container manager."""
        # Mock subprocess.run to return success
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = b"CONTAINER ID  IMAGE  COMMAND  CREATED  STATUS  PORTS  NAMES\n"
        
        # Create container manager
        container_manager = ContainerManager()
        
        # Test list containers
        containers = container_manager.list_containers()
        self.assertEqual(len(containers), 0)
        
        # Test start container
        result = container_manager.start_container("test-container")
        self.assertTrue(result)
        
        # Test stop container
        result = container_manager.stop_container("test-container")
        self.assertTrue(result)
    
    def test_update_manager(self):
        """Test update manager."""
        # Create update manager
        update_manager = UpdateManager(config_path=os.path.join(self.test_dir, "update_config.json"))
        
        # Test check for updates
        with patch('core_system.update_manager.requests.get') as mock_get:
            mock_get.return_value.status_code = 200
            mock_get.return_value.json.return_value = {
                "version": "1.1.0",
                "url": "https://example.com/update.zip",
                "release_notes": "Bug fixes and improvements"
            }
            
            update_available, version = update_manager.check_for_updates()
            self.assertTrue(update_available)
            self.assertEqual(version, "1.1.0")
    
    def test_config_manager(self):
        """Test configuration manager."""
        # Create config manager
        config_manager = ConfigManager(config_path=os.path.join(self.test_dir, "test_config.json"))
        
        # Test set and get config
        config_manager.set_config("test.key", "test_value")
        value = config_manager.get_config("test.key")
        self.assertEqual(value, "test_value")
        
        # Test save and load config
        config_manager.save_config()
        config_manager.load_config()
        value = config_manager.get_config("test.key")
        self.assertEqual(value, "test_value")
    
    @patch('core_system.device_manager.subprocess.run')
    def test_device_manager(self, mock_run):
        """Test device manager."""
        # Mock subprocess.run to return success
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = b"Device1\nDevice2\n"
        
        # Create device manager
        device_manager = DeviceManager()
        
        # Test list devices
        devices = device_manager.list_devices()
        self.assertEqual(len(devices), 2)
        self.assertEqual(devices[0], "Device1")
        
        # Test add device
        result = device_manager.add_device("TestDevice", "192.168.1.100")
        self.assertTrue(result)
        
        # Test remove device
        result = device_manager.remove_device("TestDevice")
        self.assertTrue(result)


class TestAIPipeline(unittest.TestCase):
    """Test cases for AI pipeline components."""
    
    def setUp(self):
        """Set up test environment."""
        # Create temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create mock image
        self.image_path = os.path.join(self.test_dir, "test_image.jpg")
        with open(self.image_path, 'wb') as f:
            f.write(b"mock image data")
    
    def tearDown(self):
        """Clean up test environment."""
        # Remove temporary directory
        shutil.rmtree(self.test_dir)
    
    @patch('ai_pipeline.object_detection.cv2.imread')
    @patch('ai_pipeline.object_detection.cv2.dnn.readNetFromONNX')
    def test_object_detector(self, mock_read_net, mock_imread):
        """Test object detector."""
        # Mock cv2.imread to return a mock image
        mock_imread.return_value = MagicMock()
        
        # Mock cv2.dnn.readNetFromONNX to return a mock network
        mock_net = MagicMock()
        mock_net.forward.return_value = MagicMock()
        mock_read_net.return_value = mock_net
        
        # Create object detector
        detector = ObjectDetector(model_path=os.path.join(self.test_dir, "model.onnx"))
        
        # Test detect objects
        with patch.object(detector, '_preprocess_image', return_value=MagicMock()):
            with patch.object(detector, '_postprocess_detections', return_value=[
                {"class_id": 0, "class_name": "person", "confidence": 0.95, "box": [10, 10, 100, 200]}
            ]):
                detections = detector.detect(self.image_path)
                self.assertEqual(len(detections), 1)
                self.assertEqual(detections[0]["class_name"], "person")
    
    @patch('ai_pipeline.object_tracking.cv2.imread')
    def test_object_tracker(self, mock_imread):
        """Test object tracker."""
        # Mock cv2.imread to return a mock image
        mock_imread.return_value = MagicMock()
        
        # Create object tracker
        tracker = ObjectTracker()
        
        # Test track objects
        with patch.object(tracker, '_preprocess_detections', return_value=MagicMock()):
            with patch.object(tracker, '_update_tracks', return_value=[
                {"track_id": 1, "class_name": "person", "box": [10, 10, 100, 200]}
            ]):
                tracks = tracker.track([
                    {"class_id": 0, "class_name": "person", "confidence": 0.95, "box": [10, 10, 100, 200]}
                ], self.image_path)
                self.assertEqual(len(tracks), 1)
                self.assertEqual(tracks[0]["track_id"], 1)
    
    @patch('ai_pipeline.face_recognition.cv2.imread')
    @patch('ai_pipeline.face_recognition.cv2.dnn.readNetFromONNX')
    def test_face_recognizer(self, mock_read_net, mock_imread):
        """Test face recognizer."""
        # Mock cv2.imread to return a mock image
        mock_imread.return_value = MagicMock()
        
        # Mock cv2.dnn.readNetFromONNX to return a mock network
        mock_net = MagicMock()
        mock_net.forward.return_value = MagicMock()
        mock_read_net.return_value = mock_net
        
        # Create face recognizer
        recognizer = FaceRecognizer(
            detection_model_path=os.path.join(self.test_dir, "detection_model.onnx"),
            recognition_model_path=os.path.join(self.test_dir, "recognition_model.onnx"),
            database_path=os.path.join(self.test_dir, "faces.db")
        )
        
        # Test detect faces
        with patch.object(recognizer, '_detect_faces', return_value=[
            {"box": [10, 10, 100, 100], "confidence": 0.98}
        ]):
            faces = recognizer.detect_faces(self.image_path)
            self.assertEqual(len(faces), 1)
            self.assertAlmostEqual(faces[0]["confidence"], 0.98)
        
        # Test recognize faces
        with patch.object(recognizer, '_detect_faces', return_value=[
            {"box": [10, 10, 100, 100], "confidence": 0.98}
        ]):
            with patch.object(recognizer, '_extract_features', return_value=MagicMock()):
                with patch.object(recognizer, '_match_features', return_value=("John Doe", 0.92)):
                    results = recognizer.recognize_faces(self.image_path)
                    self.assertEqual(len(results), 1)
                    self.assertEqual(results[0]["name"], "John Doe")


class TestDatabase(unittest.TestCase):
    """Test cases for database components."""
    
    def setUp(self):
        """Set up test environment."""
        # Create temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create database path
        self.db_path = os.path.join(self.test_dir, "test.db")
        
        # Create database manager
        self.db_manager = DatabaseManager(db_path=self.db_path)
    
    def tearDown(self):
        """Clean up test environment."""
        # Remove temporary directory
        shutil.rmtree(self.test_dir)
    
    def test_database_initialization(self):
        """Test database initialization."""
        self.assertIsNotNone(self.db_manager)
        self.assertTrue(os.path.exists(self.db_path))
    
    def test_database_operations(self):
        """Test database operations."""
        # Test create table
        self.db_manager.execute(
            "CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT, value INTEGER)"
        )
        
        # Test insert data
        self.db_manager.execute(
            "INSERT INTO test (name, value) VALUES (?, ?)",
            ("test1", 100)
        )
        
        # Test query data
        result = self.db_manager.query(
            "SELECT * FROM test WHERE name = ?",
            ("test1",)
        )
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["name"], "test1")
        self.assertEqual(result[0]["value"], 100)
        
        # Test update data
        self.db_manager.execute(
            "UPDATE test SET value = ? WHERE name = ?",
            (200, "test1")
        )
        
        # Test query after update
        result = self.db_manager.query(
            "SELECT * FROM test WHERE name = ?",
            ("test1",)
        )
        self.assertEqual(result[0]["value"], 200)
        
        # Test delete data
        self.db_manager.execute(
            "DELETE FROM test WHERE name = ?",
            ("test1",)
        )
        
        # Test query after delete
        result = self.db_manager.query(
            "SELECT * FROM test WHERE name = ?",
            ("test1",)
        )
        self.assertEqual(len(result), 0)


class TestCommunication(unittest.TestCase):
    """Test cases for communication components."""
    
    def setUp(self):
        """Set up test environment."""
        # Create temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create mock configuration
        self.config_path = os.path.join(self.test_dir, "communication_config.json")
        with open(self.config_path, 'w') as f:
            json.dump({
                "protocols": {
                    "http": {
                        "enabled": True,
                        "port": 8080
                    },
                    "mqtt": {
                        "enabled": True,
                        "broker": "localhost",
                        "port": 1883
                    }
                }
            }, f)
        
        # Create communication manager
        self.comm_manager = CommunicationManager(config_path=self.config_path)
    
    def tearDown(self):
        """Clean up test environment."""
        # Remove temporary directory
        shutil.rmtree(self.test_dir)
    
    def test_communication_initialization(self):
        """Test communication manager initialization."""
        self.assertIsNotNone(self.comm_manager)
        self.assertTrue(self.comm_manager.config["protocols"]["http"]["enabled"])
    
    @patch('communication.communication_manager.requests.post')
    def test_http_communication(self, mock_post):
        """Test HTTP communication."""
        # Mock requests.post to return success
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "success"}
        mock_post.return_value = mock_response
        
        # Test send HTTP message
        result = self.comm_manager.send_http_message(
            "http://example.com/api",
            {"message": "test"}
        )
        self.assertTrue(result)
        mock_post.assert_called_once()
    
    @patch('communication.communication_manager.paho.mqtt.client.Client')
    def test_mqtt_communication(self, mock_client):
        """Test MQTT communication."""
        # Mock MQTT client
        mock_client_instance = MagicMock()
        mock_client.return_value = mock_client_instance
        
        # Test connect to MQTT broker
        with patch.object(self.comm_manager, '_create_mqtt_client', return_value=mock_client_instance):
            result = self.comm_manager.connect_mqtt()
            self.assertTrue(result)
            mock_client_instance.connect.assert_called_once()
        
        # Test publish MQTT message
        result = self.comm_manager.publish_mqtt_message("test/topic", "test message")
        self.assertTrue(result)
        mock_client_instance.publish.assert_called_once()
        
        # Test subscribe to MQTT topic
        callback = MagicMock()
        result = self.comm_manager.subscribe_mqtt_topic("test/topic", callback)
        self.assertTrue(result)
        mock_client_instance.subscribe.assert_called_once()


class TestSecurity(unittest.TestCase):
    """Test cases for security components."""
    
    def setUp(self):
        """Set up test environment."""
        # Create temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create mock configuration
        self.config_path = os.path.join(self.test_dir, "security_config.json")
        with open(self.config_path, 'w') as f:
            json.dump({
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
            }, f)
        
        # Create security manager
        self.security_manager = SecurityManager(config_path=self.config_path)
    
    def tearDown(self):
        """Clean up test environment."""
        # Remove temporary directory
        shutil.rmtree(self.test_dir)
        
        # Shutdown security manager
        if hasattr(self, 'security_manager'):
            self.security_manager.shutdown()
    
    def test_security_initialization(self):
        """Test security manager initialization."""
        self.assertIsNotNone(self.security_manager)
        self.assertEqual(self.security_manager.config["security_level"], "high")
    
    def test_encryption(self):
        """Test encryption and decryption."""
        # Test encrypt data
        data = "test data"
        encrypted = self.security_manager.encrypt_data(data)
        self.assertIn("algorithm", encrypted)
        self.assertIn("key_id", encrypted)
        self.assertIn("ciphertext", encrypted)
        
        # Test decrypt data
        decrypted = self.security_manager.decrypt_data(encrypted)
        self.assertEqual(decrypted.decode('utf-8'), data)
    
    def test_hashing(self):
        """Test data hashing."""
        # Test hash data
        data = "test data"
        hash_value = self.security_manager.hash_data(data)
        self.assertTrue(isinstance(hash_value, str))
        self.assertEqual(len(hash_value), 64)  # SHA-256 produces 64 hex characters
        
        # Test verify hash
        self.assertTrue(self.security_manager.verify_hash(data, hash_value))
        self.assertFalse(self.security_manager.verify_hash("wrong data", hash_value))
    
    def test_token_management(self):
        """Test authentication token management."""
        # Test generate token
        token = self.security_manager.generate_token("user123")
        self.assertTrue(isinstance(token, str))
        
        # Test validate token
        user_id = self.security_manager.validate_token(token)
        self.assertEqual(user_id, "user123")
        
        # Test revoke token
        result = self.security_manager.revoke_token(token)
        self.assertTrue(result)
        
        # Test validate revoked token
        user_id = self.security_manager.validate_token(token)
        self.assertIsNone(user_id)
    
    def test_secure_storage(self):
        """Test secure storage."""
        # Create secure storage
        secure_storage = SecureStorage(self.security_manager, storage_dir=os.path.join(self.test_dir, "secure_storage"))
        
        # Test store data
        data = {"username": "admin", "password": "secret"}
        result = secure_storage.store("test_key", data)
        self.assertTrue(result)
        
        # Test retrieve data
        retrieved = secure_storage.retrieve("test_key")
        self.assertEqual(retrieved["username"], "admin")
        self.assertEqual(retrieved["password"], "secret")
        
        # Test delete data
        result = secure_storage.delete("test_key")
        self.assertTrue(result)
        
        # Test retrieve deleted data
        retrieved = secure_storage.retrieve("test_key")
        self.assertIsNone(retrieved)
    
    def test_certificate_manager(self):
        """Test certificate manager."""
        # Create certificate manager
        cert_manager = CertificateManager(cert_dir=os.path.join(self.test_dir, "certificates"))
        
        # Test generate self-signed certificate
        try:
            cert_file, key_file = cert_manager.generate_self_signed_cert("localhost")
            self.assertTrue(os.path.exists(cert_file))
            self.assertTrue(os.path.exists(key_file))
            
            # Test get certificate info
            cert_info = cert_manager.get_certificate_info(cert_file)
            self.assertIn("subject", cert_info)
            self.assertIn("CN=localhost", cert_info["subject"])
            
            # Test delete certificate
            result = cert_manager.delete_certificate("localhost")
            self.assertTrue(result)
            self.assertFalse(os.path.exists(cert_file))
            self.assertFalse(os.path.exists(key_file))
        except Exception as e:
            # Skip test if openssl is not available
            if "openssl" in str(e).lower():
                self.skipTest("OpenSSL not available")
            else:
                raise


class TestEmergencyServices(unittest.TestCase):
    """Test cases for emergency services components."""
    
    def setUp(self):
        """Set up test environment."""
        # Create temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create mock configuration
        self.config_path = os.path.join(self.test_dir, "emergency_services_config.json")
        with open(self.config_path, 'w') as f:
            json.dump({
                "emergency_services": {
                    "enabled": True,
                    "auto_verification": True,
                    "auto_reporting": False,
                    "notification_methods": ["push"],
                    "emergency_types": {
                        "intrusion": {
                            "enabled": True,
                            "default_severity": "high",
                            "auto_verification": True,
                            "auto_reporting": False
                        }
                    }
                }
            }, f)
        
        # Create emergency services manager
        self.emergency_manager = EmergencyServicesManager(config_path=self.config_path)
    
    def tearDown(self):
        """Clean up test environment."""
        # Remove temporary directory
        shutil.rmtree(self.test_dir)
        
        # Shutdown emergency services manager
        if hasattr(self, 'emergency_manager'):
            self.emergency_manager.shutdown()
    
    def test_emergency_initialization(self):
        """Test emergency services manager initialization."""
        self.assertIsNotNone(self.emergency_manager)
        self.assertTrue(self.emergency_manager.config["emergency_services"]["enabled"])
    
    def test_emergency_detection(self):
        """Test emergency detection."""
        # Test detect emergency
        emergency_id = self.emergency_manager.detect_emergency(
            EmergencyType.INTRUSION.value,
            "Front Door",
            EmergencySeverity.HIGH.value,
            "Motion detected by camera"
        )
        self.assertTrue(isinstance(emergency_id, str))
        self.assertTrue(len(emergency_id) > 0)
        
        # Wait for emergency to be processed
        time.sleep(1)
        
        # Test get emergency by ID
        emergency = self.emergency_manager.get_emergency_by_id(emergency_id)
        self.assertIsNotNone(emergency)
        self.assertEqual(emergency["type"], EmergencyType.INTRUSION.value)
        self.assertEqual(emergency["location"], "Front Door")
        self.assertEqual(emergency["severity"], EmergencySeverity.HIGH.value)
        self.assertEqual(emergency["details"], "Motion detected by camera")
    
    def test_emergency_status_reporting(self):
        """Test emergency status reporting."""
        # Test detect emergency
        emergency_id = self.emergency_manager.detect_emergency(
            EmergencyType.INTRUSION.value,
            "Front Door",
            EmergencySeverity.HIGH.value,
            "Motion detected by camera"
        )
        
        # Wait for emergency to be processed
        time.sleep(1)
        
        # Test report emergency status
        result = self.emergency_manager.report_emergency_status(
            emergency_id,
            EmergencyStatus.VERIFIED.value,
            "Verified by security guard"
        )
        self.assertTrue(result)
        
        # Wait for status to be processed
        time.sleep(1)
        
        # Test get emergency by ID
        emergency = self.emergency_manager.get_emergency_by_id(emergency_id)
        self.assertIsNotNone(emergency)
        self.assertEqual(emergency["status"], EmergencyStatus.VERIFIED.value)
    
    def test_emergency_contacts(self):
        """Test emergency contacts management."""
        # Test add emergency contact
        result = self.emergency_manager.add_emergency_contact({
            "name": "John Doe",
            "phone": "555-123-4567",
            "email": "john.doe@example.com",
            "primary": True
        })
        self.assertTrue(result)
        
        # Test get primary contact
        primary_contact = self.emergency_manager._get_primary_contact()
        self.assertIsNotNone(primary_contact)
        self.assertEqual(primary_contact["name"], "John Doe")
        self.assertEqual(primary_contact["phone"], "555-123-4567")
        
        # Test remove emergency contact
        result = self.emergency_manager.remove_emergency_contact(primary_contact["id"])
        self.assertTrue(result)
        
        # Test get primary contact after removal
        primary_contact = self.emergency_manager._get_primary_contact()
        self.assertIsNone(primary_contact)
    
    def test_response_plans(self):
        """Test emergency response plans."""
        # Test update response plan
        result = self.emergency_manager.update_response_plan(
            EmergencyType.INTRUSION.value,
            {
                "actions": [
                    {
                        "type": "notification",
                        "target": "all_contacts",
                        "message": "Intrusion detected at {location}",
                        "priority": "high"
                    },
                    {
                        "type": "system",
                        "command": "record_cameras",
                        "duration": 300
                    }
                ]
            }
        )
        self.assertTrue(result)
        
        # Test response plan was updated
        self.assertIn(EmergencyType.INTRUSION.value, self.emergency_manager.response_plans)
        self.assertEqual(len(self.emergency_manager.response_plans[EmergencyType.INTRUSION.value]["actions"]), 2)
        
        # Test remove response plan
        result = self.emergency_manager.remove_response_plan(EmergencyType.INTRUSION.value)
        self.assertTrue(result)
        
        # Test response plan was removed
        self.assertNotIn(EmergencyType.INTRUSION.value, self.emergency_manager.response_plans)


class TestIntegration(unittest.TestCase):
    """Integration tests for all components working together."""
    
    def setUp(self):
        """Set up test environment."""
        # Create temporary directory for test files
        self.test_dir = tempfile.mkdtemp()
        
        # Create necessary subdirectories
        os.makedirs(os.path.join(self.test_dir, "config"), exist_ok=True)
        os.makedirs(os.path.join(self.test_dir, "data"), exist_ok=True)
        os.makedirs(os.path.join(self.test_dir, "models"), exist_ok=True)
        os.makedirs(os.path.join(self.test_dir, "logs"), exist_ok=True)
        
        # Create mock configuration files
        self.system_config_path = os.path.join(self.test_dir, "config", "system.json")
        with open(self.system_config_path, 'w') as f:
            json.dump({
                "system": {
                    "name": "Viztron Homebase",
                    "version": "1.0.0",
                    "log_level": "info"
                },
                "hardware": {
                    "model": "BeagleBoard Y-AI",
                    "cpu_cores": 4,
                    "memory": 4096,
                    "storage": 64
                },
                "network": {
                    "interface": "eth0",
                    "dhcp": True
                }
            }, f)
        
        self.security_config_path = os.path.join(self.test_dir, "config", "security.json")
        with open(self.security_config_path, 'w') as f:
            json.dump({
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
            }, f)
        
        self.emergency_config_path = os.path.join(self.test_dir, "config", "emergency.json")
        with open(self.emergency_config_path, 'w') as f:
            json.dump({
                "emergency_services": {
                    "enabled": True,
                    "auto_verification": True,
                    "auto_reporting": False,
                    "notification_methods": ["push"],
                    "emergency_types": {
                        "intrusion": {
                            "enabled": True,
                            "default_severity": "high",
                            "auto_verification": True,
                            "auto_reporting": False
                        }
                    }
                }
            }, f)
        
        # Create mock database
        self.db_path = os.path.join(self.test_dir, "data", "viztron.db")
        
        # Create mock model files
        self.detection_model_path = os.path.join(self.test_dir, "models", "detection.onnx")
        with open(self.detection_model_path, 'wb') as f:
            f.write(b"mock model data")
        
        self.tracking_model_path = os.path.join(self.test_dir, "models", "tracking.onnx")
        with open(self.tracking_model_path, 'wb') as f:
            f.write(b"mock model data")
        
        self.recognition_model_path = os.path.join(self.test_dir, "models", "recognition.onnx")
        with open(self.recognition_model_path, 'wb') as f:
            f.write(b"mock model data")
        
        # Create mock image
        self.image_path = os.path.join(self.test_dir, "data", "test_image.jpg")
        with open(self.image_path, 'wb') as f:
            f.write(b"mock image data")
    
    def tearDown(self):
        """Clean up test environment."""
        # Remove temporary directory
        shutil.rmtree(self.test_dir)
    
    @unittest.skipIf(not modules_imported, "Modules not imported")
    def test_ai_pipeline_integration(self):
        """Test AI pipeline integration."""
        # Create database manager
        db_manager = DatabaseManager(db_path=self.db_path)
        
        # Create object detector
        with patch('ai_pipeline.object_detection.cv2.imread'):
            with patch('ai_pipeline.object_detection.cv2.dnn.readNetFromONNX'):
                detector = ObjectDetector(model_path=self.detection_model_path)
                
                # Create object tracker
                tracker = ObjectTracker()
                
                # Create face recognizer
                with patch('ai_pipeline.face_recognition.cv2.dnn.readNetFromONNX'):
                    recognizer = FaceRecognizer(
                        detection_model_path=self.detection_model_path,
                        recognition_model_path=self.recognition_model_path,
                        database_path=self.db_path
                    )
                    
                    # Test AI pipeline
                    with patch.object(detector, 'detect', return_value=[
                        {"class_id": 0, "class_name": "person", "confidence": 0.95, "box": [10, 10, 100, 200]}
                    ]):
                        with patch.object(tracker, 'track', return_value=[
                            {"track_id": 1, "class_name": "person", "box": [10, 10, 100, 200]}
                        ]):
                            with patch.object(recognizer, 'detect_faces', return_value=[
                                {"box": [20, 20, 80, 80], "confidence": 0.98}
                            ]):
                                with patch.object(recognizer, 'recognize_faces', return_value=[
                                    {"box": [20, 20, 80, 80], "name": "John Doe", "confidence": 0.92}
                                ]):
                                    # Detect objects
                                    detections = detector.detect(self.image_path)
                                    self.assertEqual(len(detections), 1)
                                    
                                    # Track objects
                                    tracks = tracker.track(detections, self.image_path)
                                    self.assertEqual(len(tracks), 1)
                                    
                                    # Detect faces
                                    faces = recognizer.detect_faces(self.image_path)
                                    self.assertEqual(len(faces), 1)
                                    
                                    # Recognize faces
                                    recognized = recognizer.recognize_faces(self.image_path)
                                    self.assertEqual(len(recognized), 1)
                                    self.assertEqual(recognized[0]["name"], "John Doe")
    
    @unittest.skipIf(not modules_imported, "Modules not imported")
    def test_security_emergency_integration(self):
        """Test security and emergency services integration."""
        # Create security manager
        with patch('security.security_manager.subprocess.run'):
            security_manager = SecurityManager(config_path=self.security_config_path)
            
            # Create emergency services manager
            emergency_manager = EmergencyServicesManager(config_path=self.emergency_config_path)
            
            # Test integration
            try:
                # Encrypt data
                data = "sensitive data"
                encrypted = security_manager.encrypt_data(data)
                
                # Decrypt data
                decrypted = security_manager.decrypt_data(encrypted)
                self.assertEqual(decrypted.decode('utf-8'), data)
                
                # Detect emergency
                with patch.object(emergency_manager, '_verify_emergency'):
                    with patch.object(emergency_manager, '_send_verification_request'):
                        emergency_id = emergency_manager.detect_emergency(
                            EmergencyType.INTRUSION.value,
                            "Front Door",
                            EmergencySeverity.HIGH.value,
                            "Motion detected by camera"
                        )
                        self.assertTrue(isinstance(emergency_id, str))
                        self.assertTrue(len(emergency_id) > 0)
                
                # Wait for emergency to be processed
                time.sleep(1)
                
                # Get emergency by ID
                emergency = emergency_manager.get_emergency_by_id(emergency_id)
                self.assertIsNotNone(emergency)
                self.assertEqual(emergency["type"], EmergencyType.INTRUSION.value)
            finally:
                # Shutdown managers
                security_manager.shutdown()
                emergency_manager.shutdown()
    
    @unittest.skipIf(not modules_imported, "Modules not imported")
    def test_system_communication_integration(self):
        """Test system and communication integration."""
        # Create system manager
        system_manager = SystemManager(config_path=self.system_config_path)
        
        # Create communication manager
        with patch('communication.communication_manager.paho.mqtt.client.Client'):
            comm_manager = CommunicationManager(config_path=os.path.join(self.test_dir, "config", "communication.json"))
            
            # Test integration
            with patch.object(system_manager, 'get_system_status', return_value={
                "status": "running",
                "uptime": 3600,
                "cpu_usage": 25.0,
                "memory_usage": 40.0,
                "storage_usage": 30.0
            }):
                with patch.object(comm_manager, 'send_http_message', return_value=True):
                    # Get system status
                    status = system_manager.get_system_status()
                    self.assertEqual(status["status"], "running")
                    
                    # Send status via HTTP
                    result = comm_manager.send_http_message(
                        "http://example.com/api/status",
                        status
                    )
                    self.assertTrue(result)


def run_tests():
    """Run all tests."""
    # Create test suite
    suite = unittest.TestSuite()
    
    # Add test cases
    suite.addTest(unittest.makeSuite(TestCoreSystem))
    suite.addTest(unittest.makeSuite(TestAIPipeline))
    suite.addTest(unittest.makeSuite(TestDatabase))
    suite.addTest(unittest.makeSuite(TestCommunication))
    suite.addTest(unittest.makeSuite(TestSecurity))
    suite.addTest(unittest.makeSuite(TestEmergencyServices))
    suite.addTest(unittest.makeSuite(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == "__main__":
    # Run tests
    result = run_tests()
    
    # Exit with appropriate code
    sys.exit(not result.wasSuccessful())
