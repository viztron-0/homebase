#!/usr/bin/env python3
"""
Database Manager for Viztron Homebase Module

This module implements the database functionality for the
Viztron Homebase Module, handling data storage, retrieval,
and management.

Author: Viztron System Team
Date: April 20, 2025
"""

import os
import sys
import time
import logging
import json
import sqlite3
import threading
import queue
from typing import Dict, List, Any, Optional, Tuple, Set, Union, Callable
from datetime import datetime, timedelta
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/viztron/database_manager.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('database_manager')

class DatabaseManager:
    """
    Main database manager for the Viztron Homebase Module.
    
    This class provides a unified interface for database operations,
    including data storage, retrieval, and management.
    """
    
    def __init__(self, db_path: str = "/var/lib/viztron/database/viztron.db", config_path: str = "/etc/viztron/database_config.json"):
        """
        Initialize the database manager.
        
        Args:
            db_path: Path to the SQLite database file
            config_path: Path to the database configuration file
        """
        self.db_path = db_path
        self.config_path = config_path
        self.config = self._load_config()
        
        # Create required directories
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        os.makedirs("/var/log/viztron", exist_ok=True)
        
        # Initialize database
        self.conn = None
        self.lock = threading.RLock()
        self._initialize_database()
        
        # Create PID file
        self._create_pid_file()
        
        logger.info("Database manager initialized")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load database configuration from file."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                return {
                    "database": {
                        "backup_interval": 86400,  # 24 hours
                        "backup_count": 7,
                        "vacuum_interval": 604800,  # 7 days
                        "journal_mode": "WAL",
                        "synchronous": "NORMAL",
                        "temp_store": "MEMORY",
                        "cache_size": 2000,  # pages
                        "page_size": 4096,  # bytes
                        "max_connections": 10
                    }
                }
        except Exception as e:
            logger.error(f"Failed to load database config: {str(e)}")
            return {
                "database": {
                    "backup_interval": 86400,
                    "backup_count": 7
                }
            }
    
    def _save_config(self):
        """Save database configuration to file."""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save database config: {str(e)}")
    
    def _create_pid_file(self):
        """Create PID file for the database manager."""
        try:
            pid = os.getpid()
            pid_dir = "/var/run/viztron"
            os.makedirs(pid_dir, exist_ok=True)
            
            with open(f"{pid_dir}/database_manager.pid", 'w') as f:
                f.write(str(pid))
            
            logger.debug(f"Created PID file with PID {pid}")
        except Exception as e:
            logger.error(f"Failed to create PID file: {str(e)}")
    
    def _initialize_database(self):
        """Initialize the database."""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            # Connect to database
            self.conn = self._get_connection()
            
            # Set pragmas
            self._set_pragmas()
            
            # Create tables
            self._create_tables()
            
            logger.info("Database initialized")
        except Exception as e:
            logger.error(f"Failed to initialize database: {str(e)}")
            raise
    
    def _get_connection(self) -> sqlite3.Connection:
        """
        Get a database connection.
        
        Returns:
            SQLite connection
        """
        try:
            # Create connection
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            
            # Enable row factory
            conn.row_factory = self._dict_factory
            
            return conn
        except Exception as e:
            logger.error(f"Failed to get database connection: {str(e)}")
            raise
    
    def _dict_factory(self, cursor: sqlite3.Cursor, row: Tuple) -> Dict[str, Any]:
        """
        Convert row to dictionary.
        
        Args:
            cursor: SQLite cursor
            row: Row tuple
            
        Returns:
            Row as dictionary
        """
        return {col[0]: row[idx] for idx, col in enumerate(cursor.description)}
    
    def _set_pragmas(self):
        """Set database pragmas."""
        try:
            # Get pragmas from config
            journal_mode = self.config.get("database", {}).get("journal_mode", "WAL")
            synchronous = self.config.get("database", {}).get("synchronous", "NORMAL")
            temp_store = self.config.get("database", {}).get("temp_store", "MEMORY")
            cache_size = self.config.get("database", {}).get("cache_size", 2000)
            page_size = self.config.get("database", {}).get("page_size", 4096)
            
            # Set pragmas
            with self.lock:
                self.conn.execute(f"PRAGMA journal_mode = {journal_mode}")
                self.conn.execute(f"PRAGMA synchronous = {synchronous}")
                self.conn.execute(f"PRAGMA temp_store = {temp_store}")
                self.conn.execute(f"PRAGMA cache_size = {cache_size}")
                self.conn.execute(f"PRAGMA page_size = {page_size}")
                self.conn.execute("PRAGMA foreign_keys = ON")
        except Exception as e:
            logger.error(f"Failed to set database pragmas: {str(e)}")
    
    def _create_tables(self):
        """Create database tables."""
        try:
            # Create users table
            self.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT,
                    phone TEXT,
                    role TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    password_salt TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    last_login INTEGER,
                    status TEXT NOT NULL
                )
            """)
            
            # Create devices table
            self.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    location TEXT,
                    ip_address TEXT,
                    mac_address TEXT,
                    status TEXT NOT NULL,
                    last_seen INTEGER,
                    firmware_version TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
            """)
            
            # Create cameras table
            self.execute("""
                CREATE TABLE IF NOT EXISTS cameras (
                    id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    location TEXT,
                    resolution TEXT,
                    fps INTEGER,
                    status TEXT NOT NULL,
                    last_seen INTEGER,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
                )
            """)
            
            # Create zones table
            self.execute("""
                CREATE TABLE IF NOT EXISTS zones (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
            """)
            
            # Create zone_devices table
            self.execute("""
                CREATE TABLE IF NOT EXISTS zone_devices (
                    zone_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (zone_id, device_id),
                    FOREIGN KEY (zone_id) REFERENCES zones (id) ON DELETE CASCADE,
                    FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
                )
            """)
            
            # Create events table
            self.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    details TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
            """)
            
            # Create alerts table
            self.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    details TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE
                )
            """)
            
            # Create faces table
            self.execute("""
                CREATE TABLE IF NOT EXISTS faces (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    features BLOB NOT NULL,
                    user_id TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
                )
            """)
            
            # Create face_images table
            self.execute("""
                CREATE TABLE IF NOT EXISTS face_images (
                    id TEXT PRIMARY KEY,
                    face_id TEXT NOT NULL,
                    image_path TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (face_id) REFERENCES faces (id) ON DELETE CASCADE
                )
            """)
            
            # Create detections table
            self.execute("""
                CREATE TABLE IF NOT EXISTS detections (
                    id TEXT PRIMARY KEY,
                    camera_id TEXT NOT NULL,
                    class_id INTEGER NOT NULL,
                    class_name TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    box_x INTEGER NOT NULL,
                    box_y INTEGER NOT NULL,
                    box_width INTEGER NOT NULL,
                    box_height INTEGER NOT NULL,
                    image_path TEXT,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (camera_id) REFERENCES cameras (id) ON DELETE CASCADE
                )
            """)
            
            # Create tracks table
            self.execute("""
                CREATE TABLE IF NOT EXISTS tracks (
                    id TEXT PRIMARY KEY,
                    track_id INTEGER NOT NULL,
                    camera_id TEXT NOT NULL,
                    class_id INTEGER NOT NULL,
                    class_name TEXT NOT NULL,
                    box_x INTEGER NOT NULL,
                    box_y INTEGER NOT NULL,
                    box_width INTEGER NOT NULL,
                    box_height INTEGER NOT NULL,
                    face_id TEXT,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (camera_id) REFERENCES cameras (id) ON DELETE CASCADE,
                    FOREIGN KEY (face_id) REFERENCES faces (id) ON DELETE SET NULL
                )
            """)
            
            # Create logs table
            self.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    level TEXT NOT NULL,
                    source TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                )
            """)
            
            # Create settings table
            self.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
            """)
            
            # Create schedules table
            self.execute("""
                CREATE TABLE IF NOT EXISTS schedules (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    cron_expression TEXT NOT NULL,
                    action TEXT NOT NULL,
                    parameters TEXT,
                    enabled INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
            """)
            
            # Create notifications table
            self.execute("""
                CREATE TABLE IF NOT EXISTS notifications (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    read INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            """)
            
            # Create emergency_contacts table
            self.execute("""
                CREATE TABLE IF NOT EXISTS emergency_contacts (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    phone TEXT NOT NULL,
                    email TEXT,
                    primary_contact INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
            """)
            
            # Create emergency_events table
            self.execute("""
                CREATE TABLE IF NOT EXISTS emergency_events (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    location TEXT,
                    details TEXT,
                    status TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                )
            """)
            
            # Create indexes
            self.execute("CREATE INDEX IF NOT EXISTS idx_devices_status ON devices (status)")
            self.execute("CREATE INDEX IF NOT EXISTS idx_cameras_device_id ON cameras (device_id)")
            self.execute("CREATE INDEX IF NOT EXISTS idx_cameras_status ON cameras (status)")
            self.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events (type)")
            self.execute("CREATE INDEX IF NOT EXISTS idx_events_created_at ON events (created_at)")
            self.execute("CREATE INDEX IF NOT EXISTS idx_alerts_event_id ON alerts (event_id)")
            self.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status)")
            self.execute("CREATE INDEX IF NOT EXISTS idx_detections_camera_id ON detections (camera_id)")
            self.execute("CREATE INDEX IF NOT EXISTS idx_detections_created_at ON detections (created_at)")
            self.execute("CREATE INDEX IF NOT EXISTS idx_tracks_camera_id ON tracks (camera_id)")
            self.execute("CREATE INDEX IF NOT EXISTS idx_tracks_track_id ON tracks (track_id)")
            self.execute("CREATE INDEX IF NOT EXISTS idx_logs_level ON logs (level)")
            self.execute("CREATE INDEX IF NOT EXISTS idx_logs_created_at ON logs (created_at)")
            self.execute("CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications (user_id)")
            self.execute("CREATE INDEX IF NOT EXISTS idx_notifications_read ON notifications (read)")
            self.execute("CREATE INDEX IF NOT EXISTS idx_emergency_events_status ON emergency_events (status)")
            
            # Commit changes
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to create database tables: {str(e)}")
            raise
    
    def execute(self, query: str, parameters: Tuple = ()) -> bool:
        """
        Execute a database query.
        
        Args:
            query: SQL query
            parameters: Query parameters
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute(query, parameters)
                self.conn.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to execute query: {str(e)}")
            logger.error(f"Query: {query}")
            logger.error(f"Parameters: {parameters}")
            return False
    
    def executemany(self, query: str, parameters: List[Tuple]) -> bool:
        """
        Execute a database query with multiple parameter sets.
        
        Args:
            query: SQL query
            parameters: List of query parameters
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.executemany(query, parameters)
                self.conn.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to execute query: {str(e)}")
            logger.error(f"Query: {query}")
            logger.error(f"Parameters count: {len(parameters)}")
            return False
    
    def query(self, query: str, parameters: Tuple = ()) -> List[Dict[str, Any]]:
        """
        Execute a database query and return results.
        
        Args:
            query: SQL query
            parameters: Query parameters
            
        Returns:
            List of result rows as dictionaries
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute(query, parameters)
                return cursor.fetchall()
        except Exception as e:
            logger.error(f"Failed to execute query: {str(e)}")
            logger.error(f"Query: {query}")
            logger.error(f"Parameters: {parameters}")
            return []
    
    def query_one(self, query: str, parameters: Tuple = ()) -> Optional[Dict[str, Any]]:
        """
        Execute a database query and return a single result.
        
        Args:
            query: SQL query
            parameters: Query parameters
            
        Returns:
            Result row as dictionary if found, None otherwise
        """
        try:
            with self.lock:
                cursor = self.conn.cursor()
                cursor.execute(query, parameters)
                return cursor.fetchone()
        except Exception as e:
            logger.error(f"Failed to execute query: {str(e)}")
            logger.error(f"Query: {query}")
            logger.error(f"Parameters: {parameters}")
            return None
    
    def backup_database(self) -> bool:
        """
        Backup the database.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get backup directory
            backup_dir = os.path.join(os.path.dirname(self.db_path), "backups")
            os.makedirs(backup_dir, exist_ok=True)
            
            # Create backup filename with timestamp
            timestamp = int(time.time())
            backup_path = os.path.join(backup_dir, f"viztron_{timestamp}.db")
            
            # Create backup
            with self.lock:
                # Create backup connection
                backup_conn = sqlite3.connect(backup_path)
                
                # Backup database
                self.conn.backup(backup_conn)
                
                # Close backup connection
                backup_conn.close()
            
            logger.info(f"Database backup created: {backup_path}")
            
            # Clean up old backups
            self._cleanup_backups(backup_dir)
            
            return True
        except Exception as e:
            logger.error(f"Failed to backup database: {str(e)}")
            return False
    
    def _cleanup_backups(self, backup_dir: str):
        """
        Clean up old database backups.
        
        Args:
            backup_dir: Backup directory
        """
        try:
            # Get backup count from config
            backup_count = self.config.get("database", {}).get("backup_count", 7)
            
            # Get backup files
            backup_files = []
            
            for filename in os.listdir(backup_dir):
                if filename.startswith("viztron_") and filename.endswith(".db"):
                    backup_path = os.path.join(backup_dir, filename)
                    backup_files.append((backup_path, os.path.getmtime(backup_path)))
            
            # Sort by modification time (newest first)
            backup_files.sort(key=lambda x: x[1], reverse=True)
            
            # Remove old backups
            for backup_path, _ in backup_files[backup_count:]:
                os.remove(backup_path)
                logger.info(f"Removed old database backup: {backup_path}")
        except Exception as e:
            logger.error(f"Failed to clean up old backups: {str(e)}")
    
    def vacuum_database(self) -> bool:
        """
        Vacuum the database to optimize performance.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            with self.lock:
                self.conn.execute("VACUUM")
                self.conn.commit()
            
            logger.info("Database vacuumed")
            return True
        except Exception as e:
            logger.error(f"Failed to vacuum database: {str(e)}")
            return False
    
    def get_database_size(self) -> int:
        """
        Get the database file size.
        
        Returns:
            Database size in bytes
        """
        try:
            return os.path.getsize(self.db_path)
        except Exception as e:
            logger.error(f"Failed to get database size: {str(e)}")
            return 0
    
    def get_table_row_counts(self) -> Dict[str, int]:
        """
        Get row counts for all tables.
        
        Returns:
            Dictionary of table names and row counts
        """
        try:
            # Get table names
            tables = self.query("SELECT name FROM sqlite_master WHERE type='table'")
            
            # Get row counts
            counts = {}
            
            for table in tables:
                table_name = table["name"]
                
                if table_name.startswith("sqlite_"):
                    continue
                
                count = self.query_one(f"SELECT COUNT(*) as count FROM {table_name}")
                counts[table_name] = count["count"] if count else 0
            
            return counts
        except Exception as e:
            logger.error(f"Failed to get table row counts: {str(e)}")
            return {}
    
    def get_database_stats(self) -> Dict[str, Any]:
        """
        Get database statistics.
        
        Returns:
            Dictionary of database statistics
        """
        try:
            # Get database size
            size = self.get_database_size()
            
            # Get table row counts
            row_counts = self.get_table_row_counts()
            
            # Get total row count
            total_rows = sum(row_counts.values())
            
            # Get database page count
            page_count = self.query_one("PRAGMA page_count")
            page_count = page_count["page_count"] if page_count else 0
            
            # Get database page size
            page_size = self.query_one("PRAGMA page_size")
            page_size = page_size["page_size"] if page_size else 0
            
            # Get database free pages
            free_pages = self.query_one("PRAGMA freelist_count")
            free_pages = free_pages["freelist_count"] if free_pages else 0
            
            # Calculate fragmentation
            if page_count > 0:
                fragmentation = (free_pages / page_count) * 100
            else:
                fragmentation = 0
            
            # Create stats
            stats = {
                "size": size,
                "size_mb": size / (1024 * 1024),
                "total_rows": total_rows,
                "table_row_counts": row_counts,
                "page_count": page_count,
                "page_size": page_size,
                "free_pages": free_pages,
                "fragmentation": fragmentation
            }
            
            return stats
        except Exception as e:
            logger.error(f"Failed to get database stats: {str(e)}")
            return {}
    
    def add_user(self, user: Dict[str, Any]) -> bool:
        """
        Add a user to the database.
        
        Args:
            user: User data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check required fields
            required_fields = ["id", "name", "role", "password_hash", "password_salt"]
            
            for field in required_fields:
                if field not in user:
                    logger.error(f"Missing required field in user data: {field}")
                    return False
            
            # Set timestamps
            current_time = int(time.time())
            user["created_at"] = current_time
            user["updated_at"] = current_time
            
            # Set default status
            if "status" not in user:
                user["status"] = "active"
            
            # Insert user
            return self.execute(
                """
                INSERT INTO users (
                    id, name, email, phone, role, password_hash, password_salt,
                    created_at, updated_at, last_login, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user["id"],
                    user["name"],
                    user.get("email"),
                    user.get("phone"),
                    user["role"],
                    user["password_hash"],
                    user["password_salt"],
                    user["created_at"],
                    user["updated_at"],
                    user.get("last_login"),
                    user["status"]
                )
            )
        except Exception as e:
            logger.error(f"Failed to add user: {str(e)}")
            return False
    
    def update_user(self, user_id: str, user_data: Dict[str, Any]) -> bool:
        """
        Update a user in the database.
        
        Args:
            user_id: User ID
            user_data: User data to update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set updated timestamp
            user_data["updated_at"] = int(time.time())
            
            # Build update query
            fields = []
            values = []
            
            for key, value in user_data.items():
                if key != "id":
                    fields.append(f"{key} = ?")
                    values.append(value)
            
            # Add user ID
            values.append(user_id)
            
            # Execute update
            return self.execute(
                f"UPDATE users SET {', '.join(fields)} WHERE id = ?",
                tuple(values)
            )
        except Exception as e:
            logger.error(f"Failed to update user: {str(e)}")
            return False
    
    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a user from the database.
        
        Args:
            user_id: User ID
            
        Returns:
            User data if found, None otherwise
        """
        try:
            return self.query_one(
                "SELECT * FROM users WHERE id = ?",
                (user_id,)
            )
        except Exception as e:
            logger.error(f"Failed to get user: {str(e)}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Get a user by email from the database.
        
        Args:
            email: User email
            
        Returns:
            User data if found, None otherwise
        """
        try:
            return self.query_one(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            )
        except Exception as e:
            logger.error(f"Failed to get user by email: {str(e)}")
            return None
    
    def get_users(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get users from the database.
        
        Args:
            limit: Maximum number of users to return
            offset: Offset for pagination
            
        Returns:
            List of user data
        """
        try:
            return self.query(
                "SELECT * FROM users ORDER BY name LIMIT ? OFFSET ?",
                (limit, offset)
            )
        except Exception as e:
            logger.error(f"Failed to get users: {str(e)}")
            return []
    
    def delete_user(self, user_id: str) -> bool:
        """
        Delete a user from the database.
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            return self.execute(
                "DELETE FROM users WHERE id = ?",
                (user_id,)
            )
        except Exception as e:
            logger.error(f"Failed to delete user: {str(e)}")
            return False
    
    def add_device(self, device: Dict[str, Any]) -> bool:
        """
        Add a device to the database.
        
        Args:
            device: Device data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check required fields
            required_fields = ["id", "name", "type"]
            
            for field in required_fields:
                if field not in device:
                    logger.error(f"Missing required field in device data: {field}")
                    return False
            
            # Set timestamps
            current_time = int(time.time())
            device["created_at"] = current_time
            device["updated_at"] = current_time
            
            # Set default status
            if "status" not in device:
                device["status"] = "active"
            
            # Insert device
            return self.execute(
                """
                INSERT INTO devices (
                    id, name, type, location, ip_address, mac_address,
                    status, last_seen, firmware_version, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device["id"],
                    device["name"],
                    device["type"],
                    device.get("location"),
                    device.get("ip_address"),
                    device.get("mac_address"),
                    device["status"],
                    device.get("last_seen"),
                    device.get("firmware_version"),
                    device["created_at"],
                    device["updated_at"]
                )
            )
        except Exception as e:
            logger.error(f"Failed to add device: {str(e)}")
            return False
    
    def update_device(self, device_id: str, device_data: Dict[str, Any]) -> bool:
        """
        Update a device in the database.
        
        Args:
            device_id: Device ID
            device_data: Device data to update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set updated timestamp
            device_data["updated_at"] = int(time.time())
            
            # Build update query
            fields = []
            values = []
            
            for key, value in device_data.items():
                if key != "id":
                    fields.append(f"{key} = ?")
                    values.append(value)
            
            # Add device ID
            values.append(device_id)
            
            # Execute update
            return self.execute(
                f"UPDATE devices SET {', '.join(fields)} WHERE id = ?",
                tuple(values)
            )
        except Exception as e:
            logger.error(f"Failed to update device: {str(e)}")
            return False
    
    def get_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a device from the database.
        
        Args:
            device_id: Device ID
            
        Returns:
            Device data if found, None otherwise
        """
        try:
            return self.query_one(
                "SELECT * FROM devices WHERE id = ?",
                (device_id,)
            )
        except Exception as e:
            logger.error(f"Failed to get device: {str(e)}")
            return None
    
    def get_devices(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get devices from the database.
        
        Args:
            limit: Maximum number of devices to return
            offset: Offset for pagination
            
        Returns:
            List of device data
        """
        try:
            return self.query(
                "SELECT * FROM devices ORDER BY name LIMIT ? OFFSET ?",
                (limit, offset)
            )
        except Exception as e:
            logger.error(f"Failed to get devices: {str(e)}")
            return []
    
    def get_devices_by_type(self, device_type: str) -> List[Dict[str, Any]]:
        """
        Get devices by type from the database.
        
        Args:
            device_type: Device type
            
        Returns:
            List of device data
        """
        try:
            return self.query(
                "SELECT * FROM devices WHERE type = ? ORDER BY name",
                (device_type,)
            )
        except Exception as e:
            logger.error(f"Failed to get devices by type: {str(e)}")
            return []
    
    def delete_device(self, device_id: str) -> bool:
        """
        Delete a device from the database.
        
        Args:
            device_id: Device ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            return self.execute(
                "DELETE FROM devices WHERE id = ?",
                (device_id,)
            )
        except Exception as e:
            logger.error(f"Failed to delete device: {str(e)}")
            return False
    
    def add_camera(self, camera: Dict[str, Any]) -> bool:
        """
        Add a camera to the database.
        
        Args:
            camera: Camera data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check required fields
            required_fields = ["id", "device_id", "name"]
            
            for field in required_fields:
                if field not in camera:
                    logger.error(f"Missing required field in camera data: {field}")
                    return False
            
            # Set timestamps
            current_time = int(time.time())
            camera["created_at"] = current_time
            camera["updated_at"] = current_time
            
            # Set default status
            if "status" not in camera:
                camera["status"] = "active"
            
            # Insert camera
            return self.execute(
                """
                INSERT INTO cameras (
                    id, device_id, name, location, resolution, fps,
                    status, last_seen, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    camera["id"],
                    camera["device_id"],
                    camera["name"],
                    camera.get("location"),
                    camera.get("resolution"),
                    camera.get("fps"),
                    camera["status"],
                    camera.get("last_seen"),
                    camera["created_at"],
                    camera["updated_at"]
                )
            )
        except Exception as e:
            logger.error(f"Failed to add camera: {str(e)}")
            return False
    
    def update_camera(self, camera_id: str, camera_data: Dict[str, Any]) -> bool:
        """
        Update a camera in the database.
        
        Args:
            camera_id: Camera ID
            camera_data: Camera data to update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set updated timestamp
            camera_data["updated_at"] = int(time.time())
            
            # Build update query
            fields = []
            values = []
            
            for key, value in camera_data.items():
                if key != "id":
                    fields.append(f"{key} = ?")
                    values.append(value)
            
            # Add camera ID
            values.append(camera_id)
            
            # Execute update
            return self.execute(
                f"UPDATE cameras SET {', '.join(fields)} WHERE id = ?",
                tuple(values)
            )
        except Exception as e:
            logger.error(f"Failed to update camera: {str(e)}")
            return False
    
    def get_camera(self, camera_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a camera from the database.
        
        Args:
            camera_id: Camera ID
            
        Returns:
            Camera data if found, None otherwise
        """
        try:
            return self.query_one(
                "SELECT * FROM cameras WHERE id = ?",
                (camera_id,)
            )
        except Exception as e:
            logger.error(f"Failed to get camera: {str(e)}")
            return None
    
    def get_cameras(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get cameras from the database.
        
        Args:
            limit: Maximum number of cameras to return
            offset: Offset for pagination
            
        Returns:
            List of camera data
        """
        try:
            return self.query(
                "SELECT * FROM cameras ORDER BY name LIMIT ? OFFSET ?",
                (limit, offset)
            )
        except Exception as e:
            logger.error(f"Failed to get cameras: {str(e)}")
            return []
    
    def get_cameras_by_device(self, device_id: str) -> List[Dict[str, Any]]:
        """
        Get cameras by device from the database.
        
        Args:
            device_id: Device ID
            
        Returns:
            List of camera data
        """
        try:
            return self.query(
                "SELECT * FROM cameras WHERE device_id = ? ORDER BY name",
                (device_id,)
            )
        except Exception as e:
            logger.error(f"Failed to get cameras by device: {str(e)}")
            return []
    
    def delete_camera(self, camera_id: str) -> bool:
        """
        Delete a camera from the database.
        
        Args:
            camera_id: Camera ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            return self.execute(
                "DELETE FROM cameras WHERE id = ?",
                (camera_id,)
            )
        except Exception as e:
            logger.error(f"Failed to delete camera: {str(e)}")
            return False
    
    def add_zone(self, zone: Dict[str, Any]) -> bool:
        """
        Add a zone to the database.
        
        Args:
            zone: Zone data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check required fields
            required_fields = ["id", "name", "type"]
            
            for field in required_fields:
                if field not in zone:
                    logger.error(f"Missing required field in zone data: {field}")
                    return False
            
            # Set timestamps
            current_time = int(time.time())
            zone["created_at"] = current_time
            zone["updated_at"] = current_time
            
            # Set default status
            if "status" not in zone:
                zone["status"] = "active"
            
            # Insert zone
            return self.execute(
                """
                INSERT INTO zones (
                    id, name, type, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    zone["id"],
                    zone["name"],
                    zone["type"],
                    zone["status"],
                    zone["created_at"],
                    zone["updated_at"]
                )
            )
        except Exception as e:
            logger.error(f"Failed to add zone: {str(e)}")
            return False
    
    def update_zone(self, zone_id: str, zone_data: Dict[str, Any]) -> bool:
        """
        Update a zone in the database.
        
        Args:
            zone_id: Zone ID
            zone_data: Zone data to update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set updated timestamp
            zone_data["updated_at"] = int(time.time())
            
            # Build update query
            fields = []
            values = []
            
            for key, value in zone_data.items():
                if key != "id":
                    fields.append(f"{key} = ?")
                    values.append(value)
            
            # Add zone ID
            values.append(zone_id)
            
            # Execute update
            return self.execute(
                f"UPDATE zones SET {', '.join(fields)} WHERE id = ?",
                tuple(values)
            )
        except Exception as e:
            logger.error(f"Failed to update zone: {str(e)}")
            return False
    
    def get_zone(self, zone_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a zone from the database.
        
        Args:
            zone_id: Zone ID
            
        Returns:
            Zone data if found, None otherwise
        """
        try:
            return self.query_one(
                "SELECT * FROM zones WHERE id = ?",
                (zone_id,)
            )
        except Exception as e:
            logger.error(f"Failed to get zone: {str(e)}")
            return None
    
    def get_zones(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get zones from the database.
        
        Args:
            limit: Maximum number of zones to return
            offset: Offset for pagination
            
        Returns:
            List of zone data
        """
        try:
            return self.query(
                "SELECT * FROM zones ORDER BY name LIMIT ? OFFSET ?",
                (limit, offset)
            )
        except Exception as e:
            logger.error(f"Failed to get zones: {str(e)}")
            return []
    
    def delete_zone(self, zone_id: str) -> bool:
        """
        Delete a zone from the database.
        
        Args:
            zone_id: Zone ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            return self.execute(
                "DELETE FROM zones WHERE id = ?",
                (zone_id,)
            )
        except Exception as e:
            logger.error(f"Failed to delete zone: {str(e)}")
            return False
    
    def add_device_to_zone(self, zone_id: str, device_id: str) -> bool:
        """
        Add a device to a zone.
        
        Args:
            zone_id: Zone ID
            device_id: Device ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set timestamp
            current_time = int(time.time())
            
            # Insert zone device
            return self.execute(
                """
                INSERT INTO zone_devices (
                    zone_id, device_id, created_at
                ) VALUES (?, ?, ?)
                """,
                (
                    zone_id,
                    device_id,
                    current_time
                )
            )
        except Exception as e:
            logger.error(f"Failed to add device to zone: {str(e)}")
            return False
    
    def remove_device_from_zone(self, zone_id: str, device_id: str) -> bool:
        """
        Remove a device from a zone.
        
        Args:
            zone_id: Zone ID
            device_id: Device ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            return self.execute(
                """
                DELETE FROM zone_devices
                WHERE zone_id = ? AND device_id = ?
                """,
                (zone_id, device_id)
            )
        except Exception as e:
            logger.error(f"Failed to remove device from zone: {str(e)}")
            return False
    
    def get_devices_in_zone(self, zone_id: str) -> List[Dict[str, Any]]:
        """
        Get devices in a zone.
        
        Args:
            zone_id: Zone ID
            
        Returns:
            List of device data
        """
        try:
            return self.query(
                """
                SELECT d.*
                FROM devices d
                JOIN zone_devices zd ON d.id = zd.device_id
                WHERE zd.zone_id = ?
                ORDER BY d.name
                """,
                (zone_id,)
            )
        except Exception as e:
            logger.error(f"Failed to get devices in zone: {str(e)}")
            return []
    
    def get_zones_for_device(self, device_id: str) -> List[Dict[str, Any]]:
        """
        Get zones for a device.
        
        Args:
            device_id: Device ID
            
        Returns:
            List of zone data
        """
        try:
            return self.query(
                """
                SELECT z.*
                FROM zones z
                JOIN zone_devices zd ON z.id = zd.zone_id
                WHERE zd.device_id = ?
                ORDER BY z.name
                """,
                (device_id,)
            )
        except Exception as e:
            logger.error(f"Failed to get zones for device: {str(e)}")
            return []
    
    def add_event(self, event: Dict[str, Any]) -> bool:
        """
        Add an event to the database.
        
        Args:
            event: Event data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check required fields
            required_fields = ["id", "type", "source", "severity"]
            
            for field in required_fields:
                if field not in event:
                    logger.error(f"Missing required field in event data: {field}")
                    return False
            
            # Set timestamps
            current_time = int(time.time())
            event["created_at"] = current_time
            event["updated_at"] = current_time
            
            # Set default status
            if "status" not in event:
                event["status"] = "new"
            
            # Insert event
            return self.execute(
                """
                INSERT INTO events (
                    id, type, source, severity, status, details,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["id"],
                    event["type"],
                    event["source"],
                    event["severity"],
                    event["status"],
                    event.get("details"),
                    event["created_at"],
                    event["updated_at"]
                )
            )
        except Exception as e:
            logger.error(f"Failed to add event: {str(e)}")
            return False
    
    def update_event(self, event_id: str, event_data: Dict[str, Any]) -> bool:
        """
        Update an event in the database.
        
        Args:
            event_id: Event ID
            event_data: Event data to update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set updated timestamp
            event_data["updated_at"] = int(time.time())
            
            # Build update query
            fields = []
            values = []
            
            for key, value in event_data.items():
                if key != "id":
                    fields.append(f"{key} = ?")
                    values.append(value)
            
            # Add event ID
            values.append(event_id)
            
            # Execute update
            return self.execute(
                f"UPDATE events SET {', '.join(fields)} WHERE id = ?",
                tuple(values)
            )
        except Exception as e:
            logger.error(f"Failed to update event: {str(e)}")
            return False
    
    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """
        Get an event from the database.
        
        Args:
            event_id: Event ID
            
        Returns:
            Event data if found, None otherwise
        """
        try:
            return self.query_one(
                "SELECT * FROM events WHERE id = ?",
                (event_id,)
            )
        except Exception as e:
            logger.error(f"Failed to get event: {str(e)}")
            return None
    
    def get_events(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get events from the database.
        
        Args:
            limit: Maximum number of events to return
            offset: Offset for pagination
            
        Returns:
            List of event data
        """
        try:
            return self.query(
                "SELECT * FROM events ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset)
            )
        except Exception as e:
            logger.error(f"Failed to get events: {str(e)}")
            return []
    
    def get_events_by_type(self, event_type: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get events by type from the database.
        
        Args:
            event_type: Event type
            limit: Maximum number of events to return
            offset: Offset for pagination
            
        Returns:
            List of event data
        """
        try:
            return self.query(
                "SELECT * FROM events WHERE type = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (event_type, limit, offset)
            )
        except Exception as e:
            logger.error(f"Failed to get events by type: {str(e)}")
            return []
    
    def delete_event(self, event_id: str) -> bool:
        """
        Delete an event from the database.
        
        Args:
            event_id: Event ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            return self.execute(
                "DELETE FROM events WHERE id = ?",
                (event_id,)
            )
        except Exception as e:
            logger.error(f"Failed to delete event: {str(e)}")
            return False
    
    def add_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Add an alert to the database.
        
        Args:
            alert: Alert data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check required fields
            required_fields = ["id", "event_id", "type", "severity"]
            
            for field in required_fields:
                if field not in alert:
                    logger.error(f"Missing required field in alert data: {field}")
                    return False
            
            # Set timestamps
            current_time = int(time.time())
            alert["created_at"] = current_time
            alert["updated_at"] = current_time
            
            # Set default status
            if "status" not in alert:
                alert["status"] = "new"
            
            # Insert alert
            return self.execute(
                """
                INSERT INTO alerts (
                    id, event_id, type, severity, status, details,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert["id"],
                    alert["event_id"],
                    alert["type"],
                    alert["severity"],
                    alert["status"],
                    alert.get("details"),
                    alert["created_at"],
                    alert["updated_at"]
                )
            )
        except Exception as e:
            logger.error(f"Failed to add alert: {str(e)}")
            return False
    
    def update_alert(self, alert_id: str, alert_data: Dict[str, Any]) -> bool:
        """
        Update an alert in the database.
        
        Args:
            alert_id: Alert ID
            alert_data: Alert data to update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set updated timestamp
            alert_data["updated_at"] = int(time.time())
            
            # Build update query
            fields = []
            values = []
            
            for key, value in alert_data.items():
                if key != "id":
                    fields.append(f"{key} = ?")
                    values.append(value)
            
            # Add alert ID
            values.append(alert_id)
            
            # Execute update
            return self.execute(
                f"UPDATE alerts SET {', '.join(fields)} WHERE id = ?",
                tuple(values)
            )
        except Exception as e:
            logger.error(f"Failed to update alert: {str(e)}")
            return False
    
    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Get an alert from the database.
        
        Args:
            alert_id: Alert ID
            
        Returns:
            Alert data if found, None otherwise
        """
        try:
            return self.query_one(
                "SELECT * FROM alerts WHERE id = ?",
                (alert_id,)
            )
        except Exception as e:
            logger.error(f"Failed to get alert: {str(e)}")
            return None
    
    def get_alerts(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get alerts from the database.
        
        Args:
            limit: Maximum number of alerts to return
            offset: Offset for pagination
            
        Returns:
            List of alert data
        """
        try:
            return self.query(
                "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset)
            )
        except Exception as e:
            logger.error(f"Failed to get alerts: {str(e)}")
            return []
    
    def get_alerts_by_event(self, event_id: str) -> List[Dict[str, Any]]:
        """
        Get alerts by event from the database.
        
        Args:
            event_id: Event ID
            
        Returns:
            List of alert data
        """
        try:
            return self.query(
                "SELECT * FROM alerts WHERE event_id = ? ORDER BY created_at DESC",
                (event_id,)
            )
        except Exception as e:
            logger.error(f"Failed to get alerts by event: {str(e)}")
            return []
    
    def delete_alert(self, alert_id: str) -> bool:
        """
        Delete an alert from the database.
        
        Args:
            alert_id: Alert ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            return self.execute(
                "DELETE FROM alerts WHERE id = ?",
                (alert_id,)
            )
        except Exception as e:
            logger.error(f"Failed to delete alert: {str(e)}")
            return False
    
    def add_face(self, face: Dict[str, Any]) -> bool:
        """
        Add a face to the database.
        
        Args:
            face: Face data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check required fields
            required_fields = ["id", "name", "features"]
            
            for field in required_fields:
                if field not in face:
                    logger.error(f"Missing required field in face data: {field}")
                    return False
            
            # Set timestamps
            current_time = int(time.time())
            face["created_at"] = current_time
            face["updated_at"] = current_time
            
            # Insert face
            return self.execute(
                """
                INSERT INTO faces (
                    id, name, features, user_id, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    face["id"],
                    face["name"],
                    face["features"],
                    face.get("user_id"),
                    face["created_at"],
                    face["updated_at"]
                )
            )
        except Exception as e:
            logger.error(f"Failed to add face: {str(e)}")
            return False
    
    def update_face(self, face_id: str, face_data: Dict[str, Any]) -> bool:
        """
        Update a face in the database.
        
        Args:
            face_id: Face ID
            face_data: Face data to update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set updated timestamp
            face_data["updated_at"] = int(time.time())
            
            # Build update query
            fields = []
            values = []
            
            for key, value in face_data.items():
                if key != "id":
                    fields.append(f"{key} = ?")
                    values.append(value)
            
            # Add face ID
            values.append(face_id)
            
            # Execute update
            return self.execute(
                f"UPDATE faces SET {', '.join(fields)} WHERE id = ?",
                tuple(values)
            )
        except Exception as e:
            logger.error(f"Failed to update face: {str(e)}")
            return False
    
    def get_face(self, face_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a face from the database.
        
        Args:
            face_id: Face ID
            
        Returns:
            Face data if found, None otherwise
        """
        try:
            return self.query_one(
                "SELECT * FROM faces WHERE id = ?",
                (face_id,)
            )
        except Exception as e:
            logger.error(f"Failed to get face: {str(e)}")
            return None
    
    def get_faces(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get faces from the database.
        
        Args:
            limit: Maximum number of faces to return
            offset: Offset for pagination
            
        Returns:
            List of face data
        """
        try:
            return self.query(
                "SELECT * FROM faces ORDER BY name LIMIT ? OFFSET ?",
                (limit, offset)
            )
        except Exception as e:
            logger.error(f"Failed to get faces: {str(e)}")
            return []
    
    def delete_face(self, face_id: str) -> bool:
        """
        Delete a face from the database.
        
        Args:
            face_id: Face ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            return self.execute(
                "DELETE FROM faces WHERE id = ?",
                (face_id,)
            )
        except Exception as e:
            logger.error(f"Failed to delete face: {str(e)}")
            return False
    
    def add_face_image(self, face_image: Dict[str, Any]) -> bool:
        """
        Add a face image to the database.
        
        Args:
            face_image: Face image data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check required fields
            required_fields = ["id", "face_id", "image_path"]
            
            for field in required_fields:
                if field not in face_image:
                    logger.error(f"Missing required field in face image data: {field}")
                    return False
            
            # Set timestamp
            current_time = int(time.time())
            face_image["created_at"] = current_time
            
            # Insert face image
            return self.execute(
                """
                INSERT INTO face_images (
                    id, face_id, image_path, created_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    face_image["id"],
                    face_image["face_id"],
                    face_image["image_path"],
                    face_image["created_at"]
                )
            )
        except Exception as e:
            logger.error(f"Failed to add face image: {str(e)}")
            return False
    
    def get_face_images(self, face_id: str) -> List[Dict[str, Any]]:
        """
        Get face images from the database.
        
        Args:
            face_id: Face ID
            
        Returns:
            List of face image data
        """
        try:
            return self.query(
                "SELECT * FROM face_images WHERE face_id = ? ORDER BY created_at DESC",
                (face_id,)
            )
        except Exception as e:
            logger.error(f"Failed to get face images: {str(e)}")
            return []
    
    def delete_face_image(self, image_id: str) -> bool:
        """
        Delete a face image from the database.
        
        Args:
            image_id: Image ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            return self.execute(
                "DELETE FROM face_images WHERE id = ?",
                (image_id,)
            )
        except Exception as e:
            logger.error(f"Failed to delete face image: {str(e)}")
            return False
    
    def add_detection(self, detection: Dict[str, Any]) -> bool:
        """
        Add a detection to the database.
        
        Args:
            detection: Detection data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check required fields
            required_fields = ["id", "camera_id", "class_id", "class_name", "confidence", "box_x", "box_y", "box_width", "box_height"]
            
            for field in required_fields:
                if field not in detection:
                    logger.error(f"Missing required field in detection data: {field}")
                    return False
            
            # Set timestamp
            current_time = int(time.time())
            detection["created_at"] = current_time
            
            # Insert detection
            return self.execute(
                """
                INSERT INTO detections (
                    id, camera_id, class_id, class_name, confidence,
                    box_x, box_y, box_width, box_height, image_path, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    detection["id"],
                    detection["camera_id"],
                    detection["class_id"],
                    detection["class_name"],
                    detection["confidence"],
                    detection["box_x"],
                    detection["box_y"],
                    detection["box_width"],
                    detection["box_height"],
                    detection.get("image_path"),
                    detection["created_at"]
                )
            )
        except Exception as e:
            logger.error(f"Failed to add detection: {str(e)}")
            return False
    
    def get_detections(self, camera_id: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get detections from the database.
        
        Args:
            camera_id: Camera ID
            limit: Maximum number of detections to return
            offset: Offset for pagination
            
        Returns:
            List of detection data
        """
        try:
            return self.query(
                """
                SELECT * FROM detections
                WHERE camera_id = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (camera_id, limit, offset)
            )
        except Exception as e:
            logger.error(f"Failed to get detections: {str(e)}")
            return []
    
    def get_detections_by_class(self, class_name: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get detections by class from the database.
        
        Args:
            class_name: Class name
            limit: Maximum number of detections to return
            offset: Offset for pagination
            
        Returns:
            List of detection data
        """
        try:
            return self.query(
                """
                SELECT * FROM detections
                WHERE class_name = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (class_name, limit, offset)
            )
        except Exception as e:
            logger.error(f"Failed to get detections by class: {str(e)}")
            return []
    
    def delete_old_detections(self, days: int) -> int:
        """
        Delete old detections from the database.
        
        Args:
            days: Number of days to keep
            
        Returns:
            Number of detections deleted
        """
        try:
            # Calculate cutoff timestamp
            cutoff = int(time.time()) - (days * 86400)
            
            # Get count of detections to delete
            count_result = self.query_one(
                "SELECT COUNT(*) as count FROM detections WHERE created_at < ?",
                (cutoff,)
            )
            count = count_result["count"] if count_result else 0
            
            # Delete old detections
            self.execute(
                "DELETE FROM detections WHERE created_at < ?",
                (cutoff,)
            )
            
            return count
        except Exception as e:
            logger.error(f"Failed to delete old detections: {str(e)}")
            return 0
    
    def add_track(self, track: Dict[str, Any]) -> bool:
        """
        Add a track to the database.
        
        Args:
            track: Track data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check required fields
            required_fields = ["id", "track_id", "camera_id", "class_id", "class_name", "box_x", "box_y", "box_width", "box_height"]
            
            for field in required_fields:
                if field not in track:
                    logger.error(f"Missing required field in track data: {field}")
                    return False
            
            # Set timestamp
            current_time = int(time.time())
            track["created_at"] = current_time
            
            # Insert track
            return self.execute(
                """
                INSERT INTO tracks (
                    id, track_id, camera_id, class_id, class_name,
                    box_x, box_y, box_width, box_height, face_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    track["id"],
                    track["track_id"],
                    track["camera_id"],
                    track["class_id"],
                    track["class_name"],
                    track["box_x"],
                    track["box_y"],
                    track["box_width"],
                    track["box_height"],
                    track.get("face_id"),
                    track["created_at"]
                )
            )
        except Exception as e:
            logger.error(f"Failed to add track: {str(e)}")
            return False
    
    def get_tracks(self, camera_id: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get tracks from the database.
        
        Args:
            camera_id: Camera ID
            limit: Maximum number of tracks to return
            offset: Offset for pagination
            
        Returns:
            List of track data
        """
        try:
            return self.query(
                """
                SELECT * FROM tracks
                WHERE camera_id = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (camera_id, limit, offset)
            )
        except Exception as e:
            logger.error(f"Failed to get tracks: {str(e)}")
            return []
    
    def get_tracks_by_id(self, track_id: int, camera_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get tracks by track ID from the database.
        
        Args:
            track_id: Track ID
            camera_id: Camera ID
            limit: Maximum number of tracks to return
            
        Returns:
            List of track data
        """
        try:
            return self.query(
                """
                SELECT * FROM tracks
                WHERE track_id = ? AND camera_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (track_id, camera_id, limit)
            )
        except Exception as e:
            logger.error(f"Failed to get tracks by ID: {str(e)}")
            return []
    
    def delete_old_tracks(self, days: int) -> int:
        """
        Delete old tracks from the database.
        
        Args:
            days: Number of days to keep
            
        Returns:
            Number of tracks deleted
        """
        try:
            # Calculate cutoff timestamp
            cutoff = int(time.time()) - (days * 86400)
            
            # Get count of tracks to delete
            count_result = self.query_one(
                "SELECT COUNT(*) as count FROM tracks WHERE created_at < ?",
                (cutoff,)
            )
            count = count_result["count"] if count_result else 0
            
            # Delete old tracks
            self.execute(
                "DELETE FROM tracks WHERE created_at < ?",
                (cutoff,)
            )
            
            return count
        except Exception as e:
            logger.error(f"Failed to delete old tracks: {str(e)}")
            return 0
    
    def add_log(self, level: str, source: str, message: str) -> bool:
        """
        Add a log entry to the database.
        
        Args:
            level: Log level
            source: Log source
            message: Log message
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set timestamp
            current_time = int(time.time())
            
            # Insert log
            return self.execute(
                """
                INSERT INTO logs (
                    level, source, message, created_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    level,
                    source,
                    message,
                    current_time
                )
            )
        except Exception as e:
            logger.error(f"Failed to add log: {str(e)}")
            return False
    
    def get_logs(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get logs from the database.
        
        Args:
            limit: Maximum number of logs to return
            offset: Offset for pagination
            
        Returns:
            List of log data
        """
        try:
            return self.query(
                """
                SELECT * FROM logs
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset)
            )
        except Exception as e:
            logger.error(f"Failed to get logs: {str(e)}")
            return []
    
    def get_logs_by_level(self, level: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get logs by level from the database.
        
        Args:
            level: Log level
            limit: Maximum number of logs to return
            offset: Offset for pagination
            
        Returns:
            List of log data
        """
        try:
            return self.query(
                """
                SELECT * FROM logs
                WHERE level = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (level, limit, offset)
            )
        except Exception as e:
            logger.error(f"Failed to get logs by level: {str(e)}")
            return []
    
    def delete_old_logs(self, days: int) -> int:
        """
        Delete old logs from the database.
        
        Args:
            days: Number of days to keep
            
        Returns:
            Number of logs deleted
        """
        try:
            # Calculate cutoff timestamp
            cutoff = int(time.time()) - (days * 86400)
            
            # Get count of logs to delete
            count_result = self.query_one(
                "SELECT COUNT(*) as count FROM logs WHERE created_at < ?",
                (cutoff,)
            )
            count = count_result["count"] if count_result else 0
            
            # Delete old logs
            self.execute(
                "DELETE FROM logs WHERE created_at < ?",
                (cutoff,)
            )
            
            return count
        except Exception as e:
            logger.error(f"Failed to delete old logs: {str(e)}")
            return 0
    
    def set_setting(self, key: str, value: str) -> bool:
        """
        Set a setting in the database.
        
        Args:
            key: Setting key
            value: Setting value
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set timestamps
            current_time = int(time.time())
            
            # Check if setting exists
            existing = self.query_one(
                "SELECT * FROM settings WHERE key = ?",
                (key,)
            )
            
            if existing:
                # Update setting
                return self.execute(
                    """
                    UPDATE settings
                    SET value = ?, updated_at = ?
                    WHERE key = ?
                    """,
                    (value, current_time, key)
                )
            else:
                # Insert setting
                return self.execute(
                    """
                    INSERT INTO settings (
                        key, value, created_at, updated_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    (key, value, current_time, current_time)
                )
        except Exception as e:
            logger.error(f"Failed to set setting: {str(e)}")
            return False
    
    def get_setting(self, key: str, default: str = None) -> Optional[str]:
        """
        Get a setting from the database.
        
        Args:
            key: Setting key
            default: Default value if setting not found
            
        Returns:
            Setting value if found, default otherwise
        """
        try:
            result = self.query_one(
                "SELECT value FROM settings WHERE key = ?",
                (key,)
            )
            
            if result:
                return result["value"]
            else:
                return default
        except Exception as e:
            logger.error(f"Failed to get setting: {str(e)}")
            return default
    
    def get_settings(self) -> Dict[str, str]:
        """
        Get all settings from the database.
        
        Returns:
            Dictionary of settings
        """
        try:
            results = self.query("SELECT key, value FROM settings")
            return {result["key"]: result["value"] for result in results}
        except Exception as e:
            logger.error(f"Failed to get settings: {str(e)}")
            return {}
    
    def delete_setting(self, key: str) -> bool:
        """
        Delete a setting from the database.
        
        Args:
            key: Setting key
            
        Returns:
            True if successful, False otherwise
        """
        try:
            return self.execute(
                "DELETE FROM settings WHERE key = ?",
                (key,)
            )
        except Exception as e:
            logger.error(f"Failed to delete setting: {str(e)}")
            return False
    
    def add_schedule(self, schedule: Dict[str, Any]) -> bool:
        """
        Add a schedule to the database.
        
        Args:
            schedule: Schedule data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check required fields
            required_fields = ["id", "name", "type", "cron_expression", "action"]
            
            for field in required_fields:
                if field not in schedule:
                    logger.error(f"Missing required field in schedule data: {field}")
                    return False
            
            # Set timestamps
            current_time = int(time.time())
            schedule["created_at"] = current_time
            schedule["updated_at"] = current_time
            
            # Set default enabled
            if "enabled" not in schedule:
                schedule["enabled"] = 1
            
            # Insert schedule
            return self.execute(
                """
                INSERT INTO schedules (
                    id, name, type, cron_expression, action, parameters,
                    enabled, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    schedule["id"],
                    schedule["name"],
                    schedule["type"],
                    schedule["cron_expression"],
                    schedule["action"],
                    schedule.get("parameters"),
                    schedule["enabled"],
                    schedule["created_at"],
                    schedule["updated_at"]
                )
            )
        except Exception as e:
            logger.error(f"Failed to add schedule: {str(e)}")
            return False
    
    def update_schedule(self, schedule_id: str, schedule_data: Dict[str, Any]) -> bool:
        """
        Update a schedule in the database.
        
        Args:
            schedule_id: Schedule ID
            schedule_data: Schedule data to update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set updated timestamp
            schedule_data["updated_at"] = int(time.time())
            
            # Build update query
            fields = []
            values = []
            
            for key, value in schedule_data.items():
                if key != "id":
                    fields.append(f"{key} = ?")
                    values.append(value)
            
            # Add schedule ID
            values.append(schedule_id)
            
            # Execute update
            return self.execute(
                f"UPDATE schedules SET {', '.join(fields)} WHERE id = ?",
                tuple(values)
            )
        except Exception as e:
            logger.error(f"Failed to update schedule: {str(e)}")
            return False
    
    def get_schedule(self, schedule_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a schedule from the database.
        
        Args:
            schedule_id: Schedule ID
            
        Returns:
            Schedule data if found, None otherwise
        """
        try:
            return self.query_one(
                "SELECT * FROM schedules WHERE id = ?",
                (schedule_id,)
            )
        except Exception as e:
            logger.error(f"Failed to get schedule: {str(e)}")
            return None
    
    def get_schedules(self) -> List[Dict[str, Any]]:
        """
        Get all schedules from the database.
        
        Returns:
            List of schedule data
        """
        try:
            return self.query(
                "SELECT * FROM schedules ORDER BY name"
            )
        except Exception as e:
            logger.error(f"Failed to get schedules: {str(e)}")
            return []
    
    def get_enabled_schedules(self) -> List[Dict[str, Any]]:
        """
        Get enabled schedules from the database.
        
        Returns:
            List of enabled schedule data
        """
        try:
            return self.query(
                "SELECT * FROM schedules WHERE enabled = 1 ORDER BY name"
            )
        except Exception as e:
            logger.error(f"Failed to get enabled schedules: {str(e)}")
            return []
    
    def delete_schedule(self, schedule_id: str) -> bool:
        """
        Delete a schedule from the database.
        
        Args:
            schedule_id: Schedule ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            return self.execute(
                "DELETE FROM schedules WHERE id = ?",
                (schedule_id,)
            )
        except Exception as e:
            logger.error(f"Failed to delete schedule: {str(e)}")
            return False
    
    def add_notification(self, notification: Dict[str, Any]) -> bool:
        """
        Add a notification to the database.
        
        Args:
            notification: Notification data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check required fields
            required_fields = ["id", "user_id", "type", "title", "message"]
            
            for field in required_fields:
                if field not in notification:
                    logger.error(f"Missing required field in notification data: {field}")
                    return False
            
            # Set timestamp
            current_time = int(time.time())
            notification["created_at"] = current_time
            
            # Set default read
            if "read" not in notification:
                notification["read"] = 0
            
            # Insert notification
            return self.execute(
                """
                INSERT INTO notifications (
                    id, user_id, type, title, message, read, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    notification["id"],
                    notification["user_id"],
                    notification["type"],
                    notification["title"],
                    notification["message"],
                    notification["read"],
                    notification["created_at"]
                )
            )
        except Exception as e:
            logger.error(f"Failed to add notification: {str(e)}")
            return False
    
    def mark_notification_read(self, notification_id: str) -> bool:
        """
        Mark a notification as read.
        
        Args:
            notification_id: Notification ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            return self.execute(
                "UPDATE notifications SET read = 1 WHERE id = ?",
                (notification_id,)
            )
        except Exception as e:
            logger.error(f"Failed to mark notification as read: {str(e)}")
            return False
    
    def get_notifications(self, user_id: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get notifications for a user.
        
        Args:
            user_id: User ID
            limit: Maximum number of notifications to return
            offset: Offset for pagination
            
        Returns:
            List of notification data
        """
        try:
            return self.query(
                """
                SELECT * FROM notifications
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (user_id, limit, offset)
            )
        except Exception as e:
            logger.error(f"Failed to get notifications: {str(e)}")
            return []
    
    def get_unread_notifications(self, user_id: str) -> List[Dict[str, Any]]:
        """
        Get unread notifications for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of unread notification data
        """
        try:
            return self.query(
                """
                SELECT * FROM notifications
                WHERE user_id = ? AND read = 0
                ORDER BY created_at DESC
                """,
                (user_id,)
            )
        except Exception as e:
            logger.error(f"Failed to get unread notifications: {str(e)}")
            return []
    
    def delete_notification(self, notification_id: str) -> bool:
        """
        Delete a notification from the database.
        
        Args:
            notification_id: Notification ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            return self.execute(
                "DELETE FROM notifications WHERE id = ?",
                (notification_id,)
            )
        except Exception as e:
            logger.error(f"Failed to delete notification: {str(e)}")
            return False
    
    def delete_old_notifications(self, days: int) -> int:
        """
        Delete old notifications from the database.
        
        Args:
            days: Number of days to keep
            
        Returns:
            Number of notifications deleted
        """
        try:
            # Calculate cutoff timestamp
            cutoff = int(time.time()) - (days * 86400)
            
            # Get count of notifications to delete
            count_result = self.query_one(
                "SELECT COUNT(*) as count FROM notifications WHERE created_at < ?",
                (cutoff,)
            )
            count = count_result["count"] if count_result else 0
            
            # Delete old notifications
            self.execute(
                "DELETE FROM notifications WHERE created_at < ?",
                (cutoff,)
            )
            
            return count
        except Exception as e:
            logger.error(f"Failed to delete old notifications: {str(e)}")
            return 0
    
    def add_emergency_contact(self, contact: Dict[str, Any]) -> bool:
        """
        Add an emergency contact to the database.
        
        Args:
            contact: Emergency contact data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check required fields
            required_fields = ["id", "name", "phone"]
            
            for field in required_fields:
                if field not in contact:
                    logger.error(f"Missing required field in emergency contact data: {field}")
                    return False
            
            # Set timestamps
            current_time = int(time.time())
            contact["created_at"] = current_time
            contact["updated_at"] = current_time
            
            # Set default primary
            if "primary_contact" not in contact:
                contact["primary_contact"] = 0
            
            # Insert emergency contact
            return self.execute(
                """
                INSERT INTO emergency_contacts (
                    id, name, phone, email, primary_contact, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    contact["id"],
                    contact["name"],
                    contact["phone"],
                    contact.get("email"),
                    contact["primary_contact"],
                    contact["created_at"],
                    contact["updated_at"]
                )
            )
        except Exception as e:
            logger.error(f"Failed to add emergency contact: {str(e)}")
            return False
    
    def update_emergency_contact(self, contact_id: str, contact_data: Dict[str, Any]) -> bool:
        """
        Update an emergency contact in the database.
        
        Args:
            contact_id: Emergency contact ID
            contact_data: Emergency contact data to update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set updated timestamp
            contact_data["updated_at"] = int(time.time())
            
            # Build update query
            fields = []
            values = []
            
            for key, value in contact_data.items():
                if key != "id":
                    fields.append(f"{key} = ?")
                    values.append(value)
            
            # Add contact ID
            values.append(contact_id)
            
            # Execute update
            return self.execute(
                f"UPDATE emergency_contacts SET {', '.join(fields)} WHERE id = ?",
                tuple(values)
            )
        except Exception as e:
            logger.error(f"Failed to update emergency contact: {str(e)}")
            return False
    
    def get_emergency_contact(self, contact_id: str) -> Optional[Dict[str, Any]]:
        """
        Get an emergency contact from the database.
        
        Args:
            contact_id: Emergency contact ID
            
        Returns:
            Emergency contact data if found, None otherwise
        """
        try:
            return self.query_one(
                "SELECT * FROM emergency_contacts WHERE id = ?",
                (contact_id,)
            )
        except Exception as e:
            logger.error(f"Failed to get emergency contact: {str(e)}")
            return None
    
    def get_emergency_contacts(self) -> List[Dict[str, Any]]:
        """
        Get all emergency contacts from the database.
        
        Returns:
            List of emergency contact data
        """
        try:
            return self.query(
                "SELECT * FROM emergency_contacts ORDER BY name"
            )
        except Exception as e:
            logger.error(f"Failed to get emergency contacts: {str(e)}")
            return []
    
    def get_primary_emergency_contact(self) -> Optional[Dict[str, Any]]:
        """
        Get the primary emergency contact from the database.
        
        Returns:
            Primary emergency contact data if found, None otherwise
        """
        try:
            return self.query_one(
                "SELECT * FROM emergency_contacts WHERE primary_contact = 1"
            )
        except Exception as e:
            logger.error(f"Failed to get primary emergency contact: {str(e)}")
            return None
    
    def delete_emergency_contact(self, contact_id: str) -> bool:
        """
        Delete an emergency contact from the database.
        
        Args:
            contact_id: Emergency contact ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            return self.execute(
                "DELETE FROM emergency_contacts WHERE id = ?",
                (contact_id,)
            )
        except Exception as e:
            logger.error(f"Failed to delete emergency contact: {str(e)}")
            return False
    
    def add_emergency_event(self, event: Dict[str, Any]) -> bool:
        """
        Add an emergency event to the database.
        
        Args:
            event: Emergency event data
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check required fields
            required_fields = ["id", "type", "severity"]
            
            for field in required_fields:
                if field not in event:
                    logger.error(f"Missing required field in emergency event data: {field}")
                    return False
            
            # Set timestamps
            current_time = int(time.time())
            event["created_at"] = current_time
            event["updated_at"] = current_time
            
            # Set default status
            if "status" not in event:
                event["status"] = "detected"
            
            # Insert emergency event
            return self.execute(
                """
                INSERT INTO emergency_events (
                    id, type, severity, location, details, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event["id"],
                    event["type"],
                    event["severity"],
                    event.get("location"),
                    event.get("details"),
                    event["status"],
                    event["created_at"],
                    event["updated_at"]
                )
            )
        except Exception as e:
            logger.error(f"Failed to add emergency event: {str(e)}")
            return False
    
    def update_emergency_event(self, event_id: str, event_data: Dict[str, Any]) -> bool:
        """
        Update an emergency event in the database.
        
        Args:
            event_id: Emergency event ID
            event_data: Emergency event data to update
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Set updated timestamp
            event_data["updated_at"] = int(time.time())
            
            # Build update query
            fields = []
            values = []
            
            for key, value in event_data.items():
                if key != "id":
                    fields.append(f"{key} = ?")
                    values.append(value)
            
            # Add event ID
            values.append(event_id)
            
            # Execute update
            return self.execute(
                f"UPDATE emergency_events SET {', '.join(fields)} WHERE id = ?",
                tuple(values)
            )
        except Exception as e:
            logger.error(f"Failed to update emergency event: {str(e)}")
            return False
    
    def get_emergency_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """
        Get an emergency event from the database.
        
        Args:
            event_id: Emergency event ID
            
        Returns:
            Emergency event data if found, None otherwise
        """
        try:
            return self.query_one(
                "SELECT * FROM emergency_events WHERE id = ?",
                (event_id,)
            )
        except Exception as e:
            logger.error(f"Failed to get emergency event: {str(e)}")
            return None
    
    def get_emergency_events(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get emergency events from the database.
        
        Args:
            limit: Maximum number of events to return
            offset: Offset for pagination
            
        Returns:
            List of emergency event data
        """
        try:
            return self.query(
                """
                SELECT * FROM emergency_events
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset)
            )
        except Exception as e:
            logger.error(f"Failed to get emergency events: {str(e)}")
            return []
    
    def get_active_emergency_events(self) -> List[Dict[str, Any]]:
        """
        Get active emergency events from the database.
        
        Returns:
            List of active emergency event data
        """
        try:
            return self.query(
                """
                SELECT * FROM emergency_events
                WHERE status NOT IN ('resolved', 'false_alarm')
                ORDER BY created_at DESC
                """
            )
        except Exception as e:
            logger.error(f"Failed to get active emergency events: {str(e)}")
            return []
    
    def delete_emergency_event(self, event_id: str) -> bool:
        """
        Delete an emergency event from the database.
        
        Args:
            event_id: Emergency event ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            return self.execute(
                "DELETE FROM emergency_events WHERE id = ?",
                (event_id,)
            )
        except Exception as e:
            logger.error(f"Failed to delete emergency event: {str(e)}")
            return False
    
    def close(self):
        """Close the database connection."""
        try:
            if self.conn:
                self.conn.close()
                self.conn = None
        except Exception as e:
            logger.error(f"Failed to close database connection: {str(e)}")
    
    def __del__(self):
        """Destructor."""
        self.close()


# Example usage
if __name__ == "__main__":
    # Create database manager
    db_manager = DatabaseManager()
    
    try:
        # Add a test user
        db_manager.add_user({
            "id": "user1",
            "name": "John Doe",
            "email": "john.doe@example.com",
            "role": "admin",
            "password_hash": "hash",
            "password_salt": "salt"
        })
        
        # Get the user
        user = db_manager.get_user("user1")
        print(f"User: {user}")
        
        # Add a test device
        db_manager.add_device({
            "id": "device1",
            "name": "Front Door Camera",
            "type": "camera"
        })
        
        # Get the device
        device = db_manager.get_device("device1")
        print(f"Device: {device}")
        
        # Add a test camera
        db_manager.add_camera({
            "id": "camera1",
            "device_id": "device1",
            "name": "Front Door Camera"
        })
        
        # Get the camera
        camera = db_manager.get_camera("camera1")
        print(f"Camera: {camera}")
        
        # Get database stats
        stats = db_manager.get_database_stats()
        print(f"Database stats: {stats}")
        
        # Backup database
        db_manager.backup_database()
    finally:
        # Close database connection
        db_manager.close()
