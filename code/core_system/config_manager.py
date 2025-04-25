#!/usr/bin/env python3
"""
Configuration Manager for Viztron Homebase Module

This module implements the configuration management functionality for the
Viztron Homebase Module, handling system settings, user preferences,
and configuration file management.

Author: Viztron System Team
Date: April 20, 2025
"""

import os
import sys
import time
import logging
import json
import yaml
import threading
import shutil
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/viztron/config_manager.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('config_manager')

class ConfigManager:
    """
    Manages system configuration for the Viztron Homebase Module.
    
    This class provides methods to read, write, and validate
    configuration settings for the system.
    """
    
    def __init__(self, config_dir: str = "/etc/viztron"):
        """
        Initialize the configuration manager.
        
        Args:
            config_dir: Directory containing configuration files
        """
        self.config_dir = config_dir
        
        # Create config directory if it doesn't exist
        os.makedirs(self.config_dir, exist_ok=True)
        
        # Configuration cache
        self.config_cache = {}
        
        # Configuration schemas
        self.schemas = self._load_schemas()
        
        # Configuration lock
        self.config_locks = {}
        
        # Default configurations
        self.default_configs = self._load_default_configs()
        
        logger.info("Configuration manager initialized")
    
    def _load_schemas(self) -> Dict[str, Any]:
        """
        Load configuration schemas.
        
        Returns:
            Dictionary of configuration schemas
        """
        schemas = {}
        schema_dir = os.path.join(self.config_dir, "schemas")
        
        if not os.path.exists(schema_dir):
            logger.warning(f"Schema directory {schema_dir} not found, creating it")
            os.makedirs(schema_dir, exist_ok=True)
            return schemas
        
        for filename in os.listdir(schema_dir):
            if filename.endswith(".json"):
                schema_name = filename[:-5]  # Remove .json extension
                schema_path = os.path.join(schema_dir, filename)
                
                try:
                    with open(schema_path, 'r') as f:
                        schemas[schema_name] = json.load(f)
                    logger.debug(f"Loaded schema: {schema_name}")
                except Exception as e:
                    logger.error(f"Failed to load schema {schema_name}: {str(e)}")
        
        return schemas
    
    def _load_default_configs(self) -> Dict[str, Any]:
        """
        Load default configurations.
        
        Returns:
            Dictionary of default configurations
        """
        defaults = {}
        default_dir = os.path.join(self.config_dir, "defaults")
        
        if not os.path.exists(default_dir):
            logger.warning(f"Default config directory {default_dir} not found, creating it")
            os.makedirs(default_dir, exist_ok=True)
            return defaults
        
        for filename in os.listdir(default_dir):
            if filename.endswith((".json", ".yaml", ".yml")):
                if filename.endswith(".json"):
                    config_name = filename[:-5]  # Remove .json extension
                else:
                    config_name = filename[:-5] if filename.endswith(".yaml") else filename[:-4]  # Remove .yaml or .yml extension
                
                config_path = os.path.join(default_dir, filename)
                
                try:
                    if filename.endswith(".json"):
                        with open(config_path, 'r') as f:
                            defaults[config_name] = json.load(f)
                    else:
                        with open(config_path, 'r') as f:
                            defaults[config_name] = yaml.safe_load(f)
                    logger.debug(f"Loaded default config: {config_name}")
                except Exception as e:
                    logger.error(f"Failed to load default config {config_name}: {str(e)}")
        
        return defaults
    
    def _get_config_lock(self, config_name: str) -> threading.Lock:
        """
        Get lock for a specific configuration.
        
        Args:
            config_name: Name of the configuration
            
        Returns:
            Lock object for the configuration
        """
        if config_name not in self.config_locks:
            self.config_locks[config_name] = threading.Lock()
        
        return self.config_locks[config_name]
    
    def _get_config_path(self, config_name: str) -> str:
        """
        Get path to a configuration file.
        
        Args:
            config_name: Name of the configuration
            
        Returns:
            Path to the configuration file
        """
        # Check if config exists as JSON
        json_path = os.path.join(self.config_dir, f"{config_name}.json")
        if os.path.exists(json_path):
            return json_path
        
        # Check if config exists as YAML
        yaml_path = os.path.join(self.config_dir, f"{config_name}.yaml")
        if os.path.exists(yaml_path):
            return yaml_path
        
        yml_path = os.path.join(self.config_dir, f"{config_name}.yml")
        if os.path.exists(yml_path):
            return yml_path
        
        # Default to JSON if config doesn't exist
        return json_path
    
    def _is_json_config(self, config_path: str) -> bool:
        """
        Check if a configuration file is in JSON format.
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            True if the configuration is in JSON format, False otherwise
        """
        return config_path.endswith(".json")
    
    def get_config(self, config_name: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Get a configuration.
        
        Args:
            config_name: Name of the configuration
            use_cache: Whether to use cached configuration
            
        Returns:
            Configuration dictionary
        """
        # Check cache first
        if use_cache and config_name in self.config_cache:
            return self.config_cache[config_name]
        
        # Get config path
        config_path = self._get_config_path(config_name)
        
        # Get lock for this config
        with self._get_config_lock(config_name):
            # Check if config file exists
            if not os.path.exists(config_path):
                logger.warning(f"Configuration {config_name} not found, using defaults")
                
                # Use default config if available
                if config_name in self.default_configs:
                    config = self.default_configs[config_name]
                    
                    # Save default config to file
                    self.set_config(config_name, config)
                    
                    return config
                else:
                    # Return empty config
                    return {}
            
            try:
                # Read config file
                if self._is_json_config(config_path):
                    with open(config_path, 'r') as f:
                        config = json.load(f)
                else:
                    with open(config_path, 'r') as f:
                        config = yaml.safe_load(f)
                
                # Cache config
                self.config_cache[config_name] = config
                
                return config
            except Exception as e:
                logger.error(f"Failed to read configuration {config_name}: {str(e)}")
                
                # Use default config if available
                if config_name in self.default_configs:
                    logger.warning(f"Using default configuration for {config_name}")
                    return self.default_configs[config_name]
                else:
                    # Return empty config
                    return {}
    
    def set_config(self, config_name: str, config: Dict[str, Any]) -> bool:
        """
        Set a configuration.
        
        Args:
            config_name: Name of the configuration
            config: Configuration dictionary
            
        Returns:
            True if successful, False otherwise
        """
        # Get config path
        config_path = self._get_config_path(config_name)
        
        # Get lock for this config
        with self._get_config_lock(config_name):
            try:
                # Create backup of existing config
                if os.path.exists(config_path):
                    backup_path = f"{config_path}.bak"
                    shutil.copy2(config_path, backup_path)
                
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(config_path), exist_ok=True)
                
                # Write config file
                if self._is_json_config(config_path):
                    with open(config_path, 'w') as f:
                        json.dump(config, f, indent=2)
                else:
                    with open(config_path, 'w') as f:
                        yaml.dump(config, f, default_flow_style=False)
                
                # Update cache
                self.config_cache[config_name] = config
                
                logger.info(f"Configuration {config_name} updated")
                return True
            except Exception as e:
                logger.error(f"Failed to write configuration {config_name}: {str(e)}")
                return False
    
    def update_config(self, config_name: str, updates: Dict[str, Any]) -> bool:
        """
        Update a configuration with partial changes.
        
        Args:
            config_name: Name of the configuration
            updates: Dictionary of updates to apply
            
        Returns:
            True if successful, False otherwise
        """
        # Get current config
        current_config = self.get_config(config_name)
        
        # Apply updates
        self._deep_update(current_config, updates)
        
        # Save updated config
        return self.set_config(config_name, current_config)
    
    def _deep_update(self, target: Dict[str, Any], source: Dict[str, Any]):
        """
        Deep update a dictionary with another dictionary.
        
        Args:
            target: Target dictionary to update
            source: Source dictionary with updates
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_update(target[key], value)
            else:
                target[key] = value
    
    def validate_config(self, config_name: str, config: Optional[Dict[str, Any]] = None) -> Tuple[bool, List[str]]:
        """
        Validate a configuration against its schema.
        
        Args:
            config_name: Name of the configuration
            config: Configuration dictionary to validate (if None, loads from file)
            
        Returns:
            Tuple of (is_valid, error_messages)
        """
        # Check if schema exists
        if config_name not in self.schemas:
            logger.warning(f"No schema found for configuration {config_name}")
            return True, []
        
        # Get config if not provided
        if config is None:
            config = self.get_config(config_name)
        
        # Get schema
        schema = self.schemas[config_name]
        
        # Validate config against schema
        try:
            import jsonschema
            
            jsonschema.validate(instance=config, schema=schema)
            return True, []
        except jsonschema.exceptions.ValidationError as e:
            logger.error(f"Configuration {config_name} validation failed: {str(e)}")
            return False, [str(e)]
        except Exception as e:
            logger.error(f"Error validating configuration {config_name}: {str(e)}")
            return False, [str(e)]
    
    def reset_config(self, config_name: str) -> bool:
        """
        Reset a configuration to its default values.
        
        Args:
            config_name: Name of the configuration
            
        Returns:
            True if successful, False otherwise
        """
        # Check if default config exists
        if config_name not in self.default_configs:
            logger.error(f"No default configuration found for {config_name}")
            return False
        
        # Get default config
        default_config = self.default_configs[config_name]
        
        # Save default config
        return self.set_config(config_name, default_config)
    
    def list_configs(self) -> List[str]:
        """
        List all available configurations.
        
        Returns:
            List of configuration names
        """
        configs = set()
        
        # Add configs from directory
        for filename in os.listdir(self.config_dir):
            if filename.endswith((".json", ".yaml", ".yml")) and not os.path.isdir(os.path.join(self.config_dir, filename)):
                if filename.endswith(".json"):
                    config_name = filename[:-5]  # Remove .json extension
                elif filename.endswith(".yaml"):
                    config_name = filename[:-5]  # Remove .yaml extension
                else:
                    config_name = filename[:-4]  # Remove .yml extension
                
                configs.add(config_name)
        
        # Add configs from defaults
        for config_name in self.default_configs:
            configs.add(config_name)
        
        return sorted(list(configs))
    
    def get_config_schema(self, config_name: str) -> Optional[Dict[str, Any]]:
        """
        Get schema for a configuration.
        
        Args:
            config_name: Name of the configuration
            
        Returns:
            Schema dictionary if available, None otherwise
        """
        return self.schemas.get(config_name)
    
    def set_config_schema(self, config_name: str, schema: Dict[str, Any]) -> bool:
        """
        Set schema for a configuration.
        
        Args:
            config_name: Name of the configuration
            schema: Schema dictionary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create schema directory if it doesn't exist
            schema_dir = os.path.join(self.config_dir, "schemas")
            os.makedirs(schema_dir, exist_ok=True)
            
            # Write schema file
            schema_path = os.path.join(schema_dir, f"{config_name}.json")
            with open(schema_path, 'w') as f:
                json.dump(schema, f, indent=2)
            
            # Update in-memory schema
            self.schemas[config_name] = schema
            
            logger.info(f"Schema for configuration {config_name} updated")
            return True
        except Exception as e:
            logger.error(f"Failed to write schema for configuration {config_name}: {str(e)}")
            return False
    
    def get_default_config(self, config_name: str) -> Optional[Dict[str, Any]]:
        """
        Get default configuration.
        
        Args:
            config_name: Name of the configuration
            
        Returns:
            Default configuration dictionary if available, None otherwise
        """
        return self.default_configs.get(config_name)
    
    def set_default_config(self, config_name: str, config: Dict[str, Any]) -> bool:
        """
        Set default configuration.
        
        Args:
            config_name: Name of the configuration
            config: Default configuration dictionary
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create defaults directory if it doesn't exist
            default_dir = os.path.join(self.config_dir, "defaults")
            os.makedirs(default_dir, exist_ok=True)
            
            # Write default config file
            default_path = os.path.join(default_dir, f"{config_name}.json")
            with open(default_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            # Update in-memory defaults
            self.default_configs[config_name] = config
            
            logger.info(f"Default configuration for {config_name} updated")
            return True
        except Exception as e:
            logger.error(f"Failed to write default configuration for {config_name}: {str(e)}")
            return False
    
    def export_config(self, config_name: str, export_path: str) -> bool:
        """
        Export a configuration to a file.
        
        Args:
            config_name: Name of the configuration
            export_path: Path to export the configuration to
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get config
            config = self.get_config(config_name)
            
            # Determine format based on export path
            if export_path.endswith(".json"):
                with open(export_path, 'w') as f:
                    json.dump(config, f, indent=2)
            elif export_path.endswith((".yaml", ".yml")):
                with open(export_path, 'w') as f:
                    yaml.dump(config, f, default_flow_style=False)
            else:
                # Default to JSON
                with open(export_path, 'w') as f:
                    json.dump(config, f, indent=2)
            
            logger.info(f"Configuration {config_name} exported to {export_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to export configuration {config_name}: {str(e)}")
            return False
    
    def import_config(self, config_name: str, import_path: str) -> bool:
        """
        Import a configuration from a file.
        
        Args:
            config_name: Name of the configuration
            import_path: Path to import the configuration from
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Determine format based on import path
            if import_path.endswith(".json"):
                with open(import_path, 'r') as f:
                    config = json.load(f)
            elif import_path.endswith((".yaml", ".yml")):
                with open(import_path, 'r') as f:
                    config = yaml.safe_load(f)
            else:
                # Try JSON first, then YAML
                try:
                    with open(import_path, 'r') as f:
                        config = json.load(f)
                except json.JSONDecodeError:
                    with open(import_path, 'r') as f:
                        config = yaml.safe_load(f)
            
            # Validate config if schema exists
            if config_name in self.schemas:
                is_valid, errors = self.validate_config(config_name, config)
                if not is_valid:
                    logger.error(f"Imported configuration {config_name} is invalid: {errors}")
                    return False
            
            # Save config
            result = self.set_config(config_name, config)
            
            if result:
                logger.info(f"Configuration {config_name} imported from {import_path}")
            
            return result
        except Exception as e:
            logger.error(f"Failed to import configuration {config_name}: {str(e)}")
            return False
    
    def backup_all_configs(self, backup_dir: Optional[str] = None) -> Optional[str]:
        """
        Backup all configurations to a directory.
        
        Args:
            backup_dir: Directory to store backups (if None, creates a timestamped directory)
            
        Returns:
            Path to backup directory if successful, None otherwise
        """
        try:
            # Create backup directory if not provided
            if backup_dir is None:
                timestamp = time.strftime("%Y%m%d-%H%M%S")
                backup_dir = os.path.join(self.config_dir, "backups", f"config-backup-{timestamp}")
            
            # Create backup directory
            os.makedirs(backup_dir, exist_ok=True)
            
            # Get all configs
            config_names = self.list_configs()
            
            # Backup each config
            for config_name in config_names:
                config = self.get_config(config_name)
                
                # Determine format based on original file
                config_path = self._get_config_path(config_name)
                if self._is_json_config(config_path):
                    backup_path = os.path.join(backup_dir, f"{config_name}.json")
                    with open(backup_path, 'w') as f:
                        json.dump(config, f, indent=2)
                else:
                    backup_path = os.path.join(backup_dir, f"{config_name}.yaml")
                    with open(backup_path, 'w') as f:
                        yaml.dump(config, f, default_flow_style=False)
            
            # Backup schemas
            schema_dir = os.path.join(backup_dir, "schemas")
            os.makedirs(schema_dir, exist_ok=True)
            
            for schema_name, schema in self.schemas.items():
                schema_path = os.path.join(schema_dir, f"{schema_name}.json")
                with open(schema_path, 'w') as f:
                    json.dump(schema, f, indent=2)
            
            # Backup defaults
            default_dir = os.path.join(backup_dir, "defaults")
            os.makedirs(default_dir, exist_ok=True)
            
            for default_name, default_config in self.default_configs.items():
                default_path = os.path.join(default_dir, f"{default_name}.json")
                with open(default_path, 'w') as f:
                    json.dump(default_config, f, indent=2)
            
            logger.info(f"All configurations backed up to {backup_dir}")
            return backup_dir
        except Exception as e:
            logger.error(f"Failed to backup configurations: {str(e)}")
            return None
    
    def restore_all_configs(self, backup_dir: str) -> bool:
        """
        Restore all configurations from a backup directory.
        
        Args:
            backup_dir: Directory containing configuration backups
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check if backup directory exists
            if not os.path.exists(backup_dir) or not os.path.isdir(backup_dir):
                logger.error(f"Backup directory {backup_dir} not found")
                return False
            
            # Backup current configs before restoring
            self.backup_all_configs()
            
            # Restore configs
            for filename in os.listdir(backup_dir):
                if filename.endswith((".json", ".yaml", ".yml")) and not os.path.isdir(os.path.join(backup_dir, filename)):
                    if filename.endswith(".json"):
                        config_name = filename[:-5]  # Remove .json extension
                    elif filename.endswith(".yaml"):
                        config_name = filename[:-5]  # Remove .yaml extension
                    else:
                        config_name = filename[:-4]  # Remove .yml extension
                    
                    # Import config
                    self.import_config(config_name, os.path.join(backup_dir, filename))
            
            # Restore schemas
            schema_dir = os.path.join(backup_dir, "schemas")
            if os.path.exists(schema_dir) and os.path.isdir(schema_dir):
                for filename in os.listdir(schema_dir):
                    if filename.endswith(".json"):
                        schema_name = filename[:-5]  # Remove .json extension
                        schema_path = os.path.join(schema_dir, filename)
                        
                        try:
                            with open(schema_path, 'r') as f:
                                schema = json.load(f)
                            
                            self.set_config_schema(schema_name, schema)
                        except Exception as e:
                            logger.error(f"Failed to restore schema {schema_name}: {str(e)}")
            
            # Restore defaults
            default_dir = os.path.join(backup_dir, "defaults")
            if os.path.exists(default_dir) and os.path.isdir(default_dir):
                for filename in os.listdir(default_dir):
                    if filename.endswith(".json"):
                        default_name = filename[:-5]  # Remove .json extension
                        default_path = os.path.join(default_dir, filename)
                        
                        try:
                            with open(default_path, 'r') as f:
                                default_config = json.load(f)
                            
                            self.set_default_config(default_name, default_config)
                        except Exception as e:
                            logger.error(f"Failed to restore default config {default_name}: {str(e)}")
            
            # Reload schemas and defaults
            self.schemas = self._load_schemas()
            self.default_configs = self._load_default_configs()
            
            # Clear cache
            self.config_cache = {}
            
            logger.info(f"All configurations restored from {backup_dir}")
            return True
        except Exception as e:
            logger.error(f"Failed to restore configurations: {str(e)}")
            return False


class UserPreferencesManager:
    """
    Manages user preferences for the Viztron Homebase Module.
    
    This class provides methods to read, write, and validate
    user preferences for the system.
    """
    
    def __init__(self, config_manager: ConfigManager, preferences_dir: str = "/var/lib/viztron/preferences"):
        """
        Initialize the user preferences manager.
        
        Args:
            config_manager: Configuration manager instance
            preferences_dir: Directory containing user preferences
        """
        self.config_manager = config_manager
        self.preferences_dir = preferences_dir
        
        # Create preferences directory if it doesn't exist
        os.makedirs(self.preferences_dir, exist_ok=True)
        
        # Preferences cache
        self.preferences_cache = {}
        
        # Preferences locks
        self.preferences_locks = {}
        
        logger.info("User preferences manager initialized")
    
    def _get_preferences_lock(self, user_id: str) -> threading.Lock:
        """
        Get lock for a specific user's preferences.
        
        Args:
            user_id: User ID
            
        Returns:
            Lock object for the user's preferences
        """
        if user_id not in self.preferences_locks:
            self.preferences_locks[user_id] = threading.Lock()
        
        return self.preferences_locks[user_id]
    
    def _get_preferences_path(self, user_id: str) -> str:
        """
        Get path to a user's preferences file.
        
        Args:
            user_id: User ID
            
        Returns:
            Path to the user's preferences file
        """
        return os.path.join(self.preferences_dir, f"{user_id}.json")
    
    def get_preferences(self, user_id: str, use_cache: bool = True) -> Dict[str, Any]:
        """
        Get a user's preferences.
        
        Args:
            user_id: User ID
            use_cache: Whether to use cached preferences
            
        Returns:
            User preferences dictionary
        """
        # Check cache first
        if use_cache and user_id in self.preferences_cache:
            return self.preferences_cache[user_id]
        
        # Get preferences path
        preferences_path = self._get_preferences_path(user_id)
        
        # Get lock for this user
        with self._get_preferences_lock(user_id):
            # Check if preferences file exists
            if not os.path.exists(preferences_path):
                logger.debug(f"Preferences for user {user_id} not found, using defaults")
                
                # Get default preferences
                default_preferences = self.config_manager.get_config("default_preferences")
                
                # Save default preferences for this user
                self.set_preferences(user_id, default_preferences)
                
                return default_preferences
            
            try:
                # Read preferences file
                with open(preferences_path, 'r') as f:
                    preferences = json.load(f)
                
                # Cache preferences
                self.preferences_cache[user_id] = preferences
                
                return preferences
            except Exception as e:
                logger.error(f"Failed to read preferences for user {user_id}: {str(e)}")
                
                # Get default preferences
                default_preferences = self.config_manager.get_config("default_preferences")
                
                return default_preferences
    
    def set_preferences(self, user_id: str, preferences: Dict[str, Any]) -> bool:
        """
        Set a user's preferences.
        
        Args:
            user_id: User ID
            preferences: User preferences dictionary
            
        Returns:
            True if successful, False otherwise
        """
        # Get preferences path
        preferences_path = self._get_preferences_path(user_id)
        
        # Get lock for this user
        with self._get_preferences_lock(user_id):
            try:
                # Create backup of existing preferences
                if os.path.exists(preferences_path):
                    backup_path = f"{preferences_path}.bak"
                    shutil.copy2(preferences_path, backup_path)
                
                # Create directory if it doesn't exist
                os.makedirs(os.path.dirname(preferences_path), exist_ok=True)
                
                # Write preferences file
                with open(preferences_path, 'w') as f:
                    json.dump(preferences, f, indent=2)
                
                # Update cache
                self.preferences_cache[user_id] = preferences
                
                logger.info(f"Preferences for user {user_id} updated")
                return True
            except Exception as e:
                logger.error(f"Failed to write preferences for user {user_id}: {str(e)}")
                return False
    
    def update_preferences(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update a user's preferences with partial changes.
        
        Args:
            user_id: User ID
            updates: Dictionary of updates to apply
            
        Returns:
            True if successful, False otherwise
        """
        # Get current preferences
        current_preferences = self.get_preferences(user_id)
        
        # Apply updates
        self._deep_update(current_preferences, updates)
        
        # Save updated preferences
        return self.set_preferences(user_id, current_preferences)
    
    def _deep_update(self, target: Dict[str, Any], source: Dict[str, Any]):
        """
        Deep update a dictionary with another dictionary.
        
        Args:
            target: Target dictionary to update
            source: Source dictionary with updates
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_update(target[key], value)
            else:
                target[key] = value
    
    def reset_preferences(self, user_id: str) -> bool:
        """
        Reset a user's preferences to default values.
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful, False otherwise
        """
        # Get default preferences
        default_preferences = self.config_manager.get_config("default_preferences")
        
        # Save default preferences for this user
        return self.set_preferences(user_id, default_preferences)
    
    def list_users(self) -> List[str]:
        """
        List all users with preferences.
        
        Returns:
            List of user IDs
        """
        users = []
        
        for filename in os.listdir(self.preferences_dir):
            if filename.endswith(".json"):
                user_id = filename[:-5]  # Remove .json extension
                users.append(user_id)
        
        return sorted(users)
    
    def delete_user(self, user_id: str) -> bool:
        """
        Delete a user's preferences.
        
        Args:
            user_id: User ID
            
        Returns:
            True if successful, False otherwise
        """
        # Get preferences path
        preferences_path = self._get_preferences_path(user_id)
        
        # Get lock for this user
        with self._get_preferences_lock(user_id):
            try:
                # Check if preferences file exists
                if not os.path.exists(preferences_path):
                    logger.warning(f"Preferences for user {user_id} not found")
                    return True
                
                # Delete preferences file
                os.remove(preferences_path)
                
                # Remove from cache
                if user_id in self.preferences_cache:
                    del self.preferences_cache[user_id]
                
                logger.info(f"Preferences for user {user_id} deleted")
                return True
            except Exception as e:
                logger.error(f"Failed to delete preferences for user {user_id}: {str(e)}")
                return False
    
    def export_preferences(self, user_id: str, export_path: str) -> bool:
        """
        Export a user's preferences to a file.
        
        Args:
            user_id: User ID
            export_path: Path to export the preferences to
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get preferences
            preferences = self.get_preferences(user_id)
            
            # Write preferences file
            with open(export_path, 'w') as f:
                json.dump(preferences, f, indent=2)
            
            logger.info(f"Preferences for user {user_id} exported to {export_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to export preferences for user {user_id}: {str(e)}")
            return False
    
    def import_preferences(self, user_id: str, import_path: str) -> bool:
        """
        Import a user's preferences from a file.
        
        Args:
            user_id: User ID
            import_path: Path to import the preferences from
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Read preferences file
            with open(import_path, 'r') as f:
                preferences = json.load(f)
            
            # Save preferences
            result = self.set_preferences(user_id, preferences)
            
            if result:
                logger.info(f"Preferences for user {user_id} imported from {import_path}")
            
            return result
        except Exception as e:
            logger.error(f"Failed to import preferences for user {user_id}: {str(e)}")
            return False
    
    def backup_all_preferences(self, backup_dir: Optional[str] = None) -> Optional[str]:
        """
        Backup all user preferences to a directory.
        
        Args:
            backup_dir: Directory to store backups (if None, creates a timestamped directory)
            
        Returns:
            Path to backup directory if successful, None otherwise
        """
        try:
            # Create backup directory if not provided
            if backup_dir is None:
                timestamp = time.strftime("%Y%m%d-%H%M%S")
                backup_dir = os.path.join(self.preferences_dir, "backups", f"preferences-backup-{timestamp}")
            
            # Create backup directory
            os.makedirs(backup_dir, exist_ok=True)
            
            # Get all users
            users = self.list_users()
            
            # Backup each user's preferences
            for user_id in users:
                preferences = self.get_preferences(user_id)
                
                backup_path = os.path.join(backup_dir, f"{user_id}.json")
                with open(backup_path, 'w') as f:
                    json.dump(preferences, f, indent=2)
            
            logger.info(f"All user preferences backed up to {backup_dir}")
            return backup_dir
        except Exception as e:
            logger.error(f"Failed to backup user preferences: {str(e)}")
            return None
    
    def restore_all_preferences(self, backup_dir: str) -> bool:
        """
        Restore all user preferences from a backup directory.
        
        Args:
            backup_dir: Directory containing user preferences backups
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Check if backup directory exists
            if not os.path.exists(backup_dir) or not os.path.isdir(backup_dir):
                logger.error(f"Backup directory {backup_dir} not found")
                return False
            
            # Backup current preferences before restoring
            self.backup_all_preferences()
            
            # Restore preferences
            for filename in os.listdir(backup_dir):
                if filename.endswith(".json"):
                    user_id = filename[:-5]  # Remove .json extension
                    
                    # Import preferences
                    self.import_preferences(user_id, os.path.join(backup_dir, filename))
            
            # Clear cache
            self.preferences_cache = {}
            
            logger.info(f"All user preferences restored from {backup_dir}")
            return True
        except Exception as e:
            logger.error(f"Failed to restore user preferences: {str(e)}")
            return False


# Example usage
if __name__ == "__main__":
    # Create configuration manager
    config_manager = ConfigManager()
    
    # Create user preferences manager
    preferences_manager = UserPreferencesManager(config_manager)
    
    try:
        # List available configurations
        configs = config_manager.list_configs()
        print(f"Available configurations: {configs}")
        
        # Get a configuration
        system_config = config_manager.get_config("system")
        print(f"System configuration: {system_config}")
        
        # Update a configuration
        config_manager.update_config("system", {"log_level": "DEBUG"})
        
        # List users with preferences
        users = preferences_manager.list_users()
        print(f"Users with preferences: {users}")
        
        # Get user preferences
        if users:
            user_id = users[0]
            preferences = preferences_manager.get_preferences(user_id)
            print(f"Preferences for user {user_id}: {preferences}")
        
        # Create backup of all configurations
        backup_dir = config_manager.backup_all_configs()
        print(f"Configurations backed up to: {backup_dir}")
        
        print("\nConfiguration manager running. Press Ctrl+C to exit.")
        
        # Main loop
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nExiting...")
