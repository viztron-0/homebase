#!/usr/bin/env python3
"""
Face Recognition Module for Viztron Homebase Module

This module implements face recognition using ArcFace for the
Viztron Homebase Module AI pipeline.

Author: Viztron AI Team
Date: April 19, 2025
"""

import cv2
import numpy as np
import time
import os
import logging
import sqlite3
from typing import List, Dict, Tuple, Optional, Any
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('face_recognition')

class FaceDetector:
    """
    RetinaFace face detector optimized for BeagleBoard Y-AI NPU.
    
    This class handles loading the model, preprocessing frames,
    running inference, and postprocessing results.
    """
    
    def __init__(
        self,
        model_path: str = "/opt/viztron/models/retinaface_mobile_int8.onnx",
        conf_threshold: float = 0.5,
        nms_threshold: float = 0.4,
        input_size: Tuple[int, int] = (320, 320),
        device: str = "NPU"
    ):
        """
        Initialize the face detector.
        
        Args:
            model_path: Path to the ONNX model file
            conf_threshold: Confidence threshold for detections
            nms_threshold: Non-maximum suppression threshold
            input_size: Input size for the model (width, height)
            device: Device to run inference on ("NPU", "CPU", or "GPU")
        """
        self.model_path = model_path
        self.conf_threshold = conf_threshold
        self.nms_threshold = nms_threshold
        self.input_size = input_size
        self.device = device
        
        # Load model
        self._load_model()
        
        # Warmup the model
        self._warmup()
        
        logger.info(f"Face detector initialized with {device} device")
    
    def _load_model(self):
        """Load the RetinaFace model using OpenCV's DNN module with NPU support."""
        try:
            # Check if model file exists
            if not os.path.exists(self.model_path):
                raise FileNotFoundError(f"Model file not found: {self.model_path}")
            
            # Load the model
            self.net = cv2.dnn.readNetFromONNX(self.model_path)
            
            # Set the target device
            if self.device == "NPU":
                # Configure for NPU acceleration
                self.net.setPreferableBackend(cv2.dnn.DNN_BACKEND_TIMVX)
                self.net.setPreferableTarget(cv2.dnn.DNN_TARGET_NPU)
            elif self.device == "GPU":
                # Configure for GPU acceleration
                self.net.setPreferableBackend(cv2.dnn.DNN_BACKEND_CUDA)
                self.net.setPreferableTarget(cv2.dnn.DNN_TARGET_CUDA)
            else:
                # Default to CPU
                self.net.setPreferableBackend(cv2.dnn.DNN_BACKEND_OPENCV)
                self.net.setPreferableTarget(cv2.dnn.DNN_TARGET_CPU)
            
            logger.info(f"Face detection model loaded successfully from {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to load face detection model: {str(e)}")
            raise
    
    def _warmup(self):
        """Warm up the model with a dummy input."""
        try:
            # Create a dummy input
            dummy_input = np.zeros((1, 3, *self.input_size), dtype=np.float32)
            
            # Run inference
            self.net.setInput(dummy_input)
            self.net.forward(self.net.getUnconnectedOutLayersNames())
            
            logger.info("Face detection model warmup completed successfully")
        except Exception as e:
            logger.warning(f"Face detection model warmup failed: {str(e)}")
    
    def preprocess(self, frame: np.ndarray) -> Tuple[np.ndarray, float, float]:
        """
        Preprocess the frame for inference.
        
        Args:
            frame: Input frame (BGR format)
            
        Returns:
            Tuple of (preprocessed blob, width scale, height scale)
        """
        # Get original dimensions
        original_height, original_width = frame.shape[:2]
        
        # Calculate scale factors
        width_scale = original_width / self.input_size[0]
        height_scale = original_height / self.input_size[1]
        
        # Create a blob from the frame
        blob = cv2.dnn.blobFromImage(
            frame, 
            1.0,  # Scale factor
            self.input_size,  # Resize to input dimensions
            (104.0, 117.0, 123.0),  # Mean subtraction
            swapRB=False,  # BGR format
            crop=False
        )
        
        return blob, width_scale, height_scale
    
    def detect(self, frame: np.ndarray) -> List[Dict[str, Any]]:
        """
        Detect faces in a frame.
        
        Args:
            frame: Input frame (BGR format)
            
        Returns:
            List of face detection results, each containing:
            - bbox: Bounding box [x1, y1, x2, y2]
            - confidence: Detection confidence
            - landmarks: 5 facial landmarks (10 values: x1,y1,x2,y2,...)
        """
        # Measure inference time
        start_time = time.time()
        
        # Preprocess the frame
        blob, width_scale, height_scale = self.preprocess(frame)
        
        # Set the input to the network
        self.net.setInput(blob)
        
        # Run inference
        outputs = self.net.forward(self.net.getUnconnectedOutLayersNames())
        
        # Process the outputs
        results = self._process_output(outputs, width_scale, height_scale)
        
        # Calculate inference time
        inference_time = time.time() - start_time
        logger.debug(f"Face detection inference time: {inference_time:.4f} seconds")
        
        return results
    
    def _process_output(
        self, 
        outputs: List[np.ndarray], 
        width_scale: float, 
        height_scale: float
    ) -> List[Dict[str, Any]]:
        """
        Process the model output to extract face detections.
        
        Args:
            outputs: Model outputs
            width_scale: Scale factor for width
            height_scale: Scale factor for height
            
        Returns:
            List of face detection results
        """
        # Initialize lists for bounding boxes, confidences, and landmarks
        boxes = []
        confidences = []
        landmarks = []
        
        # Process each output
        # RetinaFace outputs: [bboxes, landmarks, confidences]
        bboxes = outputs[0][0]
        face_landmarks = outputs[1][0]
        scores = outputs[2][0]
        
        # Process each detection
        for i in range(bboxes.shape[0]):
            confidence = scores[i]
            
            # Filter by confidence threshold
            if confidence >= self.conf_threshold:
                # Get bounding box coordinates
                x1, y1, x2, y2 = bboxes[i]
                
                # Scale back to original image
                x1 = int(x1 * width_scale)
                y1 = int(y1 * height_scale)
                x2 = int(x2 * width_scale)
                y2 = int(y2 * height_scale)
                
                # Get landmarks
                landmark = face_landmarks[i].reshape(-1)
                
                # Scale landmarks to original image
                landmark_scaled = []
                for j in range(0, len(landmark), 2):
                    landmark_scaled.append(landmark[j] * width_scale)
                    landmark_scaled.append(landmark[j+1] * height_scale)
                
                # Add to lists
                boxes.append([x1, y1, x2, y2])
                confidences.append(float(confidence))
                landmarks.append(landmark_scaled)
        
        # Apply non-maximum suppression
        indices = cv2.dnn.NMSBoxes(
            boxes, 
            confidences, 
            self.conf_threshold, 
            self.nms_threshold
        )
        
        # Prepare results
        results = []
        for i in indices:
            # Get index (OpenCV 4.5.4+ returns flat array)
            idx = i if isinstance(i, int) else i[0]
            
            # Get detection details
            box = boxes[idx]
            confidence = confidences[idx]
            landmark = landmarks[idx]
            
            # Add to results
            results.append({
                "bbox": box,  # [x1, y1, x2, y2]
                "confidence": confidence,
                "landmarks": landmark  # [x1, y1, x2, y2, x3, y3, x4, y4, x5, y5]
            })
        
        return results
    
    def extract_face(
        self, 
        frame: np.ndarray, 
        detection: Dict[str, Any],
        target_size: Tuple[int, int] = (112, 112),
        margin: float = 0.2
    ) -> np.ndarray:
        """
        Extract and align a face from the frame based on detection.
        
        Args:
            frame: Input frame (BGR format)
            detection: Face detection result
            target_size: Size of the output face image
            margin: Margin around the face as a fraction of face size
            
        Returns:
            Aligned face image
        """
        # Get bounding box and landmarks
        bbox = detection["bbox"]
        landmarks = detection["landmarks"]
        
        # Convert landmarks to numpy array
        landmarks = np.array(landmarks).reshape(5, 2)
        
        # Calculate face width and height
        face_width = bbox[2] - bbox[0]
        face_height = bbox[3] - bbox[1]
        
        # Add margin
        margin_x = int(face_width * margin)
        margin_y = int(face_height * margin)
        
        # Expand bounding box with margin
        x1 = max(0, bbox[0] - margin_x)
        y1 = max(0, bbox[1] - margin_y)
        x2 = min(frame.shape[1], bbox[2] + margin_x)
        y2 = min(frame.shape[0], bbox[3] + margin_y)
        
        # Extract face region
        face = frame[y1:y2, x1:x2]
        
        # Resize to target size
        face = cv2.resize(face, target_size)
        
        return face
    
    def draw_detections(self, frame: np.ndarray, detections: List[Dict[str, Any]]) -> np.ndarray:
        """
        Draw face detection results on the frame.
        
        Args:
            frame: Input frame
            detections: Face detection results from detect()
            
        Returns:
            Frame with detections drawn
        """
        # Make a copy of the frame
        output = frame.copy()
        
        # Draw each detection
        for detection in detections:
            # Extract information
            box = detection["bbox"]
            confidence = detection["confidence"]
            landmarks = detection["landmarks"]
            
            # Draw bounding box
            cv2.rectangle(
                output, 
                (box[0], box[1]), 
                (box[2], box[3]), 
                (0, 255, 0), 
                2
            )
            
            # Draw label
            label = f"Face: {confidence:.2f}"
            cv2.putText(
                output, 
                label, 
                (box[0], box[1] - 10), 
                cv2.FONT_HERSHEY_SIMPLEX, 
                0.5, 
                (0, 255, 0), 
                2
            )
            
            # Draw landmarks
            for i in range(0, len(landmarks), 2):
                cv2.circle(
                    output, 
                    (int(landmarks[i]), int(landmarks[i+1])), 
                    2, 
                    (0, 0, 255), 
                    -1
                )
        
        return output


class ArcFaceRecognizer:
    """
    ArcFace face recognition model optimized for BeagleBoard Y-AI NPU.
    
    This class handles loading the model, preprocessing faces,
    running inference, and generating face embeddings.
    """
    
    def __init__(
        self,
        model_path: str = "/opt/viztron/models/arcface_resnet50_int8.onnx",
        input_size: Tuple[int, int] = (112, 112),
        device: str = "NPU"
    ):
        """
        Initialize the ArcFace recognizer.
        
        Args:
            model_path: Path to the ONNX model file
            input_size: Input size for the model (width, height)
            device: Device to run inference on ("NPU", "CPU", or "GPU")
        """
        self.model_path = model_path
        self.input_size = input_size
        self.device = device
        
        # Load model
        self._load_model()
        
        # Warmup the model
        self._warmup()
        
        logger.info(f"ArcFace recognizer initialized with {device} device")
    
    def _load_model(self):
        """Load the ArcFace model using OpenCV's DNN module with NPU support."""
        try:
            # Check if model file exists
            if not os.path.exists(self.model_path):
                raise FileNotFoundError(f"Model file not found: {self.model_path}")
            
            # Load the model
            self.net = cv2.dnn.readNetFromONNX(self.model_path)
            
            # Set the target device
            if self.device == "NPU":
                # Configure for NPU acceleration
                self.net.setPreferableBackend(cv2.dnn.DNN_BACKEND_TIMVX)
                self.net.setPreferableTarget(cv2.dnn.DNN_TARGET_NPU)
            elif self.device == "GPU":
                # Configure for GPU acceleration
                self.net.setPreferableBackend(cv2.dnn.DNN_BACKEND_CUDA)
                self.net.setPreferableTarget(cv2.dnn.DNN_TARGET_CUDA)
            else:
                # Default to CPU
                self.net.setPreferableBackend(cv2.dnn.DNN_BACKEND_OPENCV)
                self.net.setPreferableTarget(cv2.dnn.DNN_TARGET_CPU)
            
            logger.info(f"ArcFace model loaded successfully from {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to load ArcFace model: {str(e)}")
            raise
    
    def _warmup(self):
        """Warm up the model with a dummy input."""
        try:
            # Create a dummy input
            dummy_input = np.zeros((1, 3, *self.input_size), dtype=np.float32)
            
            # Run inference
            self.net.setInput(dummy_input)
            self.net.forward()
            
            logger.info("ArcFace model warmup completed successfully")
        except Exception as e:
            logger.warning(f"ArcFace model warmup failed: {str(e)}")
    
    def preprocess(self, face: np.ndarray) -> np.ndarray:
        """
        Preprocess the face for inference.
        
        Args:
            face: Face image (BGR format)
            
        Returns:
            Preprocessed blob
        """
        # Resize if needed
        if face.shape[:2] != self.input_size:
            face = cv2.resize(face, self.input_size)
        
        # Normalize pixel values
        face = face.astype(np.float32) / 255.0
        
        # Standardize
        mean = np.array([0.5, 0.5, 0.5], dtype=np.float32)
        std = np.array([0.5, 0.5, 0.5], dtype=np.float32)
        face = (face - mean) / std
        
        # Create a blob from the face
        blob = cv2.dnn.blobFromImage(
            face, 
            1.0,  # Scale factor
            self.input_size,  # Resize to input dimensions
            (0, 0, 0),  # No mean subtraction (already done)
            swapRB=False,  # BGR format
            crop=False
        )
        
        return blob
    
    def get_embedding(self, face: np.ndarray) -> np.ndarray:
        """
        Generate embedding for a face.
        
        Args:
            face: Face image (BGR format)
            
        Returns:
            Face embedding (512-dimensional vector)
        """
        # Measure inference time
        start_time = time.time()
        
        # Preprocess the face
        blob = self.preprocess(face)
        
        # Set the input to the network
        self.net.setInput(blob)
        
        # Run inference
        embedding = self.net.forward()
        
        # Normalize embedding
        embedding = embedding / np.linalg.norm(embedding)
        
        # Calculate inference time
        inference_time = time.time() - start_time
        logger.debug(f"ArcFace inference time: {inference_time:.4f} seconds")
        
        return embedding.flatten()
    
    def compute_similarity(self, embedding1: np.ndarray, embedding2: np.ndarray) -> float:
        """
        Compute similarity between two face embeddings.
        
        Args:
            embedding1: First face embedding
            embedding2: Second face embedding
            
        Returns:
            Cosine similarity (0-1, higher is more similar)
        """
        # Compute cosine similarity
        similarity = np.dot(embedding1, embedding2)
        
        return similarity


class FaceDatabase:
    """
    Database for storing and retrieving face embeddings.
    
    This class manages a SQLite database for storing face embeddings
    of known individuals, along with their names and other metadata.
    """
    
    def __init__(self, db_path: str = "/opt/viztron/data/faces.db"):
        """
        Initialize the face database.
        
        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        
        # Create database directory if it doesn't exist
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database
        self._init_db()
        
        logger.info(f"Face database initialized at {db_path}")
    
    def _init_db(self):
        """Initialize the database schema."""
        try:
            # Connect to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create tables if they don't exist
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS persons (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS face_embeddings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    person_id INTEGER NOT NULL,
                    embedding BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (person_id) REFERENCES persons (id)
                )
            ''')
            
            # Commit changes and close connection
            conn.commit()
            conn.close()
            
            logger.info("Face database schema initialized")
        except Exception as e:
            logger.error(f"Failed to initialize face database: {str(e)}")
            raise
    
    def add_person(self, name: str, category: str = "authorized") -> int:
        """
        Add a new person to the database.
        
        Args:
            name: Name of the person
            category: Category of the person (authorized, unknown, etc.)
            
        Returns:
            ID of the new person
        """
        try:
            # Connect to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Insert person
            cursor.execute(
                "INSERT INTO persons (name, category) VALUES (?, ?)",
                (name, category)
            )
            
            # Get the ID of the new person
            person_id = cursor.lastrowid
            
            # Commit changes and close connection
            conn.commit()
            conn.close()
            
            logger.info(f"Added person {name} with ID {person_id}")
            return person_id
        except Exception as e:
            logger.error(f"Failed to add person: {str(e)}")
            raise
    
    def add_face_embedding(self, person_id: int, embedding: np.ndarray) -> int:
        """
        Add a face embedding for a person.
        
        Args:
            person_id: ID of the person
            embedding: Face embedding (512-dimensional vector)
            
        Returns:
            ID of the new embedding
        """
        try:
            # Connect to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Serialize embedding
            embedding_blob = embedding.tobytes()
            
            # Insert embedding
            cursor.execute(
                "INSERT INTO face_embeddings (person_id, embedding) VALUES (?, ?)",
                (person_id, embedding_blob)
            )
            
            # Get the ID of the new embedding
            embedding_id = cursor.lastrowid
            
            # Commit changes and close connection
            conn.commit()
            conn.close()
            
            logger.info(f"Added face embedding for person {person_id} with ID {embedding_id}")
            return embedding_id
        except Exception as e:
            logger.error(f"Failed to add face embedding: {str(e)}")
            raise
    
    def get_all_embeddings(self) -> List[Tuple[int, str, str, np.ndarray]]:
        """
        Get all face embeddings from the database.
        
        Returns:
            List of tuples (person_id, name, category, embedding)
        """
        try:
            # Connect to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Query embeddings
            cursor.execute('''
                SELECT p.id, p.name, p.category, e.embedding
                FROM persons p
                JOIN face_embeddings e ON p.id = e.person_id
            ''')
            
            # Fetch results
            results = []
            for row in cursor.fetchall():
                person_id, name, category, embedding_blob = row
                
                # Deserialize embedding
                embedding = np.frombuffer(embedding_blob, dtype=np.float32)
                
                results.append((person_id, name, category, embedding))
            
            # Close connection
            conn.close()
            
            logger.info(f"Retrieved {len(results)} face embeddings")
            return results
        except Exception as e:
            logger.error(f"Failed to get face embeddings: {str(e)}")
            raise
    
    def get_person_embeddings(self, person_id: int) -> List[np.ndarray]:
        """
        Get all face embeddings for a person.
        
        Args:
            person_id: ID of the person
            
        Returns:
            List of face embeddings
        """
        try:
            # Connect to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Query embeddings
            cursor.execute(
                "SELECT embedding FROM face_embeddings WHERE person_id = ?",
                (person_id,)
            )
            
            # Fetch results
            embeddings = []
            for row in cursor.fetchall():
                embedding_blob = row[0]
                
                # Deserialize embedding
                embedding = np.frombuffer(embedding_blob, dtype=np.float32)
                
                embeddings.append(embedding)
            
            # Close connection
            conn.close()
            
            logger.info(f"Retrieved {len(embeddings)} face embeddings for person {person_id}")
            return embeddings
        except Exception as e:
            logger.error(f"Failed to get person embeddings: {str(e)}")
            raise
    
    def get_person_info(self, person_id: int) -> Tuple[str, str]:
        """
        Get information about a person.
        
        Args:
            person_id: ID of the person
            
        Returns:
            Tuple of (name, category)
        """
        try:
            # Connect to database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Query person
            cursor.execute(
                "SELECT name, category FROM persons WHERE id = ?",
                (person_id,)
            )
            
            # Fetch result
            result = cursor.fetchone()
            
            # Close connection
            conn.close()
            
            if result:
                name, category = result
                logger.info(f"Retrieved info for person {person_id}: {name}, {category}")
                return name, category
            else:
                logger.warning(f"Person {person_id} not found")
                return None, None
        except Exception as e:
            logger.error(f"Failed to get person info: {str(e)}")
            raise


class FaceRecognitionService:
    """
    Service for face recognition in the Viztron Homebase Module.
    
    This class manages the face detector, ArcFace recognizer, and face database,
    providing an interface for the rest of the system to use.
    """
    
    def __init__(
        self,
        detector_model_path: str = "/opt/viztron/models/retinaface_mobile_int8.onnx",
        recognizer_model_path: str = "/opt/viztron/models/arcface_resnet50_int8.onnx",
        db_path: str = "/opt/viztron/data/faces.db",
        similarity_threshold: float = 0.5,
        device: str = "NPU"
    ):
        """
        Initialize the face recognition service.
        
        Args:
            detector_model_path: Path to the face detector model file
            recognizer_model_path: Path to the ArcFace model file
            db_path: Path to the face database file
            similarity_threshold: Threshold for face matching (0-1)
            device: Device to run inference on ("NPU", "CPU", or "GPU")
        """
        # Initialize face detector
        self.detector = FaceDetector(
            model_path=detector_model_path,
            device=device
        )
        
        # Initialize ArcFace recognizer
        self.recognizer = ArcFaceRecognizer(
            model_path=recognizer_model_path,
            device=device
        )
        
        # Initialize face database
        self.db = FaceDatabase(db_path=db_path)
        
        # Set similarity threshold
        self.similarity_threshold = similarity_threshold
        
        # Cache for embeddings
        self.embedding_cache = None
        
        logger.info(f"Face recognition service initialized with similarity threshold {similarity_threshold}")
    
    def update_embedding_cache(self):
        """Update the cache of face embeddings from the database."""
        self.embedding_cache = self.db.get_all_embeddings()
        logger.info(f"Updated embedding cache with {len(self.embedding_cache)} embeddings")
    
    def detect_faces(self, frame: np.ndarray) -> List[Dict[str, Any]]:
        """
        Detect faces in a frame.
        
        Args:
            frame: Input frame (BGR format)
            
        Returns:
            List of face detection results
        """
        return self.detector.detect(frame)
    
    def recognize_face(
        self,
        frame: np.ndarray,
        detection: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Recognize a face in a frame.
        
        Args:
            frame: Input frame (BGR format)
            detection: Face detection result
            
        Returns:
            Dictionary containing:
            - embedding: Face embedding
            - matches: List of matching persons, each containing:
              - person_id: ID of the person
              - name: Name of the person
              - category: Category of the person
              - similarity: Similarity score (0-1)
        """
        # Extract face from frame
        face = self.detector.extract_face(frame, detection)
        
        # Generate embedding
        embedding = self.recognizer.get_embedding(face)
        
        # Update embedding cache if needed
        if self.embedding_cache is None:
            self.update_embedding_cache()
        
        # Find matches
        matches = []
        for person_id, name, category, db_embedding in self.embedding_cache:
            # Compute similarity
            similarity = self.recognizer.compute_similarity(embedding, db_embedding)
            
            # Check if similarity is above threshold
            if similarity >= self.similarity_threshold:
                matches.append({
                    "person_id": person_id,
                    "name": name,
                    "category": category,
                    "similarity": float(similarity)
                })
        
        # Sort matches by similarity (highest first)
        matches.sort(key=lambda x: x["similarity"], reverse=True)
        
        # Return results
        return {
            "embedding": embedding,
            "matches": matches
        }
    
    def process_frame(
        self,
        frame: np.ndarray,
        camera_id: str
    ) -> Dict[str, Any]:
        """
        Process a frame for face recognition.
        
        Args:
            frame: Input frame (BGR format)
            camera_id: ID of the camera
            
        Returns:
            Dictionary containing:
            - camera_id: ID of the camera
            - timestamp: Processing timestamp
            - faces: List of face results, each containing:
              - bbox: Bounding box [x1, y1, x2, y2]
              - confidence: Detection confidence
              - landmarks: 5 facial landmarks
              - embedding: Face embedding
              - matches: List of matching persons
            - processing_time: Time taken for processing
        """
        # Record start time
        start_time = time.time()
        
        # Detect faces
        detections = self.detect_faces(frame)
        
        # Process each face
        faces = []
        for detection in detections:
            # Recognize face
            recognition_result = self.recognize_face(frame, detection)
            
            # Combine detection and recognition results
            face_result = {
                **detection,
                "embedding": recognition_result["embedding"],
                "matches": recognition_result["matches"]
            }
            
            faces.append(face_result)
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # Prepare result
        result = {
            "camera_id": camera_id,
            "timestamp": time.time(),
            "faces": faces,
            "processing_time": processing_time
        }
        
        logger.debug(f"Processed frame from camera {camera_id} with {len(faces)} faces")
        return result
    
    def add_person_with_face(
        self,
        frame: np.ndarray,
        detection: Dict[str, Any],
        name: str,
        category: str = "authorized"
    ) -> int:
        """
        Add a new person with a face to the database.
        
        Args:
            frame: Input frame (BGR format)
            detection: Face detection result
            name: Name of the person
            category: Category of the person
            
        Returns:
            ID of the new person
        """
        # Extract face from frame
        face = self.detector.extract_face(frame, detection)
        
        # Generate embedding
        embedding = self.recognizer.get_embedding(face)
        
        # Add person to database
        person_id = self.db.add_person(name, category)
        
        # Add face embedding
        self.db.add_face_embedding(person_id, embedding)
        
        # Update embedding cache
        self.update_embedding_cache()
        
        return person_id
    
    def add_face_to_person(
        self,
        frame: np.ndarray,
        detection: Dict[str, Any],
        person_id: int
    ) -> int:
        """
        Add a face to an existing person in the database.
        
        Args:
            frame: Input frame (BGR format)
            detection: Face detection result
            person_id: ID of the person
            
        Returns:
            ID of the new embedding
        """
        # Extract face from frame
        face = self.detector.extract_face(frame, detection)
        
        # Generate embedding
        embedding = self.recognizer.get_embedding(face)
        
        # Add face embedding
        embedding_id = self.db.add_face_embedding(person_id, embedding)
        
        # Update embedding cache
        self.update_embedding_cache()
        
        return embedding_id
    
    def draw_recognition_results(
        self,
        frame: np.ndarray,
        recognition_result: Dict[str, Any]
    ) -> np.ndarray:
        """
        Draw face recognition results on the frame.
        
        Args:
            frame: Input frame
            recognition_result: Recognition result from process_frame()
            
        Returns:
            Frame with recognition results drawn
        """
        # Make a copy of the frame
        output = frame.copy()
        
        # Draw each face
        for face in recognition_result["faces"]:
            # Extract information
            box = face["bbox"]
            confidence = face["confidence"]
            landmarks = face["landmarks"]
            matches = face["matches"]
            
            # Determine color based on matches
            if matches:
                # Green for authorized, red for unauthorized, yellow for others
                category = matches[0]["category"]
                if category == "authorized":
                    color = (0, 255, 0)  # Green
                elif category == "unauthorized":
                    color = (0, 0, 255)  # Red
                else:
                    color = (0, 255, 255)  # Yellow
            else:
                # Blue for unknown
                color = (255, 0, 0)  # Blue
            
            # Draw bounding box
            cv2.rectangle(
                output, 
                (box[0], box[1]), 
                (box[2], box[3]), 
                color, 
                2
            )
            
            # Draw label
            if matches:
                label = f"{matches[0]['name']}: {matches[0]['similarity']:.2f}"
            else:
                label = "Unknown"
                
            cv2.putText(
                output, 
                label, 
                (box[0], box[1] - 10), 
                cv2.FONT_HERSHEY_SIMPLEX, 
                0.5, 
                color, 
                2
            )
            
            # Draw landmarks
            for i in range(0, len(landmarks), 2):
                cv2.circle(
                    output, 
                    (int(landmarks[i]), int(landmarks[i+1])), 
                    2, 
                    (0, 0, 255), 
                    -1
                )
        
        return output


# Example usage
if __name__ == "__main__":
    # Create face recognition service
    recognition_service = FaceRecognitionService(
        detector_model_path="retinaface_mobile_int8.onnx",  # Replace with actual path
        recognizer_model_path="arcface_resnet50_int8.onnx",  # Replace with actual path
        device="CPU"  # Use CPU for testing
    )
    
    # Load a test image
    image = cv2.imread("test_image.jpg")  # Replace with actual path
    
    if image is not None:
        # Process the image
        result = recognition_service.process_frame(image, "test_camera")
        
        # Draw recognition results
        output = recognition_service.draw_recognition_results(image, result)
        
        # Display results
        print(f"Detected {len(result['faces'])} faces:")
        for face in result['faces']:
            if face['matches']:
                print(f"  Match: {face['matches'][0]['name']} ({face['matches'][0]['similarity']:.2f})")
            else:
                print("  No match found")
        
        # Save output image
        cv2.imwrite("output.jpg", output)
        print(f"Output image saved to output.jpg")
    else:
        print("Failed to load test image")
