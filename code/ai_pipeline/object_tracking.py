#!/usr/bin/env python3
"""
ByteTrack Implementation for Viztron Homebase Module

This module implements the ByteTrack algorithm for multi-object tracking
in the Viztron Homebase Module AI pipeline.

Author: Viztron AI Team
Date: April 19, 2025
"""

import numpy as np
import cv2
import time
import logging
from typing import List, Dict, Tuple, Optional, Any
from collections import deque
from scipy.optimize import linear_sum_assignment

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('object_tracking')

class KalmanFilter:
    """
    Kalman filter for tracking object motion in 2D space.
    
    This implementation uses a constant velocity model with
    state vector [x, y, w, h, vx, vy, vw, vh] where:
    - (x, y) is the center of the bounding box
    - (w, h) is the width and height of the bounding box
    - (vx, vy, vw, vh) are the respective velocities
    """
    
    def __init__(self):
        """Initialize the Kalman filter with default parameters."""
        # State transition matrix (8x8)
        # [1, 0, 0, 0, 1, 0, 0, 0]
        # [0, 1, 0, 0, 0, 1, 0, 0]
        # [0, 0, 1, 0, 0, 0, 1, 0]
        # [0, 0, 0, 1, 0, 0, 0, 1]
        # [0, 0, 0, 0, 1, 0, 0, 0]
        # [0, 0, 0, 0, 0, 1, 0, 0]
        # [0, 0, 0, 0, 0, 0, 1, 0]
        # [0, 0, 0, 0, 0, 0, 0, 1]
        self.F = np.eye(8, dtype=np.float32)
        self.F[0, 4] = 1.0  # x += vx
        self.F[1, 5] = 1.0  # y += vy
        self.F[2, 6] = 1.0  # w += vw
        self.F[3, 7] = 1.0  # h += vh
        
        # Measurement matrix (4x8)
        # [1, 0, 0, 0, 0, 0, 0, 0]
        # [0, 1, 0, 0, 0, 0, 0, 0]
        # [0, 0, 1, 0, 0, 0, 0, 0]
        # [0, 0, 0, 1, 0, 0, 0, 0]
        self.H = np.zeros((4, 8), dtype=np.float32)
        self.H[0, 0] = 1.0  # x
        self.H[1, 1] = 1.0  # y
        self.H[2, 2] = 1.0  # w
        self.H[3, 3] = 1.0  # h
        
        # Process noise covariance matrix (8x8)
        self.Q = np.eye(8, dtype=np.float32) * 0.1
        
        # Measurement noise covariance matrix (4x4)
        self.R = np.eye(4, dtype=np.float32) * 1.0
        
        # State covariance matrix (8x8)
        self.P = np.eye(8, dtype=np.float32) * 10.0
        
        # State vector (8x1)
        self.x = np.zeros((8, 1), dtype=np.float32)
        
        # Identity matrix (8x8)
        self.I = np.eye(8, dtype=np.float32)
    
    def init(self, bbox: np.ndarray):
        """
        Initialize the Kalman filter with a bounding box.
        
        Args:
            bbox: Bounding box in format [x1, y1, x2, y2]
        """
        # Convert bbox to [x, y, w, h]
        x = (bbox[0] + bbox[2]) / 2.0
        y = (bbox[1] + bbox[3]) / 2.0
        w = bbox[2] - bbox[0]
        h = bbox[3] - bbox[1]
        
        # Initialize state vector
        self.x = np.array([
            [x],
            [y],
            [w],
            [h],
            [0],  # vx
            [0],  # vy
            [0],  # vw
            [0]   # vh
        ], dtype=np.float32)
    
    def predict(self) -> np.ndarray:
        """
        Predict the next state.
        
        Returns:
            Predicted bounding box in format [x1, y1, x2, y2]
        """
        # Predict next state
        self.x = np.dot(self.F, self.x)
        
        # Update covariance
        self.P = np.dot(np.dot(self.F, self.P), self.F.T) + self.Q
        
        # Convert state to bbox
        x, y, w, h = self.x[0, 0], self.x[1, 0], self.x[2, 0], self.x[3, 0]
        
        # Return bbox in format [x1, y1, x2, y2]
        return np.array([
            x - w/2,
            y - h/2,
            x + w/2,
            y + h/2
        ])
    
    def update(self, bbox: np.ndarray):
        """
        Update the state with a new measurement.
        
        Args:
            bbox: Bounding box in format [x1, y1, x2, y2]
        """
        # Convert bbox to [x, y, w, h]
        x = (bbox[0] + bbox[2]) / 2.0
        y = (bbox[1] + bbox[3]) / 2.0
        w = bbox[2] - bbox[0]
        h = bbox[3] - bbox[1]
        
        # Measurement vector
        z = np.array([
            [x],
            [y],
            [w],
            [h]
        ], dtype=np.float32)
        
        # Calculate Kalman gain
        S = np.dot(np.dot(self.H, self.P), self.H.T) + self.R
        K = np.dot(np.dot(self.P, self.H.T), np.linalg.inv(S))
        
        # Update state
        y = z - np.dot(self.H, self.x)
        self.x = self.x + np.dot(K, y)
        
        # Update covariance
        self.P = np.dot((self.I - np.dot(K, self.H)), self.P)


class Track:
    """
    Track class for representing a tracked object.
    
    This class maintains the state of a tracked object, including
    its bounding box, class, confidence, and tracking status.
    """
    
    # Class variable to generate unique track IDs
    _next_id = 1
    
    def __init__(
        self,
        bbox: np.ndarray,
        class_id: int,
        class_name: str,
        confidence: float,
        max_age: int = 30,
        n_init: int = 3
    ):
        """
        Initialize a new track.
        
        Args:
            bbox: Bounding box in format [x1, y1, x2, y2]
            class_id: Class ID
            class_name: Class name
            confidence: Detection confidence
            max_age: Maximum number of frames to keep a track alive without matching
            n_init: Number of consecutive frames needed to confirm a track
        """
        # Assign a unique ID to this track
        self.track_id = Track._next_id
        Track._next_id += 1
        
        # Initialize Kalman filter
        self.kf = KalmanFilter()
        self.kf.init(bbox)
        
        # Store track information
        self.bbox = bbox
        self.class_id = class_id
        self.class_name = class_name
        self.confidence = confidence
        
        # Track state
        self.age = 1
        self.hits = 1
        self.time_since_update = 0
        self.state = "tentative"  # tentative, confirmed, or deleted
        
        # Track parameters
        self.max_age = max_age
        self.n_init = n_init
        
        # Track history
        self.history = deque(maxlen=50)
        self.history.append(bbox)
        
        logger.debug(f"Created new track {self.track_id} with class {class_name}")
    
    def predict(self) -> np.ndarray:
        """
        Predict the next position of the track.
        
        Returns:
            Predicted bounding box in format [x1, y1, x2, y2]
        """
        # Predict next position using Kalman filter
        self.bbox = self.kf.predict()
        
        # Increment age and time since update
        self.age += 1
        self.time_since_update += 1
        
        # Add prediction to history
        self.history.append(self.bbox)
        
        return self.bbox
    
    def update(
        self,
        bbox: np.ndarray,
        class_id: int,
        class_name: str,
        confidence: float
    ):
        """
        Update the track with a new detection.
        
        Args:
            bbox: Bounding box in format [x1, y1, x2, y2]
            class_id: Class ID
            class_name: Class name
            confidence: Detection confidence
        """
        # Update Kalman filter
        self.kf.update(bbox)
        
        # Update track information
        self.bbox = bbox
        self.class_id = class_id
        self.class_name = class_name
        self.confidence = confidence
        
        # Update track state
        self.hits += 1
        self.time_since_update = 0
        
        # Confirm track if it has been seen enough times
        if self.state == "tentative" and self.hits >= self.n_init:
            self.state = "confirmed"
            logger.debug(f"Track {self.track_id} confirmed")
        
        # Add update to history
        self.history.append(bbox)
    
    def mark_missed(self):
        """Mark the track as missed (not updated) in the current frame."""
        self.time_since_update += 1
        
        # Mark as deleted if not seen for too long
        if self.time_since_update > self.max_age:
            self.state = "deleted"
            logger.debug(f"Track {self.track_id} deleted due to age")
    
    def is_confirmed(self) -> bool:
        """Check if the track is confirmed."""
        return self.state == "confirmed"
    
    def is_deleted(self) -> bool:
        """Check if the track is deleted."""
        return self.state == "deleted"
    
    def is_tentative(self) -> bool:
        """Check if the track is tentative."""
        return self.state == "tentative"


class ByteTracker:
    """
    ByteTrack implementation for multi-object tracking.
    
    This class implements the ByteTrack algorithm, which associates
    detections with existing tracks based on motion and appearance.
    """
    
    def __init__(
        self,
        max_age: int = 30,
        n_init: int = 3,
        match_threshold: float = 0.8,
        second_match_threshold: float = 0.5,
        iou_threshold: float = 0.3
    ):
        """
        Initialize the ByteTracker.
        
        Args:
            max_age: Maximum number of frames to keep a track alive without matching
            n_init: Number of consecutive frames needed to confirm a track
            match_threshold: IoU threshold for first association stage
            second_match_threshold: IoU threshold for second association stage
            iou_threshold: IoU threshold for non-maximum suppression
        """
        self.max_age = max_age
        self.n_init = n_init
        self.match_threshold = match_threshold
        self.second_match_threshold = second_match_threshold
        self.iou_threshold = iou_threshold
        
        # Lists to store tracks
        self.tracks = []
        
        logger.info(f"ByteTracker initialized with match_threshold={match_threshold}")
    
    def update(self, detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Update tracks with new detections.
        
        Args:
            detections: List of detection results, each containing:
                - bbox: Bounding box [x1, y1, x2, y2]
                - class_id: Class ID
                - class_name: Class name
                - confidence: Detection confidence
                
        Returns:
            List of tracking results, each containing:
                - track_id: Unique track ID
                - bbox: Bounding box [x1, y1, x2, y2]
                - class_id: Class ID
                - class_name: Class name
                - confidence: Detection confidence
                - state: Track state (tentative, confirmed, or deleted)
        """
        # Initialize results list
        results = []
        
        # If no detections, mark all tracks as missed and return
        if len(detections) == 0:
            for track in self.tracks:
                track.mark_missed()
            
            # Remove deleted tracks
            self.tracks = [t for t in self.tracks if not t.is_deleted()]
            
            # Return remaining tracks
            for track in self.tracks:
                if track.is_confirmed():
                    results.append({
                        "track_id": track.track_id,
                        "bbox": track.bbox,
                        "class_id": track.class_id,
                        "class_name": track.class_name,
                        "confidence": track.confidence,
                        "state": track.state
                    })
            
            return results
        
        # Predict new locations for existing tracks
        for track in self.tracks:
            track.predict()
        
        # Split detections into high and low confidence
        high_conf_detections = [d for d in detections if d["confidence"] >= 0.5]
        low_conf_detections = [d for d in detections if d["confidence"] < 0.5]
        
        # Get confirmed and unconfirmed tracks
        confirmed_tracks = [t for t in self.tracks if t.is_confirmed()]
        unconfirmed_tracks = [t for t in self.tracks if t.is_tentative()]
        
        # Associate high confidence detections with confirmed tracks
        matches_a, unmatched_tracks_a, unmatched_detections_a = \
            self._associate_detections_to_tracks(
                high_conf_detections,
                confirmed_tracks,
                self.match_threshold
            )
        
        # Associate high confidence detections with unconfirmed tracks
        matches_b, unmatched_tracks_b, _ = \
            self._associate_detections_to_tracks(
                [high_conf_detections[i] for i in unmatched_detections_a],
                unconfirmed_tracks,
                self.match_threshold
            )
        
        # Combine matches and unmatched tracks
        matches = matches_a + [(unconfirmed_tracks[i], high_conf_detections[unmatched_detections_a[j]]) 
                              for i, j in matches_b]
        
        unmatched_tracks = [confirmed_tracks[i] for i in unmatched_tracks_a] + \
                           [unconfirmed_tracks[i] for i in unmatched_tracks_b]
        
        unmatched_detections = [high_conf_detections[i] for i in unmatched_detections_a 
                               if i not in [j for _, j in matches_b]]
        
        # Associate remaining detections with tracks using lower threshold
        matches_c, unmatched_tracks_c, unmatched_detections_c = \
            self._associate_detections_to_tracks(
                unmatched_detections + low_conf_detections,
                unmatched_tracks,
                self.second_match_threshold
            )
        
        # Combine all matches
        matches += [(unmatched_tracks[i], (unmatched_detections + low_conf_detections)[j]) 
                   for i, j in matches_c]
        
        unmatched_tracks = [unmatched_tracks[i] for i in unmatched_tracks_c]
        
        # Update matched tracks
        for track, detection in matches:
            track.update(
                detection["bbox"],
                detection["class_id"],
                detection["class_name"],
                detection["confidence"]
            )
        
        # Mark unmatched tracks as missed
        for track in unmatched_tracks:
            track.mark_missed()
        
        # Create new tracks for unmatched high confidence detections
        for i in unmatched_detections_a:
            if i not in [j for _, j in matches_b]:
                detection = high_conf_detections[i]
                track = Track(
                    detection["bbox"],
                    detection["class_id"],
                    detection["class_name"],
                    detection["confidence"],
                    self.max_age,
                    self.n_init
                )
                self.tracks.append(track)
        
        # Remove deleted tracks
        self.tracks = [t for t in self.tracks if not t.is_deleted()]
        
        # Return results for confirmed tracks
        for track in self.tracks:
            if track.is_confirmed():
                results.append({
                    "track_id": track.track_id,
                    "bbox": track.bbox,
                    "class_id": track.class_id,
                    "class_name": track.class_name,
                    "confidence": track.confidence,
                    "state": track.state
                })
        
        return results
    
    def _associate_detections_to_tracks(
        self,
        detections: List[Dict[str, Any]],
        tracks: List[Track],
        threshold: float
    ) -> Tuple[List[Tuple[Track, Dict[str, Any]]], List[int], List[int]]:
        """
        Associate detections with tracks using IoU.
        
        Args:
            detections: List of detection results
            tracks: List of tracks
            threshold: IoU threshold for association
            
        Returns:
            Tuple of (matches, unmatched_tracks, unmatched_detections)
        """
        if len(tracks) == 0 or len(detections) == 0:
            return [], list(range(len(tracks))), list(range(len(detections)))
        
        # Compute IoU matrix
        iou_matrix = np.zeros((len(tracks), len(detections)), dtype=np.float32)
        for i, track in enumerate(tracks):
            for j, detection in enumerate(detections):
                iou_matrix[i, j] = self._iou(track.bbox, detection["bbox"])
        
        # Apply Hungarian algorithm for optimal assignment
        # Convert to cost matrix (1 - IoU)
        cost_matrix = 1 - iou_matrix
        
        # Set cost to infinity if IoU is below threshold
        cost_matrix[iou_matrix < threshold] = float('inf')
        
        # Find optimal assignment
        track_indices, detection_indices = linear_sum_assignment(cost_matrix)
        
        # Filter out assignments with cost = infinity
        valid_indices = cost_matrix[track_indices, detection_indices] != float('inf')
        track_indices = track_indices[valid_indices]
        detection_indices = detection_indices[valid_indices]
        
        # Create matches
        matches = [(tracks[i], detections[j]) for i, j in zip(track_indices, detection_indices)]
        
        # Find unmatched tracks and detections
        unmatched_tracks = [i for i in range(len(tracks)) if i not in track_indices]
        unmatched_detections = [i for i in range(len(detections)) if i not in detection_indices]
        
        return matches, unmatched_tracks, unmatched_detections
    
    def _iou(self, bbox1: np.ndarray, bbox2: np.ndarray) -> float:
        """
        Calculate IoU between two bounding boxes.
        
        Args:
            bbox1: First bounding box [x1, y1, x2, y2]
            bbox2: Second bounding box [x1, y1, x2, y2]
            
        Returns:
            IoU value
        """
        # Get coordinates
        x1_1, y1_1, x2_1, y2_1 = bbox1
        x1_2, y1_2, x2_2, y2_2 = bbox2
        
        # Calculate intersection area
        x1_i = max(x1_1, x1_2)
        y1_i = max(y1_1, y1_2)
        x2_i = min(x2_1, x2_2)
        y2_i = min(y2_1, y2_2)
        
        # Check if boxes intersect
        if x2_i < x1_i or y2_i < y1_i:
            return 0.0
        
        # Calculate areas
        area_i = (x2_i - x1_i) * (y2_i - y1_i)
        area_1 = (x2_1 - x1_1) * (y2_1 - y1_1)
        area_2 = (x2_2 - x1_2) * (y2_2 - y1_2)
        
        # Calculate IoU
        area_u = area_1 + area_2 - area_i
        iou = area_i / area_u if area_u > 0 else 0.0
        
        return iou


class ObjectTrackingService:
    """
    Service for object tracking in the Viztron Homebase Module.
    
    This class manages the ByteTracker and provides an interface
    for the rest of the system to use.
    """
    
    def __init__(
        self,
        max_age: int = 30,
        n_init: int = 3,
        match_threshold: float = 0.8,
        second_match_threshold: float = 0.5,
        iou_threshold: float = 0.3
    ):
        """
        Initialize the object tracking service.
        
        Args:
            max_age: Maximum number of frames to keep a track alive without matching
            n_init: Number of consecutive frames needed to confirm a track
            match_threshold: IoU threshold for first association stage
            second_match_threshold: IoU threshold for second association stage
            iou_threshold: IoU threshold for non-maximum suppression
        """
        # Create a tracker for each camera
        self.trackers = {}
        
        # Store parameters for creating new trackers
        self.params = {
            "max_age": max_age,
            "n_init": n_init,
            "match_threshold": match_threshold,
            "second_match_threshold": second_match_threshold,
            "iou_threshold": iou_threshold
        }
        
        logger.info(f"Object tracking service initialized")
    
    def process_detections(
        self,
        detection_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process detection results for a single frame.
        
        Args:
            detection_result: Detection result from ObjectDetectionService
                - camera_id: ID of the camera
                - timestamp: Processing timestamp
                - detections: List of detection results
                - inference_time: Time taken for inference
                
        Returns:
            Dictionary containing:
                - camera_id: ID of the camera
                - timestamp: Processing timestamp
                - tracks: List of tracking results
                - tracking_time: Time taken for tracking
        """
        # Record start time
        start_time = time.time()
        
        # Extract information from detection result
        camera_id = detection_result["camera_id"]
        timestamp = detection_result["timestamp"]
        detections = detection_result["detections"]
        
        # Get or create tracker for this camera
        if camera_id not in self.trackers:
            self.trackers[camera_id] = ByteTracker(**self.params)
            logger.info(f"Created new tracker for camera {camera_id}")
        
        tracker = self.trackers[camera_id]
        
        # Update tracker with detections
        tracks = tracker.update(detections)
        
        # Calculate processing time
        tracking_time = time.time() - start_time
        
        # Prepare result
        result = {
            "camera_id": camera_id,
            "timestamp": timestamp,
            "tracks": tracks,
            "tracking_time": tracking_time
        }
        
        logger.debug(f"Processed detections from camera {camera_id} with {len(tracks)} tracks")
        return result
    
    def draw_tracks(self, frame: np.ndarray, tracks: List[Dict[str, Any]]) -> np.ndarray:
        """
        Draw tracking results on the frame.
        
        Args:
            frame: Input frame
            tracks: Tracking results from process_detections()
            
        Returns:
            Frame with tracks drawn
        """
        # Make a copy of the frame
        output = frame.copy()
        
        # Draw each track
        for track in tracks:
            # Extract information
            track_id = track["track_id"]
            box = track["bbox"]
            class_name = track["class_name"]
            confidence = track["confidence"]
            
            # Generate color based on track ID
            color = (
                (track_id * 123) % 255,
                (track_id * 85) % 255,
                (track_id * 51) % 255
            )
            
            # Draw bounding box
            cv2.rectangle(
                output, 
                (int(box[0]), int(box[1])), 
                (int(box[2]), int(box[3])), 
                color, 
                2
            )
            
            # Draw label
            label = f"{class_name} #{track_id}: {confidence:.2f}"
            cv2.putText(
                output, 
                label, 
                (int(box[0]), int(box[1]) - 10), 
                cv2.FONT_HERSHEY_SIMPLEX, 
                0.5, 
                color, 
                2
            )
        
        return output


# Example usage
if __name__ == "__main__":
    # Create object tracking service
    tracking_service = ObjectTrackingService()
    
    # Simulate detection results
    detection_result = {
        "camera_id": "test_camera",
        "timestamp": time.time(),
        "detections": [
            {
                "bbox": np.array([100, 100, 200, 200]),
                "class_id": 0,
                "class_name": "person",
                "confidence": 0.9
            },
            {
                "bbox": np.array([300, 300, 400, 400]),
                "class_id": 2,
                "class_name": "car",
                "confidence": 0.8
            }
        ],
        "inference_time": 0.05
    }
    
    # Process detections
    tracking_result = tracking_service.process_detections(detection_result)
    
    # Print results
    print(f"Tracked {len(tracking_result['tracks'])} objects:")
    for track in tracking_result["tracks"]:
        print(f"  {track['class_name']} #{track['track_id']}: {track['confidence']:.2f}")
