#!/usr/bin/env python3
"""
Object Detection Module for Viztron Homebase Module

This module implements the object detection stage of the AI pipeline,
using YOLOv8 optimized for the BeagleBoard Y-AI's NPU.

Author: Viztron AI Team
Date: April 19, 2025
"""

import cv2
import numpy as np
import time
import os
import logging
from typing import List, Dict, Tuple, Optional, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('object_detection')

class ObjectDetector:
    """
    YOLOv8 object detector optimized for BeagleBoard Y-AI NPU.
    
    This class handles loading the model, preprocessing frames,
    running inference, and postprocessing results.
    """
    
    def __init__(
        self,
        model_path: str = "/opt/viztron/models/yolov8s_int8.onnx",
        conf_threshold: float = 0.5,
        nms_threshold: float = 0.45,
        input_size: Tuple[int, int] = (640, 640),
        device: str = "NPU"
    ):
        """
        Initialize the object detector.
        
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
        
        # Class names for COCO dataset
        self.class_names = [
            "person", "bicycle", "car", "motorcycle", "airplane", "bus", "train",
            "truck", "boat", "traffic light", "fire hydrant", "stop sign", 
            "parking meter", "bench", "bird", "cat", "dog", "horse", "sheep", 
            "cow", "elephant", "bear", "zebra", "giraffe", "backpack", "umbrella", 
            "handbag", "tie", "suitcase", "frisbee", "skis", "snowboard", 
            "sports ball", "kite", "baseball bat", "baseball glove", "skateboard", 
            "surfboard", "tennis racket", "bottle", "wine glass", "cup", "fork", 
            "knife", "spoon", "bowl", "banana", "apple", "sandwich", "orange", 
            "broccoli", "carrot", "hot dog", "pizza", "donut", "cake", "chair", 
            "couch", "potted plant", "bed", "dining table", "toilet", "tv", 
            "laptop", "mouse", "remote", "keyboard", "cell phone", "microwave", 
            "oven", "toaster", "sink", "refrigerator", "book", "clock", "vase", 
            "scissors", "teddy bear", "hair drier", "toothbrush"
        ]
        
        # Load model
        self._load_model()
        
        # Warmup the model
        self._warmup()
        
        logger.info(f"Object detector initialized with {device} device")
    
    def _load_model(self):
        """Load the YOLOv8 model using OpenCV's DNN module with NPU support."""
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
            
            logger.info(f"Model loaded successfully from {self.model_path}")
        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            raise
    
    def _warmup(self):
        """Warm up the model with a dummy input."""
        try:
            # Create a dummy input
            dummy_input = np.zeros((1, 3, *self.input_size), dtype=np.float32)
            
            # Run inference
            self.net.setInput(dummy_input)
            self.net.forward(self.net.getUnconnectedOutLayersNames())
            
            logger.info("Model warmup completed successfully")
        except Exception as e:
            logger.warning(f"Model warmup failed: {str(e)}")
    
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
            1/255.0,  # Scale pixel values to [0, 1]
            self.input_size,  # Resize to input dimensions
            swapRB=True,  # BGR to RGB
            crop=False
        )
        
        return blob, width_scale, height_scale
    
    def detect(self, frame: np.ndarray) -> List[Dict[str, Any]]:
        """
        Detect objects in a frame.
        
        Args:
            frame: Input frame (BGR format)
            
        Returns:
            List of detection results, each containing:
            - bbox: Bounding box [x1, y1, x2, y2]
            - class_id: Class ID
            - class_name: Class name
            - confidence: Detection confidence
        """
        # Measure inference time
        start_time = time.time()
        
        # Preprocess the frame
        blob, width_scale, height_scale = self.preprocess(frame)
        
        # Set the input to the network
        self.net.setInput(blob)
        
        # Run inference
        outputs = self.net.forward(self.net.getUnconnectedOutLayersNames())[0]
        
        # Process the outputs
        results = self._process_output(outputs, width_scale, height_scale)
        
        # Calculate inference time
        inference_time = time.time() - start_time
        logger.debug(f"Inference time: {inference_time:.4f} seconds")
        
        return results
    
    def _process_output(
        self, 
        outputs: np.ndarray, 
        width_scale: float, 
        height_scale: float
    ) -> List[Dict[str, Any]]:
        """
        Process the model output to extract detections.
        
        Args:
            outputs: Model output
            width_scale: Scale factor for width
            height_scale: Scale factor for height
            
        Returns:
            List of detection results
        """
        # Initialize lists for bounding boxes, confidences, and class IDs
        boxes = []
        confidences = []
        class_ids = []
        
        # YOLOv8 output format: [x, y, w, h, conf, cls0, cls1, ...]
        rows = outputs.shape[0]
        
        # Process each detection
        for i in range(rows):
            # Extract class scores
            classes_scores = outputs[i][5:]
            
            # Find the maximum score and its index
            max_score = np.max(classes_scores)
            class_id = np.argmax(classes_scores)
            
            # Filter by confidence threshold
            if max_score >= self.conf_threshold:
                # Get bounding box coordinates
                x, y, w, h = outputs[i][0:4]
                
                # Convert to corner coordinates and scale back to original image
                x1 = int((x - w/2) * width_scale)
                y1 = int((y - h/2) * height_scale)
                x2 = int((x + w/2) * width_scale)
                y2 = int((y + h/2) * height_scale)
                
                # Add to lists
                boxes.append([x1, y1, x2, y2])
                confidences.append(float(max_score))
                class_ids.append(int(class_id))
        
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
            class_id = class_ids[idx]
            class_name = self.class_names[class_id] if class_id < len(self.class_names) else f"class_{class_id}"
            
            # Add to results
            results.append({
                "bbox": box,  # [x1, y1, x2, y2]
                "class_id": class_id,
                "class_name": class_name,
                "confidence": confidence
            })
        
        return results
    
    def draw_detections(self, frame: np.ndarray, detections: List[Dict[str, Any]]) -> np.ndarray:
        """
        Draw detection results on the frame.
        
        Args:
            frame: Input frame
            detections: Detection results from detect()
            
        Returns:
            Frame with detections drawn
        """
        # Make a copy of the frame
        output = frame.copy()
        
        # Draw each detection
        for detection in detections:
            # Extract information
            box = detection["bbox"]
            class_name = detection["class_name"]
            confidence = detection["confidence"]
            
            # Draw bounding box
            cv2.rectangle(
                output, 
                (box[0], box[1]), 
                (box[2], box[3]), 
                (0, 255, 0), 
                2
            )
            
            # Draw label
            label = f"{class_name}: {confidence:.2f}"
            cv2.putText(
                output, 
                label, 
                (box[0], box[1] - 10), 
                cv2.FONT_HERSHEY_SIMPLEX, 
                0.5, 
                (0, 255, 0), 
                2
            )
        
        return output


class ObjectDetectionService:
    """
    Service for object detection in the Viztron Homebase Module.
    
    This class manages the object detector and provides an interface
    for the rest of the system to use.
    """
    
    def __init__(
        self,
        model_path: str = "/opt/viztron/models/yolov8s_int8.onnx",
        conf_threshold: float = 0.5,
        nms_threshold: float = 0.45,
        input_size: Tuple[int, int] = (640, 640),
        device: str = "NPU",
        max_batch_size: int = 4
    ):
        """
        Initialize the object detection service.
        
        Args:
            model_path: Path to the ONNX model file
            conf_threshold: Confidence threshold for detections
            nms_threshold: Non-maximum suppression threshold
            input_size: Input size for the model (width, height)
            device: Device to run inference on ("NPU", "CPU", or "GPU")
            max_batch_size: Maximum batch size for batch processing
        """
        self.detector = ObjectDetector(
            model_path=model_path,
            conf_threshold=conf_threshold,
            nms_threshold=nms_threshold,
            input_size=input_size,
            device=device
        )
        
        self.max_batch_size = max_batch_size
        logger.info(f"Object detection service initialized with max batch size {max_batch_size}")
    
    def process_frame(self, frame: np.ndarray, camera_id: str) -> Dict[str, Any]:
        """
        Process a single frame from a camera.
        
        Args:
            frame: Input frame (BGR format)
            camera_id: ID of the camera that captured the frame
            
        Returns:
            Dictionary containing:
            - camera_id: ID of the camera
            - timestamp: Processing timestamp
            - detections: List of detection results
            - inference_time: Time taken for inference
        """
        # Record start time
        start_time = time.time()
        
        # Run detection
        detections = self.detector.detect(frame)
        
        # Calculate processing time
        inference_time = time.time() - start_time
        
        # Prepare result
        result = {
            "camera_id": camera_id,
            "timestamp": time.time(),
            "detections": detections,
            "inference_time": inference_time
        }
        
        logger.debug(f"Processed frame from camera {camera_id} with {len(detections)} detections")
        return result
    
    def process_batch(
        self, 
        frames: List[np.ndarray], 
        camera_ids: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Process a batch of frames from multiple cameras.
        
        Args:
            frames: List of input frames (BGR format)
            camera_ids: List of camera IDs corresponding to frames
            
        Returns:
            List of results, one for each frame
        """
        # Ensure batch size doesn't exceed maximum
        if len(frames) > self.max_batch_size:
            logger.warning(f"Batch size {len(frames)} exceeds maximum {self.max_batch_size}, splitting batch")
            
            # Process in chunks of max_batch_size
            results = []
            for i in range(0, len(frames), self.max_batch_size):
                batch_frames = frames[i:i+self.max_batch_size]
                batch_camera_ids = camera_ids[i:i+self.max_batch_size]
                batch_results = self.process_batch(batch_frames, batch_camera_ids)
                results.extend(batch_results)
            
            return results
        
        # Process each frame individually (future: implement true batch processing)
        results = []
        for frame, camera_id in zip(frames, camera_ids):
            result = self.process_frame(frame, camera_id)
            results.append(result)
        
        return results


# Example usage
if __name__ == "__main__":
    # Create object detection service
    detection_service = ObjectDetectionService(
        model_path="yolov8s_int8.onnx",  # Replace with actual path
        device="CPU"  # Use CPU for testing
    )
    
    # Load a test image
    image = cv2.imread("test_image.jpg")  # Replace with actual path
    
    if image is not None:
        # Process the image
        result = detection_service.process_frame(image, "test_camera")
        
        # Draw detections
        output = detection_service.detector.draw_detections(image, result["detections"])
        
        # Display results
        print(f"Detected {len(result['detections'])} objects:")
        for detection in result["detections"]:
            print(f"  {detection['class_name']}: {detection['confidence']:.2f}")
        
        # Save output image
        cv2.imwrite("output.jpg", output)
        print(f"Output image saved to output.jpg")
    else:
        print("Failed to load test image")
