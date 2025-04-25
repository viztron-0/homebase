# BeagleBoard Y-AI Specifications

## Overview
The BeagleBoard Y-AI is a high-performance single board computer powered by the Texas Instruments AM67A AI vision processor. This document summarizes the key specifications and capabilities relevant to the Viztron Homebase Module implementation.

## Processor
- **SoC**: Texas Instruments AM67A (may be referenced as J722s/TDA4AEN in TI documentation)
- **CPU**: Quad-core 64-bit ARM Cortex-A53 @ 1.4GHz
- **MCU**: ARM Cortex-R5F @ 800MHz for real-time IO applications
- **DSP**: 2x C7x DSPs with Matrix Multiply Accelerator (MMA)
- **AI Performance**: Up to 4 TOPS (2 TOPS per DSP)
- **GPU**: Imagination BXS-4-64 (50 GFLOP)
- **Video**: Dedicated encoder/decoder for multimedia tasks

## Memory
- **RAM**: 4GB Kingston x32 LPDDR4
- **Storage**: microSD card slot (primary boot interface, MMC1)
- **EEPROM**: 32Kbit I2C EEPROM (FT24C32A) for board information

## Connectivity
- **USB**: 
  - USB-C port (power and USB 2.0 device functionality)
  - USB 3.1 support
- **Networking**:
  - Ethernet (Gigabit)
  - Wi-Fi + Bluetooth
- **Expansion**:
  - 40-pin GPIO header (Raspberry Pi HAT compatible)
  - PCIe interface
  - I2C interfaces (5 total, 2 exposed on GPIO header)
  - SPI interfaces
  - UART interfaces
  - CAN-FD interfaces
- **Camera/Display**:
  - CSI interfaces for cameras
  - DSI and OLDI interfaces for displays
  - 3x Display with OLDI/DSI
  - 4x 4L CSI2-TX and 4x 4L CSI2-RX

## Power
- **Input**: 5V 3A via USB-C (USB-PD compatible)
- **Power Management**: TPS65219 PMIC for main logic rails
- **Core Voltage**: TPS62872 high current buck regulator (0.85V default)
- **IO Voltage**: 3.3V for expansion header

## Boot Modes
- Primary boot from microSD card
- Secondary boot from Ethernet
- Possible to boot from NVMe drives

## Security Features
- Secure Boot capability
- One-Time-Programmable (OTP) eFUSES

## Physical
- Desktop form factor
- Cooling provisions included

## AI Capabilities
- Deep Learning Acceleration via C7x DSPs with MMA
- Suitable for AI Vision applications
- 3D Graphics Processing Unit

## Relevance to Homebase Module
The BeagleBoard Y-AI provides an excellent platform for the Viztron Homebase Module with:
- Sufficient processing power for AI-based security analysis
- Multiple camera interfaces for connecting security cameras
- Networking capabilities for cloud connectivity
- Expansion options for additional sensors and interfaces
- Security features for protecting sensitive data
- Low power consumption relative to performance

This hardware platform meets the requirements specified for the Homebase Module, providing 4 TOPS of AI processing capability, sufficient connectivity options, and appropriate form factor for a home security hub.
