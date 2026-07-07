# WiFi Connect CMD

A Windows command-line tool to scan WiFi networks, connect to one, and see
detailed connection diagnostics that Windows normally hides.

## Features
- Lists nearby networks with signal, auth, cipher, and MAC (BSSID)
- Connects to a chosen network (creates a saved profile if needed)
- Streams live connection state changes during connection 
- Pulls detailed failure reasons from the Windows WLAN event log
- Restart the WiFi adapter on demand

## Requirements
- Windows 10/11
- Python 3.8+
- Some features (adapter restart, all-user profiles) need Administrator rights

## Usage
```
python wifi_connect.py
OR 
simply use RUN.bat
```