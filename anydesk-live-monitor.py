#!/usr/bin/env python3
"""
AnyDesk Live Log Monitor - Electron Integration Version
Real-time monitoring of AnyDesk log files with structured output for Electron apps
Enhanced with historical log checking capability
"""

import os
import time
import re
import platform
import json
from datetime import datetime, timedelta
from pathlib import Path

class AnydeskLiveMonitor:
    def __init__(self, log_path=None, debug=False):
        if log_path is None:
            self.log_path = self.get_default_log_path()
        else:
            self.log_path = Path(log_path)
        
        self.current_session = {}
        self.last_position = 0
        self.system = platform.system()
        self.session_features = None
        self.debug = debug
        # Store the system timezone for accurate time comparisons
        self.system_timezone = None

    def debug_print(self, message):
        """Print debug message if debug mode is enabled"""
        if self.debug:
            print(f"DEBUG: {message}", flush=True)

    def get_default_log_path(self):
        """Get default AnyDesk log path based on operating system"""
        system = platform.system()
        home = Path.home()
        
        if system == "Linux":
            return home / '.anydesk' / 'anydesk.trace'
        elif system == "Windows":
            possible_paths = [
                Path(os.environ.get('APPDATA', '')) / 'AnyDesk' / 'anydesk.trace',
                Path(os.environ.get('PROGRAMDATA', '')) / 'AnyDesk' / 'anydesk.trace',
                home / 'AppData' / 'Roaming' / 'AnyDesk' / 'anydesk.trace',
                Path('C:') / 'ProgramData' / 'AnyDesk' / 'anydesk.trace'
            ]
            for path in possible_paths:
                if path.exists():
                    return path
            
            found_logs = self.find_anydesk_logs_static()
            if found_logs:
                return found_logs[0]
            return possible_paths[0]
        elif system == "Darwin":  # macOS
            possible_paths = [
                home / 'Library' / 'Application Support' / 'AnyDesk' / 'anydesk.trace',
                home / 'Library' / 'Logs' / 'AnyDesk' / 'anydesk.trace',
                Path('/Library/Application Support/AnyDesk/anydesk.trace')
            ]
            for path in possible_paths:
                if path.exists():
                    return path
            return possible_paths[0]
        else:
            return home / '.anydesk' / 'anydesk.trace'

    def find_anydesk_logs(self):
        """Find all possible AnyDesk log files on the system"""
        system = platform.system()
        home = Path.home()
        found_logs = []
        search_patterns = []
        
        if system == "Linux":
            search_patterns = [
                home / '.anydesk' / '*.trace',
                home / '.anydesk' / '*.log'
            ]
        elif system == "Windows":
            search_patterns = [
                Path(os.environ.get('APPDATA', '')) / 'AnyDesk' / '*.trace',
                Path(os.environ.get('APPDATA', '')) / 'AnyDesk' / '*.log',
                Path(os.environ.get('PROGRAMDATA', '')) / 'AnyDesk' / '*.trace',
                Path(os.environ.get('PROGRAMDATA', '')) / 'AnyDesk' / '*.log',
            ]
        elif system == "Darwin":
            search_patterns = [
                home / 'Library' / 'Application Support' / 'AnyDesk' / '*.trace',
                home / 'Library' / 'Application Support' / 'AnyDesk' / '*.log',
                home / 'Library' / 'Logs' / 'AnyDesk' / '*.trace',
            ]
        
        for pattern in search_patterns:
            try:
                parent_dir = pattern.parent
                if parent_dir.exists():
                    for file in parent_dir.glob(pattern.name):
                        if file.is_file():
                            found_logs.append(file)
            except:
                continue
        
        return found_logs

    @staticmethod
    def find_anydesk_logs_static():
        """Static version of find_anydesk_logs for use during initialization"""
        system = platform.system()
        home = Path.home()
        found_logs = []
        
        if system == "Windows":
            search_locations = [
                Path(os.environ.get('APPDATA', '')),
                Path(os.environ.get('LOCALAPPDATA', '')),
                Path(os.environ.get('PROGRAMDATA', '')),
                home / 'AppData' / 'Roaming',
                home / 'AppData' / 'Local',
                Path('C:') / 'ProgramData',
                Path('C:') / 'Users' / 'Public' / 'Documents',
            ]
            
            for location in search_locations:
                if location.exists():
                    anydesk_folders = [
                        location / 'AnyDesk',
                        location / 'anydesk',
                        location / 'ANYDESK'
                    ]
                    for folder in anydesk_folders:
                        if folder.exists():
                            for pattern in ['*.trace', '*.log']:
                                try:
                                    for file in folder.glob(pattern):
                                        if file.is_file() and file.stat().st_size > 0:
                                            found_logs.append(file)
                                except:
                                    continue
        elif system == "Linux":
            search_patterns = [
                home / '.anydesk' / '*.trace',
                home / '.anydesk' / '*.log',
                Path('/var/log/anydesk') / '*.trace',
                Path('/var/log/anydesk') / '*.log',
            ]
            for pattern in search_patterns:
                try:
                    parent_dir = pattern.parent
                    if parent_dir.exists():
                        for file in parent_dir.glob(pattern.name):
                            if file.is_file() and file.stat().st_size > 0:
                                found_logs.append(file)
                except:
                    continue
        elif system == "Darwin":  # macOS
            search_patterns = [
                home / 'Library' / 'Application Support' / 'AnyDesk' / '*.trace',
                home / 'Library' / 'Application Support' / 'AnyDesk' / '*.log',
                home / 'Library' / 'Logs' / 'AnyDesk' / '*.trace',
                Path('/Library/Application Support/AnyDesk') / '*.trace',
            ]
            for pattern in search_patterns:
                try:
                    parent_dir = pattern.parent
                    if parent_dir.exists():
                        for file in parent_dir.glob(pattern.name):
                            if file.is_file() and file.stat().st_size > 0:
                                found_logs.append(file)
                except:
                    continue
        
        if found_logs:
            found_logs.sort(key=lambda x: (x.stat().st_mtime, x.stat().st_size), reverse=True)
        
        return found_logs

    def emit_event(self, event_type, data=None):
        """Emit structured event for Electron app"""
        if data is None:
            data = {}
        
        # Add timestamp to all events
        data['timestamp'] = datetime.now().isoformat()
        
        # Convert data to JSON string
        data_json = json.dumps(data, default=str)
        
        # Print in the format: TYPE-DATA
        print(f"{event_type}[DDD]{data_json}")

    def extract_timestamp(self, line):
        """Extract timestamp from log line - FIXED VERSION"""
        patterns = [
            # Standard AnyDesk format: INFO  2024-01-15 14:30:25.123
            r'^\s*\w+\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{3})?)',
            # Date and time at start: 2024-01-15 14:30:25.123
            r'^\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{3})?)',
            # Bracketed timestamp: [2024-01-15 14:30:25.123]
            r'^\s*\[(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{3})?)\]',
        ]
        
        for i, pattern in enumerate(patterns):
            timestamp_match = re.search(pattern, line)
            if timestamp_match:
                timestamp_str = timestamp_match.group(1)
                self.debug_print(f"Extracted timestamp '{timestamp_str}' using pattern {i+1}")
                return timestamp_str
        
        # If no pattern matches, return None to skip this line
        self.debug_print(f"No timestamp pattern matched for line: {line[:50]}...")
        return None

    def parse_timestamp(self, timestamp_str):
        """Parse timestamp string to datetime object - FIXED VERSION"""
        if not timestamp_str:
            return None
            
        patterns = [
            '%Y-%m-%d %H:%M:%S.%f',  # 2024-01-15 14:30:25.123
            '%Y-%m-%d %H:%M:%S',     # 2024-01-15 14:30:25
        ]
        
        for pattern in patterns:
            try:
                # Parse as local time (AnyDesk logs in local timezone)
                parsed_time = datetime.strptime(timestamp_str, pattern)
                self.debug_print(f"Parsed timestamp: {parsed_time}")
                return parsed_time
            except ValueError:
                continue
        
        self.debug_print(f"Failed to parse timestamp: {timestamp_str}")
        return None

    def is_within_timeframe(self, timestamp_str, minutes_ago=15):
        """Check if timestamp is within the specified minutes from now - FIXED VERSION"""
        if not timestamp_str:
            return False
            
        try:
            log_time = self.parse_timestamp(timestamp_str)
            if not log_time:
                return False
                
            current_time = datetime.now()
            cutoff_time = current_time - timedelta(minutes=minutes_ago)
            
            # Simple comparison - both times are in local timezone
            is_within = cutoff_time <= log_time <= current_time
            
            self.debug_print(f"Time check: log_time={log_time}, cutoff_time={cutoff_time}, current_time={current_time}, within_timeframe={is_within}")
            return is_within
                
        except Exception as e:
            self.debug_print(f"Error in timeframe check: {e}")
            return False

    def process_line(self, line, is_historical=False):
        """Process a single log line and detect events"""
        line = line.strip()
        if not line:
            return
        
        timestamp = self.extract_timestamp(line)
        if not timestamp:
            return  # Skip lines without valid timestamps
        
        # Add historical flag to data
        base_data = {
            'log_timestamp': timestamp,
            'is_historical': is_historical
        }
        
        startup_patterns = [
            "AnyDesk Linux Startup",
            "AnyDesk Windows Startup", 
            "AnyDesk macOS Startup",
            "AnyDesk Startup",
            "Starting AnyDesk"
        ]
        
        # AnyDesk startup
        if any(pattern in line for pattern in startup_patterns):
            version_match = re.search(r'Version ([\d.]+)', line)
            data = base_data.copy()
            if version_match:
                data['version'] = version_match.group(1)
            self.emit_event('start-app', data)
        
        elif "Accept request from" in line:
            anydesk_id_match = re.search(r'Accept request from (\d+)', line)
            if anydesk_id_match:
                anydesk_id = anydesk_id_match.group(1)
                self.current_session['anydesk_id'] = anydesk_id
                self.current_session['request_time'] = timestamp
                
                data = base_data.copy()
                data.update({
                    'anydesk_id': anydesk_id
                })
                
                # Check if it's via relay
                if "via relay" in line:
                    data['connection_type'] = 'relay'
                else:
                    data['connection_type'] = 'direct'
                
                self.emit_event('connection-request', data)
                
                # Also emit a more specific "user-connected" event for immediate detection
                self.emit_event('user-connected', data)
        
        # Client information
        elif "Client-ID:" in line and "FPR:" in line:
            client_match = re.search(r'Client-ID: (\d+).*FPR: ([a-f0-9]+)', line)
            if client_match:
                client_id = client_match.group(1)
                fingerprint = client_match.group(2)
                
                data = base_data.copy()
                data.update({
                    'client_id': client_id,
                    'fingerprint': fingerprint
                })
                
                # Extract IP if available
                ip_match = re.search(r'from ([\d.]+):', line)
                if ip_match:
                    data['ip_address'] = ip_match.group(1)
                
                self.emit_event('client-identified', data)
        
        # Authentication events
        elif "Authenticated" in line:
            auth_type = "unknown"
            if "local user" in line:
                auth_type = "local_user"
            elif "correct passphrase" in line:
                auth_type = "password"
            elif "permanent token" in line:
                auth_type = "saved_token"
            
            data = base_data.copy()
            data['auth_method'] = auth_type
            
            # Check for profile usage
            profile_match = re.search(r'Profile was used: (\w+)', line)
            if profile_match:
                data['profile'] = profile_match.group(1)
            
            self.emit_event('authentication-success', data)
        
        # Session started
        elif "Session started" in line and "ok" in line:
            data = base_data.copy()
            if hasattr(self, 'session_features') and self.session_features:
                data['features'] = self.session_features
            self.emit_event('session-started', data)
        
        # Session features
        elif "Session features:" in line:
            features_match = re.search(r'Session features: (.+)', line)
            if features_match:
                self.session_features = features_match.group(1)
        
        # Session ended
        elif "Session closed" in line or "Session stopped" in line:
            reason = "unknown"
            if "locally" in line:
                reason = "local_close"
            elif "remote side" in line:
                reason = "remote_close"
            elif "desk_rt_user_close" in line:
                reason = "user_close"
            elif "desk_rt_ipc_error" in line:
                reason = "connection_error"
            
            data = base_data.copy()
            data['reason'] = reason
            self.emit_event('session-ended', data)
        
        # Connection established to relay
        elif "Connection established" in line and "relay" in line:
            data = base_data.copy()
            data['connection_type'] = 'relay'
            self.emit_event('network-connected', data)
        
        # App shutdown
        elif "Exiting normally" in line:
            data = base_data.copy()
            self.emit_event('app-shutdown', data)
        
        # Network ID assignment
        elif "Network ID:" in line:
            network_match = re.search(r'Network ID: (\w+)', line)
            if network_match:
                network_id = network_match.group(1)
                data = base_data.copy()
                data['network_id'] = network_id
                self.emit_event('network-id-assigned', data)
        
        # External IP detection
        elif "External address:" in line:
            ip_match = re.search(r'External address: ([\d.]+:\d+)', line)
            if ip_match:
                external_ip = ip_match.group(1)
                data = base_data.copy()
                data['external_ip'] = external_ip
                self.emit_event('external-ip-detected', data)

    def check_historical_logs(self, minutes_ago=15):
        """Check logs from the last N minutes for recent activity - FIXED VERSION"""
        if not self.log_path.exists():
            return
        
        try:
            self.debug_print(f"Starting historical scan for last {minutes_ago} minutes")
            historical_events = []
            
            # Instead of reading a fixed chunk, we'll read line by line from the end
            # until we find timestamps older than our cutoff
            
            cutoff_time = datetime.now() - timedelta(minutes=minutes_ago)
            
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                # Get file size
                f.seek(0, 2)
                file_size = f.tell()
                
                # Start from a reasonable position near the end
                # Read last 50KB instead of 100KB for more precision
                read_size = min(50000, file_size)
                f.seek(max(0, file_size - read_size))
                
                # Skip partial first line
                if f.tell() > 0:
                    f.readline()
                
                lines = f.readlines()
            
            self.debug_print(f"Read {len(lines)} lines from last {read_size} bytes")
            
            # Process lines in reverse order (newest first) until we hit our time limit
            lines_processed = 0
            found_old_timestamp = False
            
            for line in reversed(lines):
                line = line.strip()
                if not line:
                    continue
                
                lines_processed += 1
                timestamp_str = self.extract_timestamp(line)
                
                if not timestamp_str:
                    continue
                
                # Parse timestamp and check if it's within our timeframe
                log_time = self.parse_timestamp(timestamp_str)
                if not log_time:
                    continue
                    
                # If this timestamp is older than our cutoff, stop processing
                if log_time < cutoff_time:
                    found_old_timestamp = True
                    self.debug_print(f"Found timestamp older than cutoff: {log_time} < {cutoff_time}")
                    break
                
                # This line is within our timeframe
                historical_events.append(line)
                self.debug_print(f"Found recent event: {line[:100]}...")
            
            # Reverse events back to chronological order
            historical_events.reverse()
            
            self.debug_print(f"Processed {lines_processed} lines, found {len(historical_events)} recent events")
            
            if historical_events:
                # Emit event about historical scan
                data = {
                    'minutes_checked': minutes_ago,
                    'events_found': len(historical_events)
                }
                self.emit_event('historical-scan-started', data)
                
                # Process each historical event
                for event_line in historical_events:
                    self.process_line(event_line, is_historical=True)
                
                # Emit completion event
                data = {
                    'minutes_checked': minutes_ago,
                    'events_processed': len(historical_events)
                }
                self.emit_event('historical-scan-completed', data)
            else:
                # No recent events found
                data = {
                    'minutes_checked': minutes_ago,
                    'events_found': 0,
                    'lines_processed': lines_processed,
                    'found_old_data': found_old_timestamp
                }
                self.emit_event('historical-scan-no-events', data)
            
            # Set position to end of file for live monitoring
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(0, 2)
                self.last_position = f.tell()
            
        except Exception as e:
            data = {
                'error': 'historical_scan_error',
                'message': str(e),
                'minutes_checked': minutes_ago
            }
            self.emit_event('ERROR', data)

    def follow_file(self):
        """Follow the log file like 'tail -f'"""
        try:
            if not self.log_path.exists():
                # Emit error event
                found_logs = self.find_anydesk_logs()
                data = {
                    'error': 'log_file_not_found',
                    'found_logs': [str(log) for log in found_logs] if found_logs else []
                }
                self.emit_event('ERROR', data)
                return
            
            # Emit monitoring started event
            data = {
                'file_position': self.last_position
            }
            self.emit_event('monitoring-started', data)
            
            while True:
                try:
                    with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(self.last_position)
                        new_lines = f.readlines()
                        
                        if new_lines:
                            for line in new_lines:
                                self.process_line(line, is_historical=False)
                            self.last_position = f.tell()
                    
                    time.sleep(0.1)
                    
                except FileNotFoundError:
                    data = {
                        'error': 'log_file_disappeared',
                        'log_path': str(self.log_path)
                    }
                    self.emit_event('ERROR', data)
                    time.sleep(1)
                    continue
                except KeyboardInterrupt:
                    data = {'reason': 'user_interrupt'}
                    self.emit_event('monitoring-stopped', data)
                    break
                except Exception as e:
                    data = {
                        'error': 'processing_error',
                        'message': str(e)
                    }
                    self.emit_event('ERROR', data)
                    time.sleep(1)
                    
        except Exception as e:
            data = {
                'error': 'fatal_error',
                'message': str(e)
            }
            self.emit_event('ERROR', data)

    def start_monitoring(self, check_historical=True, historical_minutes=15):
        """Start the live monitoring with optional historical check"""
        # Emit initialization event
        data = {
            'log_path': str(self.log_path),
            'log_exists': self.log_path.exists(),
            'check_historical': check_historical,
            'historical_minutes': historical_minutes if check_historical else 0
        }
        self.emit_event('monitor-initialized', data)
        
        # Check historical logs if requested
        if check_historical and self.log_path.exists():
            self.check_historical_logs(historical_minutes)
        
        # Start live monitoring
        self.follow_file()

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='AnyDesk Live Log Monitor - Fixed Version')
    parser.add_argument('--log-path', '-l', help='Path to AnyDesk log file (auto-detected by default)')
    parser.add_argument('--find-logs', action='store_true',
                       help='Find and list all AnyDesk log files')
    parser.add_argument('--check-history', action='store_true', default=True,
                       help='Check historical logs on startup (default: enabled)')
    parser.add_argument('--no-history', action='store_true',
                       help='Disable historical log checking')
    parser.add_argument('--history-minutes', type=int, default=15,
                       help='Minutes of historical logs to check (default: 15)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug output')
    
    args = parser.parse_args()
    
    monitor = AnydeskLiveMonitor(args.log_path, debug=args.debug)
    
    if args.find_logs:
        found_logs = monitor.find_anydesk_logs()
        data = {
            'found_logs': [str(log) for log in found_logs] if found_logs else [],
            'count': len(found_logs)
        }
        monitor.emit_event('logs-found', data)
        return
    
    # Determine if we should check historical logs
    check_historical = args.check_history and not args.no_history
    
    try:
        monitor.start_monitoring(
            check_historical=check_historical,
            historical_minutes=args.history_minutes
        )
    except KeyboardInterrupt:
        data = {'reason': 'keyboard_interrupt'}
        monitor.emit_event('completed', data)

if __name__ == "__main__":
    main()
