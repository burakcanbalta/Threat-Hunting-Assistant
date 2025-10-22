import pandas as pd
import numpy as np
import json
import sqlite3
import argparse
import logging
import asyncio
import aiohttp
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import threading
import time
import os
import re
from pathlib import Path
from typing import Dict, List, Set, Any
import hashlib
import yaml
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

class ThreatHuntingAssistant:
    def __init__(self, db_path="threat_hunting.db", config_file="config.json"):
        self.db_path = db_path
        self.config = self.load_config(config_file)
        self.setup_logging()
        self.init_database()
        
        self.ioc_database = {}
        self.hunting_playbooks = self.load_hunting_playbooks()
        self.anomaly_detectors = {}
        self.correlation_engine = CorrelationEngine()
        
        self.load_ioc_feeds()

    def load_config(self, config_file):
        default_config = {
            "data_sources": {
                "elasticsearch": {
                    "hosts": ["http://localhost:9200"],
                    "index_patterns": ["logs-*", "windows-*", "network-*"]
                },
                "splunk": {
                    "host": "localhost",
                    "port": 8089,
                    "username": "",
                    "password": ""
                }
            },
            "hunting": {
                "time_window_days": 30,
                "max_results": 1000,
                "confidence_threshold": 0.7
            },
            "ioc": {
                "feeds": [
                    "./ioc_lists/malware_domains.txt",
                    "./ioc_lists/suspicious_ips.txt",
                    "./ioc_lists/emerging_threats.json"
                ],
                "update_interval": 3600
            },
            "ml": {
                "enable_anomaly_detection": True,
                "contamination": 0.1,
                "random_state": 42
            }
        }

        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    return self.merge_configs(default_config, user_config)
            except Exception as e:
                print(f"Config load error: {e}")
        
        return default_config

    def merge_configs(self, default, user):
        result = default.copy()
        for key, value in user.items():
            if isinstance(value, dict) and key in result:
                result[key] = self.merge_configs(result[key], value)
            else:
                result[key] = value
        return result

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('threat_hunting.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hunting_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                scenario TEXT,
                start_time DATETIME,
                end_time DATETIME,
                findings_count INTEGER,
                status TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hunting_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                finding_type TEXT,
                severity TEXT,
                description TEXT,
                evidence TEXT,
                confidence REAL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ioc_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                ioc_type TEXT,
                ioc_value TEXT,
                source TEXT,
                context TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS correlation_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                correlation_type TEXT,
                entities TEXT,
                confidence REAL,
                timeline TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anomaly_scores (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                entity_type TEXT,
                entity_value TEXT,
                anomaly_score REAL,
                features TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()

    def load_hunting_playbooks(self):
        playbooks_dir = Path("./hunting_playbooks")
        playbooks = {}
        
        if not playbooks_dir.exists():
            playbooks_dir.mkdir(parents=True)
            self.create_default_playbooks(playbooks_dir)
        
        for playbook_file in playbooks_dir.glob("*.yaml"):
            try:
                with open(playbook_file, 'r') as f:
                    playbook = yaml.safe_load(f)
                    playbooks[playbook['name']] = playbook
            except Exception as e:
                self.logger.error(f"Failed to load playbook {playbook_file}: {e}")
        
        return playbooks

    def create_default_playbooks(self, playbooks_dir):
        default_playbooks = {
            "lateral_movement": {
                "name": "lateral_movement",
                "description": "Detect lateral movement techniques",
                "techniques": ["T1021", "T1076", "T1080"],
                "queries": {
                    "elasticsearch": [
                        "event.action:(\"remote*\" OR \"psexec\" OR \"wmi*\")",
                        "process.name:(\"psexec*\" OR \"wmic*\" OR \"schtasks*\")"
                    ],
                    "splunk": [
                        "index=* (\"PsExec\" OR \"WMIC\" OR \"schtasks\")"
                    ]
                },
                "iocs": ["SMB connections", "RDP sessions", "WMI executions"],
                "confidence_threshold": 0.7
            },
            "persistence": {
                "name": "persistence",
                "description": "Detect persistence mechanisms",
                "techniques": ["T1543", "T1053", "T1136"],
                "queries": {
                    "elasticsearch": [
                        "registry.path:*Run* OR registry.path:*Services*",
                        "process.name:(\"schtasks*\" OR \"at*\" OR \"sc*\")"
                    ],
                    "splunk": [
                        "index=* (\"Registry\" OR \"Scheduled Task\" OR \"Service\")"
                    ]
                },
                "iocs": ["Registry modifications", "Scheduled tasks", "Service installations"],
                "confidence_threshold": 0.8
            },
            "data_exfiltration": {
                "name": "data_exfiltration",
                "description": "Detect data exfiltration attempts",
                "techniques": ["T1041", "T1020", "T1030"],
                "queries": {
                    "elasticsearch": [
                        "network.bytes:>1000000",
                        "dns.query.type:(TXT OR NULL)",
                        "url.domain:(pastebin.com OR transfer.sh)"
                    ],
                    "splunk": [
                        "index=network bytes>1000000",
                        "index=dns query_type=TX"
                    ]
                },
                "iocs": ["Large outbound transfers", "DNS tunneling", "Cloud storage uploads"],
                "confidence_threshold": 0.6
            },
            "command_control": {
                "name": "command_control",
                "description": "Detect C2 communication",
                "techniques": ["T1071", "T1090", "T1102"],
                "queries": {
                    "elasticsearch": [
                        "http.user_agent:(\"Mozilla*\" \"Python*\" \"curl*\")",
                        "dns.query.name:*.ddns.net",
                        "network.protocol:(\"DNS\" \"ICMP\")"
                    ],
                    "splunk": [
                        "index=web suspicious_user_agent=*",
                        "index=dns query=*.ddns.net"
                    ]
                },
                "iocs": ["Beaconing patterns", "Suspicious user agents", "Dynamic DNS domains"],
                "confidence_threshold": 0.75
            }
        }
        
        for name, playbook in default_playbooks.items():
            playbook_file = playbooks_dir / f"{name}.yaml"
            with open(playbook_file, 'w') as f:
                yaml.dump(playbook, f, default_flow_style=False)

    def load_ioc_feeds(self):
        ioc_dir = Path("./ioc_lists")
        if not ioc_dir.exists():
            ioc_dir.mkdir(parents=True)
        
        for feed_path in self.config['ioc']['feeds']:
            feed_file = Path(feed_path)
            if feed_file.exists():
                try:
                    if feed_file.suffix == '.json':
                        with open(feed_file, 'r') as f:
                            iocs = json.load(f)
                            self.ioc_database.update(iocs)
                    else:
                        with open(feed_file, 'r') as f:
                            for line in f:
                                line = line.strip()
                                if line and not line.startswith('#'):
                                    ioc_type = self.classify_ioc(line)
                                    if ioc_type:
                                        if ioc_type not in self.ioc_database:
                                            self.ioc_database[ioc_type] = set()
                                        self.ioc_database[ioc_type].add(line)
                except Exception as e:
                    self.logger.error(f"Failed to load IOC feed {feed_file}: {e}")
        
        self.logger.info(f"Loaded {sum(len(iocs) for iocs in self.ioc_database.values())} IOCs")

    def classify_ioc(self, ioc):
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
            return 'ip'
        elif re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', ioc):
            return 'domain'
        elif re.match(r'^[a-fA-F0-9]{32}$', ioc):
            return 'md5'
        elif re.match(r'^[a-fA-F0-9]{40}$', ioc):
            return 'sha1'
        elif re.match(r'^[a-fA-F0-9]{64}$', ioc):
            return 'sha256'
        elif re.match(r'^https?://', ioc):
            return 'url'
        return None

    def run_hunting_scenario(self, scenario_name, time_window=None):
        if scenario_name not in self.hunting_playbooks:
            self.logger.error(f"Unknown scenario: {scenario_name}")
            return None
        
        playbook = self.hunting_playbooks[scenario_name]
        session_id = f"{scenario_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self.logger.info(f"Starting hunting session: {session_id}")
        
        start_time = datetime.now()
        findings = []
        
        self.save_hunting_session(session_id, scenario_name, start_time, None, 0, "RUNNING")
        
        try:
            ioc_matches = self.hunt_iocs(playbook, session_id)
            behavioral_findings = self.hunt_behavioral(playbook, session_id, time_window)
            ml_anomalies = self.hunt_anomalies(playbook, session_id, time_window)
            
            findings.extend(ioc_matches)
            findings.extend(behavioral_findings)
            findings.extend(ml_anomalies)
            
            correlated_findings = self.correlate_findings(findings, session_id)
            findings.extend(correlated_findings)
            
            end_time = datetime.now()
            self.save_hunting_session(session_id, scenario_name, start_time, end_time, len(findings), "COMPLETED")
            
            self.generate_scenario_report(session_id, findings, playbook)
            
            return findings
            
        except Exception as e:
            self.logger.error(f"Hunting scenario failed: {e}")
            self.save_hunting_session(session_id, scenario_name, start_time, datetime.now(), 0, "FAILED")
            return None

    def hunt_iocs(self, playbook, session_id):
        findings = []
        
        for ioc_type, ioc_values in self.ioc_database.items():
            for ioc_value in ioc_values:
                context = self.check_ioc_context(ioc_value, ioc_type, playbook)
                if context:
                    finding = {
                        'session_id': session_id,
                        'finding_type': 'IOC_MATCH',
                        'severity': 'HIGH',
                        'description': f"IOC Match: {ioc_value}",
                        'evidence': context,
                        'confidence': 0.9
                    }
                    findings.append(finding)
                    
                    self.save_ioc_match(session_id, ioc_type, ioc_value, 'IOC_FEED', context)
        
        return findings

    def check_ioc_context(self, ioc_value, ioc_type, playbook):
        return f"Found in {ioc_type} feed matching {playbook['name']} scenario"

    def hunt_behavioral(self, playbook, session_id, time_window):
        findings = []
        
        for data_source, queries in playbook.get('queries', {}).items():
            for query in queries:
                try:
                    results = self.execute_query(data_source, query, time_window)
                    for result in results:
                        finding = {
                            'session_id': session_id,
                            'finding_type': 'BEHAVIORAL',
                            'severity': 'MEDIUM',
                            'description': f"Behavioral pattern detected: {query}",
                            'evidence': str(result),
                            'confidence': 0.7
                        }
                        findings.append(finding)
                except Exception as e:
                    self.logger.error(f"Query execution failed for {data_source}: {e}")
        
        return findings

    def execute_query(self, data_source, query, time_window):
        if data_source == 'elasticsearch':
            return self.execute_elasticsearch_query(query, time_window)
        elif data_source == 'splunk':
            return self.execute_splunk_query(query, time_window)
        else:
            return []

    def execute_elasticsearch_query(self, query, time_window):
        return [{"sample": "result", "query": query}]

    def execute_splunk_query(self, query, time_window):
        return [{"sample": "result", "query": query}]

    def hunt_anomalies(self, playbook, session_id, time_window):
        if not self.config['ml']['enable_anomaly_detection']:
            return []
        
        findings = []
        
        try:
            features = self.extract_anomaly_features(playbook, time_window)
            if features and len(features) > 10:
                anomalies = self.detect_anomalies(features, playbook['name'])
                
                for anomaly in anomalies:
                    finding = {
                        'session_id': session_id,
                        'finding_type': 'ANOMALY',
                        'severity': 'HIGH' if anomaly['score'] > 0.8 else 'MEDIUM',
                        'description': f"Anomaly detected: {anomaly['entity']}",
                        'evidence': f"Anomaly score: {anomaly['score']:.3f}",
                        'confidence': anomaly['score']
                    }
                    findings.append(finding)
                    
                    self.save_anomaly_score(session_id, 'BEHAVIORAL', anomaly['entity'], 
                                          anomaly['score'], str(anomaly['features']))
        
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
        
        return findings

    def extract_anomaly_features(self, playbook, time_window):
        features = []
        
        end_time = datetime.now()
        start_time = end_time - timedelta(days=time_window or self.config['hunting']['time_window_days'])
        
        for i in range(100):
            feature_vector = {
                'network_connections': np.random.poisson(50),
                'process_creations': np.random.poisson(100),
                'file_creations': np.random.poisson(30),
                'registry_modifications': np.random.poisson(20),
                'dns_queries': np.random.poisson(200),
                'user_logons': np.random.poisson(10)
            }
            features.append(feature_vector)
        
        return features

    def detect_anomalies(self, features, scenario_name):
        if scenario_name not in self.anomaly_detectors:
            self.anomaly_detectors[scenario_name] = IsolationForest(
                contamination=self.config['ml']['contamination'],
                random_state=self.config['ml']['random_state']
            )
        
        feature_matrix = np.array([list(f.values()) for f in features])
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(feature_matrix)
        
        detector = self.anomaly_detectors[scenario_name]
        anomaly_scores = detector.fit_predict(scaled_features)
        decision_scores = detector.decision_function(scaled_features)
        
        anomalies = []
        for i, (score, decision) in enumerate(zip(anomaly_scores, decision_scores)):
            if score == -1:
                anomaly = {
                    'entity': f"Entity_{i}",
                    'score': max(0.5, 1 - decision),
                    'features': features[i]
                }
                anomalies.append(anomaly)
        
        return anomalies

    def correlate_findings(self, findings, session_id):
        correlated = self.correlation_engine.correlate(findings)
        
        results = []
        for correlation in correlated:
            result = {
                'session_id': session_id,
                'finding_type': 'CORRELATION',
                'severity': 'HIGH',
                'description': f"Correlated events: {correlation['type']}",
                'evidence': f"Entities: {correlation['entities']}",
                'confidence': correlation['confidence']
            }
            results.append(result)
            
            self.save_correlation_result(session_id, correlation['type'], 
                                       str(correlation['entities']), correlation['confidence'],
                                       str(correlation.get('timeline', '')))
        
        return results

    def save_hunting_session(self, session_id, scenario, start_time, end_time, findings_count, status):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO hunting_sessions 
            (session_id, scenario, start_time, end_time, findings_count, status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session_id, scenario, start_time, end_time, findings_count, status))
        
        conn.commit()
        conn.close()

    def save_finding(self, session_id, finding_type, severity, description, evidence, confidence):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO hunting_findings 
            (session_id, finding_type, severity, description, evidence, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (session_id, finding_type, severity, description, evidence, confidence))
        
        conn.commit()
        conn.close()

    def save_ioc_match(self, session_id, ioc_type, ioc_value, source, context):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO ioc_matches 
            (session_id, ioc_type, ioc_value, source, context)
            VALUES (?, ?, ?, ?, ?)
        ''', (session_id, ioc_type, ioc_value, source, context))
        
        conn.commit()
        conn.close()

    def save_correlation_result(self, session_id, correlation_type, entities, confidence, timeline):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO correlation_results 
            (session_id, correlation_type, entities, confidence, timeline)
            VALUES (?, ?, ?, ?, ?)
        ''', (session_id, correlation_type, entities, confidence, timeline))
        
        conn.commit()
        conn.close()

    def save_anomaly_score(self, session_id, entity_type, entity_value, anomaly_score, features):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO anomaly_scores 
            (session_id, entity_type, entity_value, anomaly_score, features)
            VALUES (?, ?, ?, ?, ?)
        ''', (session_id, entity_type, entity_value, anomaly_score, features))
        
        conn.commit()
        conn.close()

    def generate_scenario_report(self, session_id, findings, playbook):
        report = {
            'session_id': session_id,
            'scenario': playbook['name'],
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_findings': len(findings),
                'high_severity': len([f for f in findings if f['severity'] == 'HIGH']),
                'medium_severity': len([f for f in findings if f['severity'] == 'MEDIUM']),
                'average_confidence': np.mean([f['confidence'] for f in findings]) if findings else 0
            },
            'findings': findings,
            'recommendations': self.generate_recommendations(findings, playbook)
        }
        
        report_file = f"./reports/{session_id}_report.json"
        os.makedirs(os.path.dirname(report_file), exist_ok=True)
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.logger.info(f"Report generated: {report_file}")
        return report

    def generate_recommendations(self, findings, playbook):
        recommendations = []
        
        high_findings = [f for f in findings if f['severity'] == 'HIGH']
        if high_findings:
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Immediate investigation required',
                'details': f"{len(high_findings)} high severity findings detected"
            })
        
        ioc_findings = [f for f in findings if f['finding_type'] == 'IOC_MATCH']
        if ioc_findings:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Update blocking rules',
                'details': f"{len(ioc_findings)} known IOCs detected"
            })
        
        anomaly_findings = [f for f in findings if f['finding_type'] == 'ANOMALY']
        if anomaly_findings:
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Review anomaly detection rules',
                'details': f"{len(anomaly_findings)} behavioral anomalies detected"
            })
        
        return recommendations

    def generate_comprehensive_report(self, days=7, output_format='json'):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT scenario, COUNT(*) as session_count, 
                   AVG(findings_count) as avg_findings,
                   SUM(CASE WHEN status = 'COMPLETED' THEN 1 ELSE 0 END) as completed_sessions
            FROM hunting_sessions 
            WHERE start_time > datetime('now', '-? days')
            GROUP BY scenario
        ''', (days,))
        
        scenario_stats = cursor.fetchall()
        
        cursor.execute('''
            SELECT finding_type, severity, COUNT(*) as count
            FROM hunting_findings 
            WHERE timestamp > datetime('now', '-? days')
            GROUP BY finding_type, severity
            ORDER BY count DESC
        ''', (days,))
        
        finding_stats = cursor.fetchall()
        
        cursor.execute('''
            SELECT ioc_type, COUNT(*) as count
            FROM ioc_matches 
            WHERE timestamp > datetime('now', '-? days')
            GROUP BY ioc_type
            ORDER BY count DESC
        ''', (days,))
        
        ioc_stats = cursor.fetchall()
        
        conn.close()
        
        report_data = {
            'report_period_days': days,
            'generated_at': datetime.now().isoformat(),
            'scenario_statistics': [
                {
                    'scenario': stat[0],
                    'session_count': stat[1],
                    'average_findings': round(stat[2] or 0, 2),
                    'completed_sessions': stat[3]
                } for stat in scenario_stats
            ],
            'finding_statistics': [
                {
                    'type': stat[0],
                    'severity': stat[1],
                    'count': stat[2]
                } for stat in finding_stats
            ],
            'ioc_statistics': [
                {
                    'type': stat[0],
                    'count': stat[1]
                } for stat in ioc_stats
            ]
        }
        
        if output_format == 'json':
            return json.dumps(report_data, indent=2, default=str)
        elif output_format == 'html':
            return self.generate_html_report(report_data)
        else:
            return self.format_text_report(report_data)

    def format_text_report(self, report_data):
        output = f"Threat Hunting Comprehensive Report\n"
        output += "=" * 60 + "\n"
        output += f"Period: Last {report_data['report_period_days']} days\n"
        output += f"Generated: {report_data['generated_at']}\n\n"
        
        output += "Scenario Statistics:\n"
        output += "-" * 30 + "\n"
        for stat in report_data['scenario_statistics']:
            output += f"{stat['scenario']}: {stat['session_count']} sessions, "
            output += f"{stat['average_findings']:.1f} avg findings\n"
        
        output += "\nFinding Statistics:\n"
        output += "-" * 30 + "\n"
        for stat in report_data['finding_statistics']:
            output += f"{stat['type']} ({stat['severity']}): {stat['count']} findings\n"
        
        output += "\nIOC Statistics:\n"
        output += "-" * 30 + "\n"
        for stat in report_data['ioc_statistics']:
            output += f"{stat['type']}: {stat['count']} matches\n"
        
        return output

    def generate_html_report(self, report_data):
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Threat Hunting Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
                .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
                .stat { background: #f8f9fa; padding: 10px; margin: 5px 0; border-radius: 3px; }
                .high { border-left: 4px solid #e74c3c; }
                .medium { border-left: 4px solid #f39c12; }
                .low { border-left: 4px solid #3498db; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Threat Hunting Report</h1>
                <p>Period: Last {{period}} days | Generated: {{timestamp}}</p>
            </div>
            
            <div class="section">
                <h2>Scenario Statistics</h2>
                {% for stat in scenario_stats %}
                <div class="stat">
                    <strong>{{ stat.scenario }}</strong>: {{ stat.session_count }} sessions, 
                    {{ stat.average_findings }} avg findings
                </div>
                {% endfor %}
            </div>
            
            <div class="section">
                <h2>Finding Statistics</h2>
                {% for stat in finding_stats %}
                <div class="stat {{ stat.severity.lower() }}">
                    {{ stat.type }} ({{ stat.severity }}): {{ stat.count }} findings
                </div>
                {% endfor %}
            </div>
        </body>
        </html>
        """
        
        from jinja2 import Template
        template = Template(html_template)
        return template.render(
            period=report_data['report_period_days'],
            timestamp=report_data['generated_at'],
            scenario_stats=report_data['scenario_statistics'],
            finding_stats=report_data['finding_statistics']
        )

    def continuous_monitoring(self, interval=3600):
        self.logger.info(f"Starting continuous threat hunting (interval: {interval}s)")
        
        try:
            while True:
                self.logger.info("Starting monitoring cycle")
                
                for scenario_name in self.hunting_playbooks.keys():
                    findings = self.run_hunting_scenario(scenario_name, time_window=1)
                    
                    if findings:
                        high_findings = [f for f in findings if f['severity'] == 'HIGH']
                        if high_findings:
                            self.logger.warning(f"🚨 HIGH severity findings in {scenario_name}: {len(high_findings)}")
                
                self.logger.info(f"Monitoring cycle completed. Sleeping for {interval} seconds")
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.logger.info("Continuous monitoring stopped")

class CorrelationEngine:
    def __init__(self):
        self.entity_graph = defaultdict(set)
        self.temporal_windows = []
    
    def correlate(self, findings):
        correlated = []
        
        entities = self.extract_entities(findings)
        self.build_entity_graph(entities)
        
        temporal_correlations = self.temporal_analysis(findings)
        behavioral_correlations = self.behavioral_analysis(findings)
        
        correlated.extend(temporal_correlations)
        correlated.extend(behavioral_correlations)
        
        return correlated
    
    def extract_entities(self, findings):
        entities = []
        for finding in findings:
            if 'evidence' in finding:
                entities.extend(self.parse_entities(finding['evidence']))
        return entities
    
    def parse_entities(self, text):
        entities = []
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        domain_pattern = r'[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+'
        
        entities.extend(re.findall(ip_pattern, str(text)))
        entities.extend(re.findall(domain_pattern, str(text)))
        
        return entities
    
    def build_entity_graph(self, entities):
        for i, entity1 in enumerate(entities):
            for entity2 in entities[i+1:]:
                self.entity_graph[entity1].add(entity2)
                self.entity_graph[entity2].add(entity1)
    
    def temporal_analysis(self, findings):
        time_buckets = defaultdict(list)
        
        for finding in findings:
            if 'timestamp' in finding:
                hour_bucket = finding['timestamp'].strftime('%Y-%m-%d %H:00')
                time_buckets[hour_bucket].append(finding)
        
        correlations = []
        for bucket, bucket_findings in time_buckets.items():
            if len(bucket_findings) >= 3:
                correlation = {
                    'type': 'TEMPORAL_CORRELATION',
                    'entities': [f['description'][:50] for f in bucket_findings],
                    'confidence': min(0.9, len(bucket_findings) * 0.2),
                    'timeline': bucket
                }
                correlations.append(correlation)
        
        return correlations
    
    def behavioral_analysis(self, findings):
        behavioral_patterns = defaultdict(list)
        
        for finding in findings:
            if 'finding_type' in finding:
                behavioral_patterns[finding['finding_type']].append(finding)
        
        correlations = []
        for pattern_type, pattern_findings in behavioral_patterns.items():
            if len(pattern_findings) >= 2:
                correlation = {
                    'type': f'BEHAVIORAL_{pattern_type}',
                    'entities': [f['description'][:30] for f in pattern_findings],
                    'confidence': min(0.8, len(pattern_findings) * 0.3),
                    'timeline': f"{len(pattern_findings)} occurrences"
                }
                correlations.append(correlation)
        
        return correlations

def main():
    parser = argparse.ArgumentParser(description='Threat Hunting Assistant')
    parser.add_argument('--scenario', help='Run specific hunting scenario')
    parser.add_argument('--list-scenarios', action='store_true', help='List available scenarios')
    parser.add_argument('--report', action='store_true', help='Generate comprehensive report')
    parser.add_argument('--days', type=int, default=7, help='Days for report generation')
    parser.add_argument('--format', choices=['text', 'json', 'html'], default='text', help='Report format')
    parser.add_argument('--monitor', action='store_true', help='Continuous monitoring')
    parser.add_argument('--interval', type=int, default=3600, help='Monitoring interval in seconds')
    
    args = parser.parse_args()
    
    hunter = ThreatHuntingAssistant()
    
    if args.list_scenarios:
        print("Available hunting scenarios:")
        for scenario in hunter.hunting_playbooks.keys():
            print(f"  - {scenario}")
        return
    
    if args.scenario:
        findings = hunter.run_hunting_scenario(args.scenario)
        if findings:
            print(f"✅ Hunting completed: {len(findings)} findings")
        else:
            print("❌ Hunting failed or no findings")
    
    if args.report:
        report = hunter.generate_comprehensive_report(args.days, args.format)
        print(report)
    
    if args.monitor:
        hunter.continuous_monitoring(args.interval)
    
    if not any([args.scenario, args.report, args.monitor, args.list_scenarios]):
        parser.print_help()

if __name__ == "__main__":
    main()
