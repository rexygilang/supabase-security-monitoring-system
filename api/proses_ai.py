import json
import time
import asyncio
import os
from http.server import BaseHTTPRequestHandler

async def simulate_rf_model(payload_data):
    """
    Simulates NVIDIA NIM Random Forest Classifier.
    Simulated network/inference latency: 0.3 seconds.
    """
    start_time = time.perf_counter()
    await asyncio.sleep(0.30)  # Simulated model execution time
    elapsed = time.perf_counter() - start_time
    
    # Feature scoring logic
    payload_str = str(payload_data).lower()
    is_suspicious = any(kw in payload_str for kw in ['drop', 'select', 'union', 'exec', '--', '1=1', 'script'])
    
    score = 0.94 if is_suspicious else 0.05
    status = "CRITICAL_THREAT" if is_suspicious else "SAFE"
    
    return {
        "model": "NVIDIA NIM - Random Forest Threat Classifier v2",
        "threat_score": score,
        "classification": status,
        "features_analyzed": ["sql_keywords", "query_length", "special_chars"],
        "execution_time_seconds": round(elapsed, 4)
    }

async def simulate_svm_model(payload_data):
    """
    Simulates NVIDIA NIM Support Vector Machine Anomaly Detector.
    Simulated network/inference latency: 0.5 seconds.
    """
    start_time = time.perf_counter()
    await asyncio.sleep(0.50)  # Simulated model execution time
    elapsed = time.perf_counter() - start_time
    
    payload_str = str(payload_data).lower()
    is_suspicious = any(kw in payload_str for kw in ['drop', 'select', 'union', 'exec', '--', '1=1', 'script'])
    
    score = 0.89 if is_suspicious else 0.08
    status = "SQL_INJECTION_ATTEMPT" if is_suspicious else "NORMAL_TRAFFIC"
    
    return {
        "model": "NVIDIA NIM - Support Vector Machine Anomaly Detector v1",
        "threat_score": score,
        "classification": status,
        "hyperplane_distance": 1.42 if is_suspicious else -0.85,
        "execution_time_seconds": round(elapsed, 4)
    }

async def process_dual_ai_parallel(payload_data):
    """
    Executes both AI models concurrently using asyncio.gather.
    Sequential time would be 0.3s + 0.5s = 0.8s.
    Parallel execution wall-clock time is max(0.3s, 0.5s) + overhead = ~0.55-0.65s.
    """
    overall_start = time.perf_counter()
    
    # CRITICAL: asyncio.gather is used for true parallel async execution
    rf_result, svm_result = await asyncio.gather(
        simulate_rf_model(payload_data),
        simulate_svm_model(payload_data)
    )
    
    total_elapsed = time.perf_counter() - overall_start
    
    threat_detected = (rf_result["threat_score"] > 0.5) or (svm_result["threat_score"] > 0.5)
    
    return {
        "status": "success",
        "execution_time_seconds": round(total_elapsed, 4),
        "execution_mode": "asynchronous_parallel",
        "predictions": {
            "random_forest": rf_result,
            "svm": svm_result
        },
        "consensus": "CRITICAL_THREAT_DETECTED" if threat_detected else "ALL_SYSTEMS_SECURE",
        "threat_level": "RED" if threat_detected else "GREEN",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }

class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else "{}"
        
        try:
            payload_data = json.loads(body)
        except Exception:
            payload_data = {"raw_text": body}
            
        result = asyncio.run(process_dual_ai_parallel(payload_data))
        
        response_body = json.dumps(result, indent=2).encode('utf-8')
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(response_body)

    def do_GET(self):
        # Demo run with default threat test payload
        default_payload = {"event": "DATABASE_QUERY", "query": "SELECT * FROM users WHERE id = 1 OR '1'='1'; DROP TABLE logs;"}
        result = asyncio.run(process_dual_ai_parallel(default_payload))
        
        response_body = json.dumps(result, indent=2).encode('utf-8')
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(response_body)
