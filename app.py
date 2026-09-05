from flask import Flask, render_template, jsonify, request
import subprocess
import yara
import os
import time
import threading
import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import shutil

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('quarantine', exist_ok=True)

# Load YARA rules
try:
    rules = yara.compile(filepath='signatures/spyware_rules.yar')
    print("YARA rules loaded successfully")
except Exception as e:
    print("YARA failed:", e)
    rules = None

data = {
    "threats_detected": 0,
    "quarantined": 0,
    "files_scanned": 0,
    "protection_score": 87,
    "threat_level": 0,
    "threat_log": []
}

def update_threat_level():
    data["threat_level"] = min(100, len(data["threat_log"]) * 8 + 20)

class FileHandler(FileSystemEventHandler):
   def on_created(self, event):
    if not event.is_directory:
        if "quarantine" in event.src_path.lower():
            print(f"Ignoring quarantine file: {event.src_path}")
            return
            print(f"New file detected: {event.src_path}")
            result = scan_file_with_clam_and_yara(event.src_path)
            if result["status"] == "detected":
                success = quarantine_file(event.src_path)
                if success:
                    data["threat_log"].insert(0, {
                        "name": os.path.basename(event.src_path),
                        "platform": "LINUX",
                        "type": "MALWARE",
                        "status": "QUARANTINED",
                        "reason": result.get("reason", "Detected")
                    })
                    data["quarantined"] += 1
                data["threats_detected"] += 1
                update_threat_level()

def start_real_time_monitoring():
    import time
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

    class FileHandler(FileSystemEventHandler):
        def on_created(self, event):
            print(f"[DEBUG] FileSystemEvent triggered! Path: {event.src_path} | Is Dir: {event.is_directory}")
            
            if event.is_directory:
                print("[DEBUG] Ignored directory")
                return
                
            filepath = event.src_path
            filename = os.path.basename(filepath)
            print(f"[DEBUG] New file detected → {filename}")

            if "quarantine" in filepath.lower():
                print("[DEBUG] Ignored quarantine file")
                return

            time.sleep(2)   # Increased delay
            
            print(f"[DEBUG] Starting scan on: {filename}")
            result = scan_file_with_clam_and_yara(filepath)
            print(f"[DEBUG] Scan result: {result}")

            data["files_scanned"] += 1
            print(f"[DEBUG] Files scanned count now: {data['files_scanned']}")

            if result["status"] == "detected":
                print(f"[DEBUG] Malware detected! Quarantining...")
                success = quarantine_file(filepath)
                data["threats_detected"] += 1
                if success:
                    data["quarantined"] += 1
                data["threat_log"].insert(0, {
                    "name": filename,
                    "platform": "DOWNLOADS",
                    "type": "MALWARE",
                    "status": "QUARANTINED",
                    "reason": result.get("reason", "Real-time Detection")
                })
                update_threat_level()
                print(f"[DEBUG] ✅ SUCCESS: {filename} quarantined!")
            else:
                print(f"[DEBUG] File clean: {filename}")
                try:
                    os.remove(filepath)
                except:
                    pass

    observer = Observer()
    event_handler = FileHandler()
    downloads_path = os.path.expanduser("~/Downloads")
    
    observer.schedule(event_handler, downloads_path, recursive=False)
    observer.start()
    print(f"[Real-time Monitoring] ACTIVE on {downloads_path}")

def initial_scan_downloads():
    """Scan all existing files in Downloads folder on startup"""
    downloads_path = os.path.expanduser("~/Downloads")
    print(f"[Initial Scan] Starting scan of existing files in {downloads_path}")
    
    for filename in os.listdir(downloads_path):
        filepath = os.path.join(downloads_path, filename)
        if os.path.isfile(filepath) and not filename.startswith('.'):
            print(f"[Initial Scan] Checking: {filename}")
            result = scan_file_with_clam_and_yara(filepath)
            data["files_scanned"] += 1
            
            if result["status"] == "detected":
                success = quarantine_file(filepath)
                data["threats_detected"] += 1
                if success:
                    data["quarantined"] += 1
                data["threat_log"].insert(0, {
                    "name": filename,
                    "platform": "DOWNLOADS",
                    "type": "MALWARE",
                    "status": "QUARANTINED",
                    "reason": result.get("reason", "Initial Scan")
                })
                print(f"[Initial Scan] ✅ Quarantined: {filename}")
    
    update_threat_level()
    print("[Initial Scan] Completed")

def scan_file_with_clam_and_yara(file_path):
    print(f"[Scan] Starting fast scan: {os.path.basename(file_path)}")
    
    # Try clamdscan first (very fast)
    try:
        result = subprocess.run(['clamdscan', '--no-summary', file_path], 
                              capture_output=True, text=True, timeout=30)
        if result.returncode == 1:
            print("[Scan] ✅ ClamAV (daemon) - Malware Found")
            return {"status": "detected", "reason": "ClamAV (clamdscan) - Malware Found"}
    except:
        pass

    # Fallback to normal clamscan if daemon fails
    try:
        result = subprocess.run(['clamscan', '--no-summary', file_path], 
                              capture_output=True, text=True, timeout=45)
        if result.returncode == 1:
            print("[Scan] ✅ ClamAV - Malware Found")
            return {"status": "detected", "reason": "ClamAV - Malware Found"}
    except:
        pass

    # YARA Scan (fast pattern matching)
    try:
        rules = yara.compile(filepath='signatures/spyware_rules.yar')
        matches = rules.match(file_path)
        if matches:
            reason = f"YARA: {matches[0].rule}"
            print(f"[Scan] ✅ {reason}")
            return {"status": "detected", "reason": reason}
    except:
        pass

    print("[Scan] File is clean")
    return {"status": "clean", "reason": "Clean"}

def quarantine_file(file_path):
    q_path = os.path.join("quarantine", os.path.basename(file_path))
    
    # Try fast rename first
    try:
        os.rename(file_path, q_path)
        print(f"Successfully renamed to quarantine: {q_path}")
        return True
    except OSError as e:
        print(f"Rename failed: {e}")
        
        # Fallback: copy + force delete original
        try:
            shutil.copy2(file_path, q_path)
            print(f"Copied to quarantine: {q_path}")
            
            # Force remove original - no silent ignore
            try:
                os.remove(file_path)
                print(f"Original file deleted from temp: {file_path}")
            except Exception as delete_e:
                print(f"CRITICAL: Failed to delete original file: {delete_e}")
                print(f"File still exists at: {file_path} - MANUAL CLEANUP NEEDED")
                return False  # Do not count as quarantined if original still exists
            
            return True
        except Exception as copy_e:
            print(f"Copy failed: {copy_e}")
            return False

@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    return jsonify(data)

@app.route('/api/scan', methods=['POST'])
def upload_and_scan():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"})

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"})

    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)
    print(f"File uploaded: {file.filename}")

    # ALWAYS increment files scanned - regardless of clean or malicious
    data["files_scanned"] += 1

    result = scan_file_with_clam_and_yara(filepath)

    if result["status"] == "detected":
        success = quarantine_file(filepath)
        data["threats_detected"] += 1
        if success:
            data["quarantined"] += 1
            data["threat_log"].insert(0, {
                "name": file.filename,
                "platform": "UPLOADED",
                "type": "MALWARE",
                "status": "QUARANTINED",
                "reason": result.get("reason", "Signature Match")
            })
        else:
            data["threat_log"].insert(0, {
                "name": file.filename,
                "platform": "UPLOADED",
                "type": "MALWARE",
                "status": "DETECTED",
                "reason": result.get("reason", "Signature Match")
            })
        update_threat_level()
        msg = "Threat found and quarantined" if success else "Threat detected but quarantine failed"
        return jsonify({"status": "detected", "message": msg})

    # Clean file - remove temp file
    try:
        os.remove(filepath)
    except:
        pass

    update_threat_level()
    return jsonify({"status": "clean", "message": "File is clean"})

@app.route('/api/network')
def get_network():
    connections = psutil.net_connections(kind='inet')
    return jsonify({
        "active_connections": len(connections),
        "sample": [str(c) for c in connections[:5]]
    })

@app.route('/api/processes')
def get_processes():
    import psutil
    processes = []
    
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'cmdline']):
        try:
            pinfo = proc.info
            name = pinfo['name'] or "Unknown"
            cpu = round(pinfo['cpu_percent'] or 0, 1)
            mem = round(pinfo['memory_percent'] or 0, 1)
            cmd = " ".join(pinfo['cmdline'])[:100] if pinfo['cmdline'] else ""
            
            # Risk Scoring Logic
            risk_score = 0
            risk_level = "Low"
            color = "green"
            
            if cpu > 30 or mem > 25:
                risk_score += 40
            if any(susp in name.lower() for susp in ['python', 'cmd', 'powershell', 'nc', 'netcat', 'bash', 'sh']):
                risk_score += 25
            if len(name) > 20 or any(char.isdigit() for char in name):
                risk_score += 20
            if "temp" in cmd.lower() or "downloads" in cmd.lower():
                risk_score += 15
                
            if risk_score >= 60:
                risk_level = "High"
                color = "red"
            elif risk_score >= 35:
                risk_level = "Medium"
                color = "yellow"
                
            processes.append({
                "pid": pinfo['pid'],
                "name": name,
                "cpu": cpu,
                "memory": mem,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "color": color,
                "cmdline": cmd[:80]
            })
        except:
            continue
    
    # Sort by risk score (highest first)
    processes.sort(key=lambda x: x['risk_score'], reverse=True)
    
    return jsonify({
        "processes": processes[:50],   # Limit to top 50
        "total_processes": len(processes)
    })

if __name__ == '__main__':
    # Initial scan of existing files
    initial_scan_downloads()
    
    # Start real-time monitoring
    threading.Thread(target=start_real_time_monitoring, daemon=True).start()
    
    print("🚀 SpyShieldX started successfully!")
    print("📁 Real-time monitoring is active on ~/Downloads")
    
    app.run(host='0.0.0.0', port=5000, debug=False)
