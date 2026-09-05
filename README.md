
```markdown
# SpyShieldX - Real-Time Spyware Detection and Prevention System

SpyShieldX is a real-time spyware and malware detection system built using Python and Flask. It continuously monitors folders, scans files using ClamAV and YARA, quarantines threats, and displays live results on a web dashboard.

This project was developed as a final-year academic project to demonstrate practical integration of open-source cybersecurity tools.

---

## Features

- Real-time file monitoring using `watchdog`
- Hybrid malware detection (ClamAV + YARA)
- Automatic quarantine of malicious files
- Live web dashboard with threat statistics
- Process Monitor (using `psutil`)
- Network Monitor
- Clear detection reasons shown in the dashboard
- Support for scanning individual files and folders

---

## Tech Stack

| Category              | Technology              |
|-----------------------|-------------------------|
| Language              | Python 3                |
| Backend               | Flask                   |
| Signature Detection   | ClamAV                  |
| Pattern Detection     | YARA                    |
| Real-time Monitoring  | watchdog                |
| Process/Network Info  | psutil                  |
| Frontend              | HTML,Tailwind, Chart.js |
| Environment           | Kali Linux              |

---

## Prerequisites

Before running the project, make sure the following are installed:

- Python 3.10 or higher
- ClamAV (`clamscan` and `clamd`)
- YARA
- Kali Linux (recommended) or Ubuntu

### Install ClamAV and YARA (Kali/Ubuntu):

bash
sudo apt update
sudo apt install clamav clamav-daemon yara -y
sudo freshclam
```

---

## Installation & Setup

1. **Clone the repository**
```bash
git clone https://github.com/DeoreDishant-ps1/SpyShieldX.git
cd SpyShieldX
```

2. **Create virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install Python dependencies**
```bash
pip install -r requirements.txt
```

4. **Run the application**
```bash
python app.py
```

5. Open your browser and go to:
```
http://127.0.0.1:5000
```

---

## How It Works

1. The system monitors the Downloads folder in real-time using `watchdog`.
2. When a new file is detected, it is scanned by:
   - **ClamAV** (signature-based detection)
   - **YARA** (custom pattern-based detection)
3. If the file is found malicious, it is moved to the quarantine folder.
4. The dashboard updates live with threat count, quarantine status, and detection reasons.

---

## Limitations

- Detection depends on ClamAV signatures and custom YARA rules.
- Zero-day malware without known patterns may not be detected.
- Currently optimized for Linux (Kali/Ubuntu).
- Not a replacement for commercial antivirus solutions.

---

## Future Improvements

- Machine Learning based detection
- Persistence and autostart scanner
- Cross-platform support (Windows)
- Better report generation
- User authentication

---

## Disclaimer

This project is developed for **educational purposes only**.  
Do not use it as a primary security solution in production environments.

---

## Author

**Dishant Deore**  
Final Year Project – Computer Science & Engineering
```

