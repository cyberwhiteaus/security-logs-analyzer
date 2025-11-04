[README.md](https://github.com/user-attachments/files/23330860/README.md)
# 🔍 Security Log Analyzer

A Python-based security tool that analyzes web server logs to detect potential cyber attacks in real-time.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Security](https://img.shields.io/badge/Security-Cyber%20Defense-red)
![Status](https://img.shields.io/badge/Status-Completed-green)

## 🚀 Features

- **Brute-force Attack Detection** - Identifies multiple rapid login attempts from same IP
- **SQL Injection Detection** - Flags suspicious SQL commands in URL parameters
- **Real-time Analysis** - Processes logs and generates instant security reports
- **Customizable Rules** - Easy to modify detection thresholds and patterns

## 🛡️ Security Threats Detected

| Threat Type | Detection Method | Example |
|-------------|------------------|---------|
| Brute-force | IP-based request counting | `192.168.1.100 - 6 login attempts` |
| SQL Injection | Keyword pattern matching | `admin.php?user=1' OR '1'='1` |

## 📁 Project Structure
