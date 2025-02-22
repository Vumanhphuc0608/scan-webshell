import os
import re
import hashlib
import requests
import base64
import psutil
import datetime

# Các hàm và API thường bị lợi dụng trong webshell
suspicious_patterns = [
    r'system\s*\(', r'exec\s*\(', r'shell_exec\s*\(', r'passthru\s*\(', r'popen\s*\(', r'eval\s*\(',
    r'assert\s*\(', r'include\s*\(', r'require\s*\(', r'CreateObject\("WScript.Shell"\)\.Run',
    r'move_uploaded_file\s*\(', r'file_get_contents\s*\(', r'file_put_contents\s*\(',
    r'GetSystemInfo', r'GetUserName', r'GetComputerName', r'VirtualAlloc', r'VirtualFree',
    r'CreateFile', r'ReadFile', r'WriteFile', r'DeleteFile', r'FindFirstFile', r'FindNextFile',
    r'CreateProcess', r'OpenProcess', r'TerminateProcess', r'GetExitCodeProcess', r'ShellExecute', r'ShellExecuteEx',
    r'WSASocket', r'connect', r'send', r'recv', r'bind', r'listen', r'accept',
    r'RegOpenKeyEx', r'RegSetValueEx', r'RegQueryValueEx', r'RegDeleteKey', r'RegDeleteValue',
    r'ReadProcessMemory', r'WriteProcessMemory'
]

log_file = "webshell_scan.log"

def log_message(message):
    print(message)
    with open(log_file, "a",encoding="utf-8") as log:
        log.write(message + "\n")

# Hàm tính hash SHA256 của file
def calculate_hash(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        log_message(f"[-] Lỗi khi tính hash của file {file_path}: {e}")
        return None

# Kiểm tra hash file trên VirusTotal
def check_virustotal(api_key, file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            log_message(f"[-] Lỗi từ VirusTotal API: {response.status_code}")
    except Exception as e:
        log_message(f"[-] Lỗi kết nối đến VirusTotal: {e}")
    return None

# Kiểm tra xem file có chứa mã bị obfuscate không
def is_obfuscated(content):
    if re.search(r'base64_decode\s*\(', content) or len(re.findall(r'[A-Za-z0-9+/]{20,}=*', content)) > 5:
        return True
    return False

# Kiểm tra process đáng ngờ
def check_suspicious_processes():
    suspicious_processes = ["cmd.exe", "powershell.exe", "bash", "sh"]
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'] in suspicious_processes:
            log_message(f"[!] Phát hiện process đáng ngờ: {process.info['name']} (PID: {process.info['pid']})")

# Kiểm tra file config có dấu hiệu lạ
def check_config_files(directory):
    config_files = [".htaccess", "web.config"]
    for root, _, files in os.walk(directory):
        for file in files:
            if file in config_files:
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if any(re.search(pattern, content) for pattern in suspicious_patterns):
                        log_message(f"[!] Phát hiện mã đáng ngờ trong file config: {file_path}")

# Phát hiện file có CreateTime khác biệt
def detect_anomalous_files(directory):
    timestamps = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                create_time = os.stat(file_path).st_ctime
                timestamps.append(create_time)
            except Exception as e:
                log_message(f"[-] Lỗi khi kiểm tra thời gian tạo file {file_path}: {e}")
    if timestamps:
        avg_time = sum(timestamps) / len(timestamps)
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                create_time = os.stat(file_path).st_ctime
                if abs(create_time - avg_time) > 86400:
                    log_message(f"[!] File {file_path} có CreateTime khác biệt đáng ngờ!")

# Hàm quét thư mục webserver
def scan_directory(directory, api_key=None):
    check_suspicious_processes()
    check_config_files(directory)
    detect_anomalous_files(directory)
    
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    for pattern in suspicious_patterns:
                        if re.search(pattern, content):
                            log_message(f"[!] Phát hiện mã đáng ngờ trong file: {file_path}")
                            break
                    if is_obfuscated(content):
                        log_message(f"[!] File {file_path} có dấu hiệu obfuscate!")
                if api_key:
                    file_hash = calculate_hash(file_path)
                    if file_hash:
                        vt_result = check_virustotal(api_key, file_hash)
                        if vt_result:
                            log_message(f"[!] File {file} có thể độc hại! Kiểm tra trên VirusTotal.")
            except Exception as e:
                log_message(f"[-] Lỗi khi quét file {file_path}: {e}")

web_directory = r"/var/www/html/"
//đây là api virustotal  của tôi, bạn thay api của bạn vào
api_key = "3564892adbf14ccd8e84685841ea42b10c09c81cdca89efcc6568fd34fdd4a3b"
scan_directory(web_directory, api_key)
