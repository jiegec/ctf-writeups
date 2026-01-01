# Day 17 Won’t You Guide My Drone Tonight?

Reverse engineer the protocol by AI:

## Protocol Analysis

- Server: ctf.csd.lol:6969
- Protocol uses "KMPS" magic header (0x53504d4b)
- Message types: 1=handshake, 2=get state, 3=make move, 4=get flag/status

## Game Mechanics

- Current node: 32-bit integer `C`
- Target node: `T` (from type 4 response: "Reach 0x... to get the flag")
- Neighbors/move vectors: list of 32-bit integers `[m1, m2, ..., mn]`
- Move operation: from node `u`, move vector `m` takes you to node `u ^ m`
- To move: send `(m, u ^ m)` in type 3 message
- Server validates: `m` must be in neighbor list, and second value must equal `u ^ m`
- Error message: "Not a neighbor of the current node" if validation fails

## Problem Interpretation
Graph navigation problem:

- Nodes are 32-bit integers
- From node `u`, can move to `u ^ m` for each `m` in neighbor list of `u`
- Need to find path from start `C` to target `T`
- Only see neighbors of current node
- Limited time per connection ("short amount of time before kicked off")

## Challenges

1. Graph structure unknown
2. Move vectors change with position (different nodes have different allowed moves)
3. Server appears to rate-limit connections
4. Need to solve quickly within time limit

## Key Insights
- Move vectors are XOR differences, not destination nodes
- Server maintains some state (likely per IP/session)
- Target is fixed location, changes displayed based on current position

## Recommended Attack Strategy
1. Implement graph exploration with reconnection
2. Cache visited nodes and moves
3. Use BFS to find path to target
4. Execute path quickly within time limit
5. Handle server rate-limiting with delays

## Unresolved Questions
1. Does server reset state on new connection?
2. Is graph consistent or random?
3. Time limit duration?
4. Can multiple type3 messages be sent in one connection?

## Code Structure Needed
- Graph explorer with BFS
- State persistence across connections
- Rate limit handling
- Fast path execution

According to the analysis, use random walk that skips already walked notes until we reach the target:

```python
#!/usr/bin/env python3
import socket
import struct
import re
import time
from collections import deque


class GraphExplorer:
    def __init__(self):
        self.sock = None
        self.current = None
        self.target = None

    def connect(self):
        if self.sock:
            self.sock.close()
        self.sock = socket.socket()
        self.sock.settimeout(3)
        self.sock.connect(("ctf.csd.lol", 6969))

    def send_msg(self, msg_type, data=b""):
        print("Send", msg_type, data)
        length = 8 + len(data)
        header = struct.pack("<IBBH", 0x53504D4B, 1, msg_type, length)
        self.sock.sendall(header + data)

    def recv_exact(self, n):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        print("Recv", data)
        return data

    def get_state(self):
        """Get current node and neighbors"""
        # Type 2
        self.send_msg(2)
        resp = self.recv_exact(16)

        C = struct.unpack("<I", resp[8:12])[0]
        n = struct.unpack("<I", resp[12:16])[0]

        neighbors = []
        if n > 0:
            data = self.recv_exact(4 * n)
            for i in range(0, 4 * n, 4):
                val = struct.unpack("<I", data[i : i + 4])[0]
                neighbors.append(val)

        self.current = C
        return C, neighbors

    def get_target(self):
        """Get target node"""
        # Type 4
        self.send_msg(4)
        resp = self.recv_exact(72)
        msg_text = resp[8:].decode("ascii", errors="ignore").rstrip("\x00")
        match = re.search(r"0x([0-9a-f]+)", msg_text, re.IGNORECASE)
        if match:
            T = int(match.group(1), 16)
            self.target = T
            return T
        return None

    def move_to(self, neighbor):
        """Move to neighbor node"""
        if not self.sock:
            return False

        v23 = neighbor
        v24 = self.current ^ neighbor

        data = struct.pack("<II", v23, v24)
        self.send_msg(3, data)

        try:
            resp = self.recv_exact(12)
            # Check if move succeeded
            # Response should be 12 bytes: header + echoed v23
            echoed = struct.unpack("<I", resp[8:12])[0]
            if echoed == v23:
                self.current = v24  # Update current
                return True
            else:
                print(f"Unexpected response: {resp.hex()}")
                return False
        except:
            print("Move failed or connection closed")
            return False

    def simple_solve(self):
        """Try to solve by exploring"""
        self.connect()

        self.send_msg(1)
        self.recv_exact(16)

        C, neighbors = self.get_state()
        T = self.get_target()

        history = []
        while True:
            history.append(C)
            print(f"Start: 0x{C:08x}, Target: 0x{T:08x}")
            print(f"Neighbors ({len(neighbors)}): {[hex(n) for n in neighbors]}")

            # Check if target is direct neighbor
            if T in neighbors:
                print(f"Target is direct neighbor!")
                if self.move_to(T):
                    print(f"Moved to target!")
                    # Get flag
                    self.send_msg(4)
                    resp = self.recv_exact(72)
                    flag_msg = resp[8:].decode("ascii", errors="ignore").rstrip("\x00")
                    print(f"Flag: {flag_msg}")
                    if flag_msg.startswith("csd{"):
                        return flag_msg
                return None

            # Find a new neighbor
            while neighbors[-1] in history:
                neighbors.pop()
            n = neighbors[-1]
            print(f"\nTrying neighbor: 0x{n:08x}")
            if self.move_to(n):
                C, neighbors = self.get_state()
                continue

        return None


def main():
    explorer = GraphExplorer()

    try:
        flag = explorer.simple_solve()
        if flag:
            print(f"\nSUCCESS! Flag: {flag}")
            return flag
    except Exception as e:
        print(f"Error: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
```
