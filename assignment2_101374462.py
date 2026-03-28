"""
Author: <Mehmet Emin Onem>
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os 
import platform
import datetime

print(f"Python Version: {platform.python_version()}")
print(f"Operating System: {os.name}")



# Add a 1-line comment above it explaining what it stores
#Stores well known port numbers, mapped to their common service names 

common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
}



class NetworkTool:
    def __init__(self, target):
        self.target = target

#Q3: What is the benefit of using @property and @target.setter?
#Using @property and @target.setter protects the internal __target attribute 
#by controlling how it is accessed and modified from outside the class.
#The setter acts as a gatekeeper, allowing us to add validation
#logic; such as rejecting empty strings, before storing the value.

    @property
    def target(self):
        return self.__target



    @target.setter
    def target(self, value):
        if value == "":
            print("Error: Target cannot be empty")
            return
        self.__target = value

    def __del__(self):
        print("NetworkTool instnace destroyed. ")



# Q1: How does PortScanner reuse code from NetworkTool?

#PortScanner inherits from NetworkTool, so it reuses the target property
#and its validation logic without writing them again. It also calls super().init(target)
#to let the parent class handle target storage directly.


class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed. ")
        super().__del__()

    def scan_port(self, port):

#Q4: What would happen without try-except here?

#Without try-except, a failed connection on any port would raise an unhandled
#exception and stop the entire program. Since scan_port runs across multiple 
#threads, one error would crash everything and the remaining ports would never be scanned.

        try:
            s =socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((self.target, port))


            if result ==0:
                status = "Open"
            else: 
                status = "Closed"

            service_name = common_ports.get(port, "Unknown")

            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()

        except socket.error as e:
            print(f"Socket error on port {port}: {e}")
        finally:
            s.close()


    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]
    

#Q2: Why do we use threading instead of scanning one port at a time?
#Each port scan has to wait for a timeout, so doing them one by one would take forever.
#With threading, we scan multiple ports at the same time and finish much faster.
    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)

        for t in threads:
            t.start()

        for t in threads:
            t.join()


def save_results(target, results):
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("""
                       CREATE TABLE IF NOT EXISTS scans (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       target TEXT,
                       port INTEGER,
                       status TEXT,
                       service TEXT,
                       scan_date TEXT
                       )
                       """)
        for port, status, service in results:
            cursor.execute("""
                           INSERT INTO scans (target, port, status, service, scan_date)
                           VALUES (?, ?, ?, ?, ?)
                           """, (target, port, status, service, str(datetime.datetime.now())))

        conn.commit()
        conn.close()
        print("Results saved to scan_history.db")

    except sqlite3.Error as e:
        print(f"Database error: {e}")


def load_past_scans():
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()

        if not rows:
            print("No past scans found.")
        else:
            print("\n --- Past Scan History ---")
            for row in rows:
                print(f"[{row[5]}] {row[1]} : Port {row[2]} ({row[4]}) - {row[3]}")
        conn.close()

    except sqlite3.OperationalError:
        print("No past scans found.")


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":
    try:
        target_input = input("Enter target IP (press Enter for 127.0.0.1): ").strip()
        target = target_input if target_input else "127.0.0.1"
 
        start_port = int(input("Enter start port (1-1024): ").strip())
        end_port = int(input("Enter end port (1-1024): ").strip())
 
        if not (1 <= start_port <= 1024) or not (1 <= end_port <= 1024):
            print("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("End port must be greater than or equal to start port.")
        else:
            scanner = PortScanner(target)
            print(f"Scanning {target} from port {start_port} to {end_port}...")
 
            scanner.scan_range(start_port, end_port)
 
            open_ports = scanner.get_open_ports()
            for port, status, service in open_ports:
                print(f"Port {port}: {status} ({service})")
            print(f"Total open ports found: {len(open_ports)}")
 
            save_results(target, open_ports)
 
            history_input = input("Would you like to see past scan history? (yes/no): ").strip().lower()
            if history_input == "yes":
                load_past_scans()
 
    except ValueError:
        print("Invalid input. Please enter a valid integer.")


# Q5: New Feature Proposal
# TODO: Your 2-3 sentence description here... (Part 2, Q5)
#I would add a Quick Scan mode where the user can choose
#to scan only the most common ports instead of a full range.
#It uses a list comprehension to filter ports from the
#common_ports dictionary, making the scan much faster.

# Diagram: See diagram_101374462.png in the repository root
