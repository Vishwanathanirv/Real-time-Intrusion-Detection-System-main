"""
Direct Attack Data Injector for PacketEye
Bypasses network capture and directly inserts attack patterns into database
Works WITHOUT Npcap!
"""

import mysql.connector
import datetime
import random
import time
import os
from dotenv import load_dotenv

# Load environment
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "packeteye")
    )

def inject_benign_traffic(count=20):
    """Inject normal benign traffic"""
    print(f"[🟢 Benign] Injecting {count} benign packets...")
    conn = get_db_connection()
    cursor = conn.cursor()
    
    for i in range(count):
        timestamp = datetime.datetime.now()
        src_ip = f"192.168.1.{random.randint(10, 200)}"
        dest_ip = "192.168.1.1"
        protocol = "TCP"
        length = random.randint(500, 1500)
        flags = random.randint(16, 24)  # Normal ACK/PSH flags
        
        cursor.execute("""
            INSERT INTO packets 
            (timestamp, src_ip, dest_ip, protocol, length, flags, status, reason, attack_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (timestamp, src_ip, dest_ip, protocol, length, flags, 
              "Normal", "Normal traffic", "BENIGN"))
        
        if (i + 1) % 5 == 0:
            print(f"  ✓ Injected {i + 1}/{count} benign packets")
    
    conn.commit()
    conn.close()
    print(f"[✅ Benign] Completed - {count} benign packets injected\n")

def inject_ddos_attack(count=50):
    """Inject DDoS attack pattern"""
    print(f"[🔴 DDoS] Injecting {count} DDoS attack packets...")
    conn = get_db_connection()
    cursor = conn.cursor()
    
    for i in range(count):
        timestamp = datetime.datetime.now()
        src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        dest_ip = "192.168.1.100"
        protocol = "TCP"
        length = random.randint(40, 100)
        flags = 2  # SYN flag
        
        cursor.execute("""
            INSERT INTO packets 
            (timestamp, src_ip, dest_ip, protocol, length, flags, status, reason, attack_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (timestamp, src_ip, dest_ip, protocol, length, flags,
              "Anomaly", "Classified as DDoS", "DDoS"))
        
        if (i + 1) % 10 == 0:
            print(f"  ✓ Injected {i + 1}/{count} DDoS packets")
        time.sleep(0.01)
    
    conn.commit()
    conn.close()
    print(f"[✅ DDoS] Completed - {count} DDoS attack packets injected\n")

def inject_port_scan(count=100):
    """Inject port scan pattern"""
    print(f"[🔴 PortScan] Injecting {count} port scan packets...")
    conn = get_db_connection()
    cursor = conn.cursor()
    
    src_ip = f"192.168.1.{random.randint(10, 200)}"
    
    for i in range(count):
        timestamp = datetime.datetime.now()
        dest_port = i + 1  # Sequential ports
        dest_ip = "192.168.1.100"
        protocol = "TCP"
        length = 60
        flags = 2  # SYN flag
        
        cursor.execute("""
            INSERT INTO packets 
            (timestamp, src_ip, dest_ip, protocol, length, flags, status, reason, attack_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (timestamp, src_ip, dest_ip, protocol, length, flags,
              "Anomaly", "Classified as PortScan", "PortScan"))
        
        if (i + 1) % 20 == 0:
            print(f"  ✓ Injected {i + 1}/{count} port scan packets")
        time.sleep(0.005)
    
    conn.commit()
    conn.close()
    print(f"[✅ PortScan] Completed - {count} port scan packets injected\n")

def inject_dos_hulk(count=40):
    """Inject DoS Hulk attack"""
    print(f"[🔴 DoS Hulk] Injecting {count} DoS Hulk packets...")
    conn = get_db_connection()
    cursor = conn.cursor()
    
    for i in range(count):
        timestamp = datetime.datetime.now()
        src_ip = f"192.168.1.{random.randint(10, 200)}"
        dest_ip = "192.168.1.100"
        protocol = "TCP"
        length = random.randint(100, 500)
        flags = 2  # SYN
        
        cursor.execute("""
            INSERT INTO packets 
            (timestamp, src_ip, dest_ip, protocol, length, flags, status, reason, attack_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (timestamp, src_ip, dest_ip, protocol, length, flags,
              "Anomaly", "Classified as DoS Hulk", "DoS Hulk"))
        
        if (i + 1) % 10 == 0:
            print(f"  ✓ Injected {i + 1}/{count} DoS Hulk packets")
        time.sleep(0.01)
    
    conn.commit()
    conn.close()
    print(f"[✅ DoS Hulk] Completed - {count} DoS Hulk packets injected\n")

def inject_ssh_brute_force(count=30):
    """Inject SSH brute force attack"""
    print(f"[🔴 SSH-Patator] Injecting {count} SSH brute force packets...")
    conn = get_db_connection()
    cursor = conn.cursor()
    
    src_ip = f"192.168.1.{random.randint(10, 200)}"
    
    for i in range(count):
        timestamp = datetime.datetime.now()
        dest_ip = "192.168.1.100"
        protocol = "TCP"
        length = random.randint(100, 300)
        flags = 24  # PSH+ACK
        
        cursor.execute("""
            INSERT INTO packets 
            (timestamp, src_ip, dest_ip, protocol, length, flags, status, reason, attack_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (timestamp, src_ip, dest_ip, protocol, length, flags,
              "Anomaly", "Classified as SSH-Patator", "SSH-Patator"))
        
        if (i + 1) % 10 == 0:
            print(f"  ✓ Injected {i + 1}/{count} SSH brute force packets")
        time.sleep(0.05)
    
    conn.commit()
    conn.close()
    print(f"[✅ SSH-Patator] Completed - {count} SSH brute force packets injected\n")

def inject_web_attack(count=25):
    """Inject web attack"""
    print(f"[🔴 Web Attack] Injecting {count} web attack packets...")
    conn = get_db_connection()
    cursor = conn.cursor()
    
    for i in range(count):
        timestamp = datetime.datetime.now()
        src_ip = f"192.168.1.{random.randint(10, 200)}"
        dest_ip = "192.168.1.100"
        protocol = "TCP"
        length = random.randint(200, 800)
        flags = 24  # PSH+ACK
        
        cursor.execute("""
            INSERT INTO packets 
            (timestamp, src_ip, dest_ip, protocol, length, flags, status, reason, attack_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (timestamp, src_ip, dest_ip, protocol, length, flags,
              "Anomaly", "Classified as Web Attack", "Web Attack"))
        
        if (i + 1) % 10 == 0:
            print(f"  ✓ Injected {i + 1}/{count} web attack packets")
        time.sleep(0.05)
    
    conn.commit()
    conn.close()
    print(f"[✅ Web Attack] Completed - {count} web attack packets injected\n")

def inject_bot_traffic(count=15):
    """Inject bot traffic"""
    print(f"[🔴 Bot] Injecting {count} bot traffic packets...")
    conn = get_db_connection()
    cursor = conn.cursor()
    
    src_ip = f"192.168.1.{random.randint(10, 200)}"
    
    for i in range(count):
        timestamp = datetime.datetime.now()
        dest_ip = "192.168.1.100"
        protocol = "TCP"
        length = random.randint(150, 400)
        flags = 24  # PSH+ACK
        
        cursor.execute("""
            INSERT INTO packets 
            (timestamp, src_ip, dest_ip, protocol, length, flags, status, reason, attack_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (timestamp, src_ip, dest_ip, protocol, length, flags,
              "Anomaly", "Classified as Bot", "Bot"))
        
        if (i + 1) % 5 == 0:
            print(f"  ✓ Injected {i + 1}/{count} bot packets")
        time.sleep(0.1)
    
    conn.commit()
    conn.close()
    print(f"[✅ Bot] Completed - {count} bot traffic packets injected\n")

def run_full_simulation():
    """Run complete attack simulation"""
    print("\n" + "="*70)
    print("🚀 STARTING COMPREHENSIVE ATTACK SIMULATION")
    print("   (Direct Database Injection - NO Npcap Required!)")
    print("="*70 + "\n")
    
    attacks = [
        ("Normal Traffic", lambda: inject_benign_traffic(20)),
        ("DDoS Attack", lambda: inject_ddos_attack(50)),
        ("Port Scan", lambda: inject_port_scan(100)),
        ("DoS Hulk", lambda: inject_dos_hulk(40)),
        ("SSH Brute Force", lambda: inject_ssh_brute_force(30)),
        ("Web Attack", lambda: inject_web_attack(25)),
        ("Bot Traffic", lambda: inject_bot_traffic(15)),
        ("More Normal Traffic", lambda: inject_benign_traffic(30)),
    ]
    
    for i, (name, attack_func) in enumerate(attacks, 1):
        print(f"[{i}/{len(attacks)}] {name}")
        print("-" * 70)
        attack_func()
        time.sleep(2)
    
    print("="*70)
    print("✅ SIMULATION COMPLETED!")
    print("="*70)
    print("\n📊 Check your dashboard at: http://localhost:3000")
    print("   Total packets injected: ~310")
    print("   Attack types: DDoS, PortScan, DoS Hulk, SSH-Patator, Web Attack, Bot")

if __name__ == "__main__":
    import sys
    
    print("\n⚠️  This will inject test data directly into the database")
    print("   No network capture required - works WITHOUT Npcap!\n")
    
    if len(sys.argv) > 1:
        attack_type = sys.argv[1]
        
        if attack_type == "benign":
            inject_benign_traffic(30)
        elif attack_type == "ddos":
            inject_ddos_attack(50)
        elif attack_type == "portscan":
            inject_port_scan(100)
        elif attack_type == "dos-hulk":
            inject_dos_hulk(40)
        elif attack_type == "ssh":
            inject_ssh_brute_force(30)
        elif attack_type == "web":
            inject_web_attack(25)
        elif attack_type == "bot":
            inject_bot_traffic(15)
        else:
            print(f"Unknown attack type: {attack_type}")
            print("Available: benign, ddos, portscan, dos-hulk, ssh, web, bot")
    else:
        run_full_simulation()
