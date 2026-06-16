"""
Attack Traffic Simulator for PacketEye Testing
Generates realistic attack patterns to test the IDS
"""

from scapy.all import *
import time
import random
import argparse

# Target configuration
TARGET_IP = "127.0.0.1"  # Localhost for testing
YOUR_IP = "192.168.1.100"  # Change to your IP

def ddos_attack(target_ip, duration=10):
    """Simulate DDoS attack - High packet rate flood"""
    print(f"[🔴 DDoS] Starting DDoS attack simulation for {duration} seconds...")
    start_time = time.time()
    count = 0
    
    while time.time() - start_time < duration:
        # High packet rate with SYN floods
        for _ in range(100):  # 100 packets per iteration
            src_port = random.randint(1024, 65535)
            packet = IP(src=YOUR_IP, dst=target_ip)/TCP(sport=src_port, dport=80, flags="S")
            send(packet, verbose=0)
            count += 1
        time.sleep(0.1)
    
    print(f"[✅ DDoS] Sent {count} packets - Flow Packets/s should be very high (5000-20000)")

def dos_hulk(target_ip, duration=10):
    """Simulate DoS Hulk - HTTP GET flood"""
    print(f"[🔴 DoS Hulk] Starting DoS Hulk attack for {duration} seconds...")
    start_time = time.time()
    count = 0
    
    while time.time() - start_time < duration:
        # Multiple SYN packets with high frequency
        for _ in range(50):
            src_port = random.randint(1024, 65535)
            packet = IP(src=YOUR_IP, dst=target_ip)/TCP(sport=src_port, dport=80, flags="S")
            send(packet, verbose=0)
            count += 1
        time.sleep(0.05)
    
    print(f"[✅ DoS Hulk] Sent {count} packets - High SYN flags, high packet rate")

def port_scan(target_ip):
    """Simulate Port Scan - Sequential port probing"""
    print(f"[🔴 PortScan] Starting port scan simulation...")
    count = 0
    
    # Scan common ports
    for port in range(1, 1024):
        packet = IP(src=YOUR_IP, dst=target_ip)/TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
        send(packet, verbose=0)
        count += 1
        if count % 100 == 0:
            time.sleep(0.1)
    
    print(f"[✅ PortScan] Scanned {count} ports - Low destination ports, many SYN flags")

def dos_slowloris(target_ip, duration=10):
    """Simulate Slowloris - Slow HTTP connections"""
    print(f"[🔴 DoS Slowloris] Starting Slowloris attack for {duration} seconds...")
    start_time = time.time()
    count = 0
    
    while time.time() - start_time < duration:
        # Slow, persistent connections
        src_port = random.randint(1024, 65535)
        packet = IP(src=YOUR_IP, dst=target_ip)/TCP(sport=src_port, dport=80, flags="S")
        send(packet, verbose=0)
        count += 1
        time.sleep(0.5)  # Slow rate
    
    print(f"[✅ Slowloris] Sent {count} packets - Very long flow duration")

def ftp_brute_force(target_ip, duration=10):
    """Simulate FTP Brute Force"""
    print(f"[🔴 FTP-Patator] Starting FTP brute force for {duration} seconds...")
    start_time = time.time()
    count = 0
    
    while time.time() - start_time < duration:
        src_port = random.randint(1024, 65535)
        packet = IP(src=YOUR_IP, dst=target_ip)/TCP(sport=src_port, dport=21, flags="PA")
        send(packet, verbose=0)
        count += 1
        time.sleep(0.1)
    
    print(f"[✅ FTP-Patator] Sent {count} packets to port 21")

def ssh_brute_force(target_ip, duration=10):
    """Simulate SSH Brute Force"""
    print(f"[🔴 SSH-Patator] Starting SSH brute force for {duration} seconds...")
    start_time = time.time()
    count = 0
    
    while time.time() - start_time < duration:
        src_port = random.randint(1024, 65535)
        packet = IP(src=YOUR_IP, dst=target_ip)/TCP(sport=src_port, dport=22, flags="PA")
        send(packet, verbose=0)
        count += 1
        time.sleep(0.1)
    
    print(f"[✅ SSH-Patator] Sent {count} packets to port 22")

def web_attack(target_ip, duration=10):
    """Simulate Web Attack - HTTP requests to web server"""
    print(f"[🔴 Web Attack] Starting web attack for {duration} seconds...")
    start_time = time.time()
    count = 0
    
    while time.time() - start_time < duration:
        # HTTP packets on port 80/443
        for port in [80, 443, 8080]:
            src_port = random.randint(1024, 65535)
            packet = IP(src=YOUR_IP, dst=target_ip)/TCP(sport=src_port, dport=port, flags="PA")
            send(packet, verbose=0)
            count += 1
        time.sleep(0.2)
    
    print(f"[✅ Web Attack] Sent {count} packets to web ports")

def bot_traffic(target_ip, duration=10):
    """Simulate Bot traffic - C&C communication"""
    print(f"[🔴 Bot] Starting bot traffic simulation for {duration} seconds...")
    start_time = time.time()
    count = 0
    
    while time.time() - start_time < duration:
        # Long-duration flows with periodic communication
        src_port = random.randint(1024, 65535)
        packet = IP(src=YOUR_IP, dst=target_ip)/TCP(sport=src_port, dport=random.randint(8000, 9000), flags="PA")
        send(packet, verbose=0)
        count += 1
        time.sleep(2)  # Long duration between packets
    
    print(f"[✅ Bot] Sent {count} packets - Long flow duration")

def benign_traffic(target_ip, duration=10):
    """Generate normal benign traffic"""
    print(f"[🟢 Benign] Generating normal traffic for {duration} seconds...")
    start_time = time.time()
    count = 0
    
    while time.time() - start_time < duration:
        # Normal web browsing
        src_port = random.randint(1024, 65535)
        packet = IP(src=YOUR_IP, dst=target_ip)/TCP(sport=src_port, dport=random.choice([80, 443]), flags="PA")
        send(packet, verbose=0)
        count += 1
        time.sleep(random.uniform(0.5, 2.0))
    
    print(f"[✅ Benign] Sent {count} normal packets")

def run_all_attacks(target_ip):
    """Run all attack simulations sequentially"""
    print("\n" + "="*70)
    print("🚀 STARTING COMPREHENSIVE ATTACK SIMULATION")
    print("="*70 + "\n")
    
    attacks = [
        ("Benign Traffic", lambda: benign_traffic(target_ip, 10)),
        ("DDoS Attack", lambda: ddos_attack(target_ip, 10)),
        ("DoS Hulk", lambda: dos_hulk(target_ip, 10)),
        ("Port Scan", lambda: port_scan(target_ip)),
        ("DoS Slowloris", lambda: dos_slowloris(target_ip, 10)),
        ("FTP Brute Force", lambda: ftp_brute_force(target_ip, 10)),
        ("SSH Brute Force", lambda: ssh_brute_force(target_ip, 10)),
        ("Web Attack", lambda: web_attack(target_ip, 10)),
        ("Bot Traffic", lambda: bot_traffic(target_ip, 10)),
    ]
    
    for i, (name, attack_func) in enumerate(attacks, 1):
        print(f"\n[{i}/{len(attacks)}] {name}")
        print("-" * 70)
        attack_func()
        print(f"✅ {name} completed. Waiting 5 seconds before next attack...\n")
        time.sleep(5)
    
    print("\n" + "="*70)
    print("✅ ALL ATTACKS COMPLETED!")
    print("="*70)
    print("\nCheck your PacketEye dashboard at http://localhost:3000")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PacketEye Attack Simulator")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address")
    parser.add_argument("--attack", choices=[
        "all", "ddos", "dos-hulk", "portscan", "slowloris", 
        "ftp-brute", "ssh-brute", "web", "bot", "benign"
    ], default="all", help="Attack type to simulate")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds")
    
    args = parser.parse_args()
    
    print("\n⚠️  WARNING: This will generate network traffic. Use responsibly!")
    print(f"Target: {args.target}")
    print(f"Attack: {args.attack}")
    print(f"Duration: {args.duration}s\n")
    
    if args.attack == "all":
        run_all_attacks(args.target)
    elif args.attack == "ddos":
        ddos_attack(args.target, args.duration)
    elif args.attack == "dos-hulk":
        dos_hulk(args.target, args.duration)
    elif args.attack == "portscan":
        port_scan(args.target)
    elif args.attack == "slowloris":
        dos_slowloris(args.target, args.duration)
    elif args.attack == "ftp-brute":
        ftp_brute_force(args.target, args.duration)
    elif args.attack == "ssh-brute":
        ssh_brute_force(args.target, args.duration)
    elif args.attack == "web":
        web_attack(args.target, args.duration)
    elif args.attack == "bot":
        bot_traffic(args.target, args.duration)
    elif args.attack == "benign":
        benign_traffic(args.target, args.duration)
