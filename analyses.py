import os
import re
import json
import csv
import ipaddress
from collections import defaultdict, Counter
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple, Optional

import pandas as pd
import matplotlib.pyplot as plt

from scapy.all import PcapReader, conf, load_layer
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.all import TLSClientHello

load_layer("tls")
load_layer("http")
conf.verb = 0

ROOT_DIR = r"C:\Users\Administrator\Desktop\Matteo\Università\3° Anno\Reti\catture_271125_gr49"
OUTPUT_DIR = os.path.join(ROOT_DIR, "Report_Finale_Esame")
OUTPUT_GRAPHS_DIR = os.path.join(OUTPUT_DIR, "Grafici_Comparativi")

PCAP_FILENAME = "traffic.pcap"
WHOIS_FILENAME = "whois_metadata.json"

ORDER_MAPPING = {
    'xiaomi': ["Gemini", "Copilot", "Perplexity", "ChatGPT"],
    'pixel':  ["ChatGPT", "Gemini", "Copilot", "Perplexity"]
}

# cerchiamo file candidati nella cartella sessione
NETSTAT_HINTS = ["netstat", "socket", "sockets", "connections", "conn", "mirage"]

PACKAGE_RE = re.compile(r"(?P<pkg>([a-zA-Z0-9_]+\.)+[a-zA-Z0-9_]+)")
IPPORT_RE = re.compile(r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):(?P<port>\d{1,5})")

# -----------------------------
# UTILS
# -----------------------------
def safe_mkdir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def is_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except Exception:
        return False

def is_global_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except Exception:
        return False

def get_app_task(device_name: str, index: int) -> Tuple[str, str]:
    d_key = 'xiaomi' if 'xiaomi' in device_name.lower() else ('pixel' if 'pixel' in device_name.lower() else None)
    if not d_key or index > 7:
        return "Unknown", "Unknown"
    app_idx = index // 2
    app_name = ORDER_MAPPING[d_key][app_idx] if app_idx < len(ORDER_MAPPING[d_key]) else "Unknown"
    task_type = "Text" if (index % 2) == 0 else "Image"
    return app_name, task_type

def get_whois_org(ip_addr: str, whois_data: dict) -> str:
    if not whois_data:
        return "N/A"
    record = whois_data.get(ip_addr)
    if not record:
        return "Unknown"

    if 'nets' in record and isinstance(record['nets'], list) and record['nets']:
        net = record['nets'][0]
        org = net.get('description') or net.get('name') or net.get('organization')
        if org:
            return org

    return record.get('org') or record.get('organization') or record.get('asn_description') or "Unknown"

def find_netstat_like_files(session_dir: str) -> List[str]:
    out = []
    for fn in os.listdir(session_dir):
        low = fn.lower()
        if any(h in low for h in NETSTAT_HINTS) and low.endswith((".txt", ".log", ".csv")):
            out.append(os.path.join(session_dir, fn))
    return out

def parse_port_to_package(session_dir: str) -> Dict[int, str]:
    """
    - cerca un file netstat/log in session_dir
    - estrae (ip:port) e package dalla stessa riga
    - ritorna port -> package più frequente
    """
    cand = find_netstat_like_files(session_dir)
    if not cand:
        return {}

    port_counter: Dict[int, Counter] = defaultdict(Counter)

    for path in cand:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    m_pkg = PACKAGE_RE.search(line)
                    if not m_pkg:
                        continue
                    pkg = m_pkg.group("pkg")

                    # prende la prima occorrenza ip:port nella riga (euristica)
                    m_ipport = IPPORT_RE.search(line)
                    if not m_ipport:
                        continue
                    port = int(m_ipport.group("port"))
                    if 0 < port <= 65535:
                        port_counter[port][pkg] += 1
        except Exception:
            continue

    port_to_pkg = {}
    for port, c in port_counter.items():
        pkg, _ = c.most_common(1)[0]
        port_to_pkg[port] = pkg
    return port_to_pkg

Endpoint = Tuple[str, int]  # (ip, port)

def canonical_eps(src: Endpoint, dst: Endpoint) -> Tuple[Endpoint, Endpoint]:
    #Per matteo2: la direzione si calcola confrontando src/dst con (A,B)
    return (src, dst) if src <= dst else (dst, src)

@dataclass
class Conversation:
    a_ip: str
    a_port: int
    b_ip: str
    b_port: int
    proto: str

    pkts_a2b: int = 0
    bytes_a2b: int = 0
    pkts_b2a: int = 0
    bytes_b2a: int = 0

    sni: Set[str] = None
    http_host: Set[str] = None
    dns_names: Set[str] = None

    remote_ip: str = ""
    remote_org: str = ""
    app_package: str = "Unknown"

    def __post_init__(self):
        self.sni = self.sni or set()
        self.http_host = self.http_host or set()
        self.dns_names = self.dns_names or set()

    @property
    def pkts_total(self) -> int:
        return self.pkts_a2b + self.pkts_b2a

    @property
    def bytes_total(self) -> int:
        return self.bytes_a2b + self.bytes_b2a


def analyze_session(pcap_path: str, session_dir: str, whois_data: dict):
    """
    - trace_summary.txt (capinfos-like)
    - conversations_tcp.csv / conversations_udp.csv
    - dns_answers.csv / sni.csv / http_host.csv
    """

    port_to_pkg = parse_port_to_package(session_dir)

    # DNS ip -> domains
    ip_to_domains: Dict[str, Set[str]] = defaultdict(set)

   #tshark -T fields
    dns_answer_rows: List[dict] = []
    sni_rows: List[dict] = []
    http_rows: List[dict] = []

    conversations: Dict[Tuple[Endpoint, Endpoint, str], Conversation] = {}

    start_ts = None
    end_ts = None
    total_bytes = 0
    total_pkts = 0

    private_ip_counter = Counter()

    try:
        reader = PcapReader(pcap_path)
    except Exception:
        return None

    with reader:
        for pkt in reader:
            if not pkt.haslayer(IP):
                continue

            ip = pkt[IP]
            ts = float(pkt.time)

            if start_ts is None:
                start_ts = ts
            end_ts = ts

            pkt_len = len(pkt)
            total_bytes += pkt_len
            total_pkts += 1

            if is_private_ip(ip.src):
                private_ip_counter[ip.src] += 1
            if is_private_ip(ip.dst):
                private_ip_counter[ip.dst] += 1

            # ---- Estrazione DNS ----
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                try:
                    if int(dns.qr) == 1 and int(dns.ancount) > 0: 
                        qname = ""
                        if dns.qd and getattr(dns.qd, "qname", None):
                            qname = dns.qd.qname.decode("utf-8", "ignore").rstrip(".")

                        for i in range(int(dns.ancount)):
                            rr = dns.an[i]
                            if isinstance(rr, DNSRR) and hasattr(rr, "rdata"):
                                rdata = rr.rdata
                                if isinstance(rdata, str) and re.match(r"^\d{1,3}(\.\d{1,3}){3}$", rdata):
                                    ip_to_domains[rdata].add(qname) if qname else None
                                    dns_answer_rows.append({
                                        "frame.time_epoch": ts,
                                        "dns.a": rdata,
                                        "dns.qry.name": qname
                                    })
                except Exception:
                    pass

            # ---- transport ----
            if pkt.haslayer(TCP):
                proto = "TCP"
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
            elif pkt.haslayer(UDP):
                proto = "UDP"
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)
            else:
                continue

            src_ep: Endpoint = (ip.src, sport)
            dst_ep: Endpoint = (ip.dst, dport)
            a_ep, b_ep = canonical_eps(src_ep, dst_ep)

            key = (a_ep, b_ep, proto)
            if key not in conversations:
                conversations[key] = Conversation(
                    a_ip=a_ep[0], a_port=a_ep[1],
                    b_ip=b_ep[0], b_port=b_ep[1],
                    proto=proto
                )
            conv = conversations[key]

            if src_ep == a_ep and dst_ep == b_ep:
                conv.pkts_a2b += 1
                conv.bytes_a2b += pkt_len
            else:
                conv.pkts_b2a += 1
                conv.bytes_b2a += pkt_len

            # ---- SNI ---- 
            if pkt.haslayer(TLSClientHello):
                try:
                    ch = pkt[TLSClientHello]
                    if getattr(ch, "extensions", None):
                        for ext in ch.extensions:
                            if getattr(ext, "servernames", None):
                                for sn in ext.servernames:
                                    val = sn.servername
                                    if isinstance(val, bytes):
                                        val = val.decode("utf-8", "ignore")
                                    val = str(val).strip()
                                    if val:
                                        conv.sni.add(val)
                                        sni_rows.append({
                                            "frame.time_epoch": ts,
                                            "tls.handshake.extensions_server_name": val,
                                            "src_ip": ip.src, "dst_ip": ip.dst,
                                            "src_port": sport, "dst_port": dport,
                                            "proto": proto
                                        })
                except Exception:
                    pass

            # ---- HTTP Host ---- :contentReference
            if pkt.haslayer(HTTPRequest):
                try:
                    h = pkt[HTTPRequest].Host
                    if h:
                        val = h.decode("utf-8", "ignore").strip()
                        if val:
                            conv.http_host.add(val)
                            http_rows.append({
                                "frame.time_epoch": ts,
                                "http.host": val,
                                "src_ip": ip.src, "dst_ip": ip.dst,
                                "src_port": sport, "dst_port": dport,
                                "proto": proto
                            })
                except Exception:
                    pass

    duration = (end_ts - start_ts) if (start_ts is not None and end_ts is not None) else 0.0
    bitrate_bps = (total_bytes * 8 / duration) if duration > 0 else 0.0

    device_ip_guess = private_ip_counter.most_common(1)[0][0] if private_ip_counter else ""

    # ---- arricchimento conversation: remote_ip, dns_names, whois, app_package ----
    conv_list: List[Conversation] = []
    for conv in conversations.values():
        remote_ip = ""
        if is_global_ip(conv.a_ip):
            remote_ip = conv.a_ip
        elif is_global_ip(conv.b_ip):
            remote_ip = conv.b_ip
        else:
            # fallback: scegli quello diverso dal device_ip_guess
            if device_ip_guess and conv.a_ip == device_ip_guess:
                remote_ip = conv.b_ip
            elif device_ip_guess and conv.b_ip == device_ip_guess:
                remote_ip = conv.a_ip
            else:
                remote_ip = conv.b_ip

        conv.remote_ip = remote_ip
        if remote_ip in ip_to_domains:
            conv.dns_names |= ip_to_domains[remote_ip]

        conv.remote_org = get_whois_org(remote_ip, whois_data)

        # app labeling via netstat: porta locale (endpoint con device_ip_guess)
        pkg = "Unknown"
        if device_ip_guess:
            local_port = conv.a_port if conv.a_ip == device_ip_guess else (conv.b_port if conv.b_ip == device_ip_guess else None)
            if local_port and local_port in port_to_pkg:
                pkg = port_to_pkg[local_port]
        conv.app_package = pkg

        conv_list.append(conv)

    summary = {
        "pcap_path": pcap_path,
        "duration_sec": duration,
        "total_pkts": total_pkts,
        "total_bytes": total_bytes,
        "bitrate_bps": bitrate_bps,
        "device_ip_guess": device_ip_guess
    }

    return summary, conv_list, dns_answer_rows, sni_rows, http_rows


def export_session(out_dir: str, summary, conv_list, dns_rows, sni_rows, http_rows, whois_data):
    safe_mkdir(out_dir)

    # trace_summary.txt (capinfos-like) :contentReference[oaicite:14]{index=14}
    with open(os.path.join(out_dir, "trace_summary.txt"), "w", encoding="utf-8") as f:
        f.write(f"PCAP: {summary['pcap_path']}\n")
        f.write(f"Duration (s): {summary['duration_sec']:.6f}\n")
        f.write(f"Total packets: {summary['total_pkts']}\n")
        f.write(f"Total bytes: {summary['total_bytes']}\n")
        f.write(f"Avg bitrate (bps): {summary['bitrate_bps']:.3f}\n")
        f.write(f"Device IP guess: {summary['device_ip_guess']}\n")

    # conversations tcp/udp (CSV)
    conv_fields = [
        "a_ip","a_port","b_ip","b_port","proto",
        "pkts_a2b","bytes_a2b","pkts_b2a","bytes_b2a",
        "pkts_total","bytes_total",
        "remote_ip","remote_org",
        "app_package",
        "dns_names","sni","http_host"
    ]

    tcp_rows = []
    udp_rows = []

    for c in conv_list:
        row = {
            "a_ip": c.a_ip, "a_port": c.a_port,
            "b_ip": c.b_ip, "b_port": c.b_port,
            "proto": c.proto,
            "pkts_a2b": c.pkts_a2b, "bytes_a2b": c.bytes_a2b,
            "pkts_b2a": c.pkts_b2a, "bytes_b2a": c.bytes_b2a,
            "pkts_total": c.pkts_total, "bytes_total": c.bytes_total,
            "remote_ip": c.remote_ip,
            "remote_org": c.remote_org,
            "app_package": c.app_package,
            "dns_names": ";".join(sorted([x for x in c.dns_names if x])),
            "sni": ";".join(sorted([x for x in c.sni if x])),
            "http_host": ";".join(sorted([x for x in c.http_host if x]))
        }
        if c.proto == "TCP":
            tcp_rows.append(row)
        elif c.proto == "UDP":
            udp_rows.append(row)

    def write_csv(path, rows, fields):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for r in rows:
                w.writerow(r)

    write_csv(os.path.join(out_dir, "conversations_tcp.csv"), tcp_rows, conv_fields)
    write_csv(os.path.join(out_dir, "conversations_udp.csv"), udp_rows, conv_fields)

    # DNS answers / SNI / HTTP Host (CSV dedicati)
    write_csv(os.path.join(out_dir, "dns_answers.csv"), dns_rows, ["frame.time_epoch", "dns.a", "dns.qry.name"])
    write_csv(os.path.join(out_dir, "sni.csv"), sni_rows,
              ["frame.time_epoch","tls.handshake.extensions_server_name","src_ip","dst_ip","src_port","dst_port","proto"])
    write_csv(os.path.join(out_dir, "http_host.csv"), http_rows,
              ["frame.time_epoch","http.host","src_ip","dst_ip","src_port","dst_port","proto"])

    # whois summary
    with open(os.path.join(out_dir, "whois_summary.json"), "w", encoding="utf-8") as f:
        json.dump(whois_data or {}, f, ensure_ascii=False, indent=2)


def generate_minimal_graphs(df_sessions: pd.DataFrame, out_dir: str):
    safe_mkdir(out_dir)
    if df_sessions.empty:
        return

    # total MB per app/task/device
    fig, ax = plt.subplots(figsize=(12, 6))
    labels = [f"{r.Device}\n{r.App_Name}\n{r.Task_Type}" for r in df_sessions.itertuples(index=False)]
    ax.bar(range(len(df_sessions)), df_sessions["Total_MB"].values)
    ax.set_title("Traffico totale per sessione (MB)")
    ax.set_ylabel("MB")
    ax.set_xticks(range(len(df_sessions)))
    ax.set_xticklabels(labels, rotation=45, ha="right")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "1_total_MB_per_session.png"), dpi=200, bbox_inches="tight")
    plt.close(fig)

    # MB/s normalizzato
    fig, ax = plt.subplots(figsize=(12, 6))
    ax.bar(range(len(df_sessions)), df_sessions["MBps"].values)
    ax.set_title("Traffico normalizzato per durata (MB/s)")
    ax.set_ylabel("MB/s")
    ax.set_xticks(range(len(df_sessions)))
    ax.set_xticklabels(labels, rotation=45, ha="right")
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, "2_MBps_per_session.png"), dpi=200, bbox_inches="tight")
    plt.close(fig)

def main():
    safe_mkdir(OUTPUT_DIR)
    safe_mkdir(OUTPUT_GRAPHS_DIR)

    global_sessions = []

    print("[START] Analisi conforme PDF: capinfos-like, conv TCP/UDP, DNS/SNI/HTTP Host, whois. ")

    for device in os.listdir(ROOT_DIR):
        d_path = os.path.join(ROOT_DIR, device)
        if not os.path.isdir(d_path):
            continue
        if device.startswith("Report") or device.startswith("_analysis"):
            continue

        timestamps = sorted([t for t in os.listdir(d_path) if os.path.isdir(os.path.join(d_path, t))])

        for index, ts in enumerate(timestamps):
            if index >= 8:
                break

            app_name, task_type = get_app_task(device, index)

            session_dir = os.path.join(d_path, ts)
            pcap = os.path.join(session_dir, PCAP_FILENAME)
            whois = os.path.join(session_dir, WHOIS_FILENAME)

            if not os.path.exists(pcap):
                continue

            # output per sessione
            session_name = f"{device}_{app_name}_{task_type}_{ts}"
            out_dir = os.path.join(OUTPUT_DIR, "Dettagli_Sessioni", session_name)
            safe_mkdir(out_dir)

            # whois data (se presente)
            whois_data = {}
            if os.path.exists(whois):
                try:
                    with open(whois, "r", encoding="utf-8") as f:
                        whois_data = json.load(f)
                except Exception:
                    whois_data = {}

            print(f"[PCAP] {session_name}")

            result = analyze_session(pcap, session_dir, whois_data)
            if not result:
                continue

            summary, conv_list, dns_rows, sni_rows, http_rows = result

            export_session(out_dir, summary, conv_list, dns_rows, sni_rows, http_rows, whois_data)

            # riepilogo sessione
            total_mb = summary["total_bytes"] / (1024 * 1024)
            mbps = (total_mb / summary["duration_sec"]) if summary["duration_sec"] > 0 else 0.0

            # top org per byte (dalla conversation list)
            org_counter = Counter()
            pkg_counter = Counter()
            for c in conv_list:
                org_counter[c.remote_org] += c.bytes_total
                if c.app_package != "Unknown":
                    pkg_counter[c.app_package] += c.bytes_total

            top_org = org_counter.most_common(1)[0][0] if org_counter else "N/A"
            top_pkg = pkg_counter.most_common(1)[0][0] if pkg_counter else "Unknown"

            global_sessions.append({
                "Device": device,
                "App_Name": app_name,        # metadato sperimentale (ordine sessioni)
                "Task_Type": task_type,      # Text/Image (ordine sessioni)
                "Session": ts,
                "Duration_Sec": summary["duration_sec"],
                "Total_Bytes": summary["total_bytes"],
                "Total_MB": total_mb,
                "MBps": mbps,
                "Device_IP_Guess": summary["device_ip_guess"],
                "Top_Org_By_Bytes": top_org,
                "Top_App_Package_By_Bytes": top_pkg
            })

    df = pd.DataFrame(global_sessions)
    df.to_csv(os.path.join(OUTPUT_DIR, "Riepilogo_Sessioni.csv"), index=False)
    df.to_excel(os.path.join(OUTPUT_DIR, "Riepilogo_Sessioni.xlsx"), index=False)

    generate_minimal_graphs(df, OUTPUT_GRAPHS_DIR)
    print(f"\n[DONE] Output in: {OUTPUT_DIR}")

if __name__ == "__main__":
    main()
