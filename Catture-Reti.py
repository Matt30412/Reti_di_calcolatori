import os
import json
import pandas as pd
import logging
import matplotlib.pyplot as plt
import seaborn as sns
from scapy.all import *
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.all import TLS, TLSClientHello

load_layer("tls")
load_layer("http")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

ROOT_DIR = r"C:\Users\Administrator\Desktop\Matteo\Università\3° Anno\Reti\catture_271125_gr49"
OUTPUT_FILE = os.path.join(ROOT_DIR, "Report_Dati_Completo.xlsx")
OUTPUT_IMG_DIR = os.path.join(ROOT_DIR, "Grafici_Finali_Report")

# --- . ORDINE DELLE CATTURE ---
# Xiaomi: Gemini -> Copilot -> Perplexity -> ChatGPT
# Pixel:  ChatGPT -> Gemini -> Copilot -> Perplexity
# Logica: La prima cartella (indice 0) è TESTO, la seconda (indice 1) è IMMAGINE.
ORDER_MAPPING = {
    'xiaomi': ["Gemini", "Copilot", "Perplexity", "ChatGPT"],
    'pixel':  ["ChatGPT", "Gemini", "Copilot", "Perplexity"]
}

def get_app_and_task(device_name, index):
    d_key = 'xiaomi' if 'xiaomi' in device_name.lower() else ('pixel' if 'pixel' in device_name.lower() else None)
    
    if not d_key or index > 7: return "Unknown", "Unknown"
    
    # Mappa l'App (2 catture per app)
    app_idx = index // 2
    try:
        app_name = ORDER_MAPPING[d_key][app_idx]
    except IndexError: return "Extra", "Extra"
    
    # Mappa il Task (Pari = Testo, Dispari = Immagine)
    task_type = "Text" if (index % 2) == 0 else "Image"
    
    return app_name, task_type

def get_whois_org(ip_addr, whois_data):
    if not whois_data: return "N/A"
    record = whois_data.get(ip_addr)
    if not record: return "Unknown"
    
    # Logica robusta per cercare l'organizzazione
    if 'nets' in record and isinstance(record['nets'], list) and len(record['nets']) > 0:
        net = record['nets'][0]
        org = net.get('description') or net.get('name') or net.get('organization')
        if org: return org
        
    return record.get('org') or record.get('organization') or "Unknown"

def process_pcap(pcap_path, whois_path, device, timestamp, app_name, task_type):
    results = []
    
    # Carica Whois
    whois_data = {}
    if os.path.exists(whois_path):
        try:
            with open(whois_path, 'r') as f:
                whois_data = json.load(f)
        except Exception:
            pass

    try: packets = PcapReader(pcap_path)
    except: return []

    flows = {}
    start_time = None
    end_time = None

    for pkt in packets:
        if not pkt.haslayer(IP): continue
        
        # Filtra traffico broadcast inutile
        if pkt[IP].dst.endswith('.255') or pkt[IP].dst.startswith(('224.', '239.')): continue

        ts = float(pkt.time)
        if start_time is None: start_time = ts
        end_time = ts
        
        pkt_len = len(pkt)
        ip = pkt[IP]
        proto = "TCP" if ip.proto == 6 else ("UDP" if ip.proto == 17 else f"IP-{ip.proto}")
        
        src_port = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
        dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
        
        # Biflusso univoco
        key = tuple(sorted([(ip.src, src_port), (ip.dst, dst_port)])) + (proto,)
        
        if key not in flows:
            flows[key] = {'pkts': 0, 'bytes': 0, 'sni': set(), 'host': set()}
        
        flows[key]['pkts'] += 1
        flows[key]['bytes'] += pkt_len
        
        # Estrazione SNI (TLS)
        if pkt.haslayer(TLSClientHello):
            try:
                if hasattr(pkt[TLSClientHello], 'extensions'):
                    for ext in pkt[TLSClientHello].extensions:
                        if hasattr(ext, 'servernames') and ext.servernames:
                            for sn in ext.servernames:
                                val = sn.servername.decode('utf-8', 'ignore') if isinstance(sn.servername, bytes) else sn.servername
                                flows[key]['sni'].add(val)
            except: pass
        # Estrazione Host (HTTP)    
        if pkt.haslayer(HTTPRequest):
             if pkt[HTTPRequest].Host:
                 val = pkt[HTTPRequest].Host.decode('utf-8','ignore')
                 flows[key]['host'].add(val)

    duration = (end_time - start_time) if (end_time and start_time) else 0

    for key, data in flows.items():
        ip_1, port_1 = key[0]
        ip_2, port_2 = key[1]
        
        # Identifica IP remoto
        is_private = ip_1.startswith(('192.168.', '10.', '172.'))
        remote_ip = ip_2 if is_private else ip_1
        
        if remote_ip.startswith(('192.168.', '10.', '172.', '224.', '239.')): continue

        org = get_whois_org(remote_ip, whois_data)
        app_str = ", ".join([x for x in (list(data['sni']) + list(data['host'])) if x])

        results.append({
            'Device': device,
            'App_Name': app_name,
            'Task_Type': task_type,
            'Session': timestamp,
            'Duration_Sec': round(duration, 2),
            'Proto': key[2],
            'Dst_IP': remote_ip,
            'Total_Bytes': data['bytes'],
            'Remote_Org': org,
            'App_Info': app_str
        })
        
    return results

def genera_tutti_i_grafici(df: pd.DataFrame, output_folder: str):
    """

    Output:
      - confronto consumo dati (Text / Image) tra dispositivi per app
      - panoramica per device (Text vs Image per app)
      - mix protocollare per device (byte)
      - top organizzazioni per traffico (byte), separato per device
      - andamento per sessione (MB) per device (utile per trovare anomalie)
    """
    import os
    import numpy as np
    import matplotlib.pyplot as plt
    from textwrap import shorten

    if df is None or df.empty:
        print("[WARN] DataFrame vuoto: nessun grafico generato.")
        return {}

    os.makedirs(output_folder, exist_ok=True)

    # ---------- Helpers ----------
    def _save(fig, filename):
        path = os.path.join(output_folder, filename)
        fig.tight_layout()
        fig.savefig(path, dpi=200, bbox_inches="tight")
        plt.close(fig)
        return path

    def _to_mb(x):
        return x / (1024 * 1024)

    def _safe_label(s, width=28):
        # accorcia label troppo lunghe (org, app_info, ecc.)
        return shorten(str(s), width=width, placeholder="…")

    saved = {}

    # ---------- Normalizzazione colonne ----------
    required = {"Device", "App_Name", "Task_Type", "Session", "Total_Bytes", "Proto", "Remote_Org"}
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise ValueError(f"DataFrame mancante colonne richieste: {missing}")

    dfx = df.copy()
    dfx["Total_Bytes"] = pd.to_numeric(dfx["Total_Bytes"], errors="coerce").fillna(0).astype(float)
    dfx["Total_MB"] = _to_mb(dfx["Total_Bytes"])

    # Aggrego per sessione (somma bytes di tutti i biflussi della sessione)
    df_sess = (
        dfx.groupby(["Device", "App_Name", "Task_Type", "Session"], dropna=False)
           .agg(Total_Bytes=("Total_Bytes", "sum"),
                Total_MB=("Total_MB", "sum"),
                Flows=("Total_Bytes", "size"))
           .reset_index()
    )

    # Ordine coerente delle app (mantieni ordine "naturale" se possibile)
    app_order = [a for a in ["ChatGPT", "Gemini", "Copilot", "Perplexity"] if a in df_sess["App_Name"].unique()]
    if not app_order:
        app_order = sorted(df_sess["App_Name"].unique().tolist())

    device_order = sorted(df_sess["Device"].unique().tolist())
    task_order = ["Text", "Image"]

    # ---------- G1: Confronto dispositivi per task (MB, non conteggi/medie) ----------
    for task in task_order:
        sub = df_sess[df_sess["Task_Type"] == task].copy()
        if sub.empty:
            continue

        # pivot: righe=app, colonne=device, valori=MB (somma)
        pv = (sub.groupby(["App_Name", "Device"])["Total_MB"].sum()
                  .unstack("Device")
                  .reindex(index=app_order, columns=device_order)
                  .fillna(0.0))

        x = np.arange(len(pv.index))
        width = 0.8 / max(1, len(device_order))

        fig, ax = plt.subplots(figsize=(11, 6))
        for i, dev in enumerate(device_order):
            ax.bar(x + i * width, pv[dev].values, width, label=dev)

        ax.set_title(f"Consumo dati per App — Task {task} (MB totali per sessione)")
        ax.set_ylabel("Traffico totale (MB)")
        ax.set_xticks(x + (len(device_order)-1)*width/2)
        ax.set_xticklabels(pv.index, rotation=0)
        ax.legend()
        saved[f"confronto_device_{task.lower()}"] = _save(fig, f"1_Confronto_Device_{task.upper()}.png")

    # ---------- G2: Panoramica per device (Text vs Image per app) ----------
    for dev in device_order:
        sub = df_sess[df_sess["Device"] == dev].copy()
        if sub.empty:
            continue

        pv = (sub.groupby(["App_Name", "Task_Type"])["Total_MB"].sum()
                  .unstack("Task_Type")
                  .reindex(index=app_order, columns=task_order)
                  .fillna(0.0))

        x = np.arange(len(pv.index))
        width = 0.35

        fig, ax = plt.subplots(figsize=(11, 6))
        ax.bar(x - width/2, pv["Text"].values if "Text" in pv.columns else np.zeros(len(x)), width, label="Text")
        ax.bar(x + width/2, pv["Image"].values if "Image" in pv.columns else np.zeros(len(x)), width, label="Image")

        ax.set_title(f"{dev} — Consumo dati per App (Text vs Image) — MB totali")
        ax.set_ylabel("Traffico totale (MB)")
        ax.set_xticks(x)
        ax.set_xticklabels(pv.index)
        ax.legend()
        saved[f"panoramica_{dev.lower()}"] = _save(fig, f"2_Panoramica_{dev}_App.png")

    # ---------- G3: Mix protocollare per device (BYTE/MB, non count di flussi) ----------
    proto_order = sorted(dfx["Proto"].unique().tolist())
    pv_proto = (
        dfx.groupby(["Device", "Proto"])["Total_MB"].sum()
           .unstack("Proto")
           .reindex(index=device_order, columns=proto_order)
           .fillna(0.0)
    )

    fig, ax = plt.subplots(figsize=(10, 6))
    bottom = np.zeros(len(pv_proto.index))
    x = np.arange(len(pv_proto.index))

    for proto in pv_proto.columns:
        vals = pv_proto[proto].values
        ax.bar(x, vals, bottom=bottom, label=proto)
        bottom += vals

    ax.set_title("Mix protocollare per dispositivo (MB totali)")
    ax.set_ylabel("Traffico totale (MB)")
    ax.set_xticks(x)
    ax.set_xticklabels(pv_proto.index)
    ax.legend()
    saved["mix_protocolli"] = _save(fig, "3_Mix_Protocolli_MB.png")

    # ---------- G4: Top organizzazioni per traffico (MB) — confronto per device ----------
    # Top-10 globale per MB
    org_mb = (dfx.groupby("Remote_Org")["Total_MB"].sum()
                 .sort_values(ascending=False))
    top_orgs = org_mb.head(10).index.tolist()

    sub = dfx[dfx["Remote_Org"].isin(top_orgs)].copy()
    pv_org = (sub.groupby(["Remote_Org", "Device"])["Total_MB"].sum()
                 .unstack("Device")
                 .reindex(index=top_orgs, columns=device_order)
                 .fillna(0.0))

    # Label pulite
    y_labels = [_safe_label(o, 36) for o in pv_org.index]
    y = np.arange(len(pv_org.index))
    height = 0.8 / max(1, len(device_order))

    fig, ax = plt.subplots(figsize=(12, 7))
    for i, dev in enumerate(device_order):
        ax.barh(y + i * height, pv_org[dev].values, height, label=dev)

    ax.set_title("Top 10 organizzazioni contattate — per traffico (MB totali)")
    ax.set_xlabel("Traffico totale (MB)")
    ax.set_yticks(y + (len(device_order)-1)*height/2)
    ax.set_yticklabels(y_labels)
    ax.invert_yaxis()
    ax.legend()
    saved["top_org_mb"] = _save(fig, "4_Top_Organizzazioni_MB.png")

    # ---------- G5: Andamento per sessione (MB) per device ----------
    # utile per beccare sessioni “strane” o assegnazioni app/task errate
    df_timeline = (df_sess.groupby(["Device", "Session"])["Total_MB"].sum().reset_index())

    # prova a ordinare temporalmente; se fallisce, resta ordine alfabetico
    dt = pd.to_datetime(df_timeline["Session"], errors="coerce")
    df_timeline["__dt"] = dt
    for dev in device_order:
        sub = df_timeline[df_timeline["Device"] == dev].copy()
        if sub.empty:
            continue

        if sub["__dt"].notna().any():
            sub = sub.sort_values("__dt")
            x_labels = sub["Session"].astype(str).tolist()
        else:
            sub = sub.sort_values("Session")
            x_labels = sub["Session"].astype(str).tolist()

        x = np.arange(len(sub))
        fig, ax = plt.subplots(figsize=(12, 5))
        ax.plot(x, sub["Total_MB"].values, marker="o")
        ax.set_title(f"{dev} — Traffico totale per sessione (MB)")
        ax.set_ylabel("MB totali")
        ax.set_xticks(x)
        ax.set_xticklabels([_safe_label(s, 14) for s in x_labels], rotation=30, ha="right")
        saved[f"timeline_{dev.lower()}"] = _save(fig, f"5_Timeline_Sessioni_{dev}.png")

    print(f"[OK] Grafici generati in: {output_folder}")
    return saved

def main():
    all_data = []
    print("--- Inizio Analisi Completa ---")
    
    for device in os.listdir(ROOT_DIR):
        d_path = os.path.join(ROOT_DIR, device)
        if not os.path.isdir(d_path): continue
        
        # Ordina cartelle timestamp
        timestamps = sorted([t for t in os.listdir(d_path) if os.path.isdir(os.path.join(d_path, t))])
        
        for index, ts in enumerate(timestamps):
            if index >= 8: break # Analizziamo solo le prime 8
            
            app_name, task_type = get_app_and_task(device, index)
            print(f"[{device.upper()}] Sessione {index+1}: {app_name} ({task_type})")
            
            pcap = os.path.join(d_path, ts, "traffic.pcap")
            whois = os.path.join(d_path, ts, "whois_metadata.json")
            
            if os.path.exists(pcap):
                rows = process_pcap(pcap, whois, device, ts, app_name, task_type)
                all_data.extend(rows)

    if all_data:
        df = pd.DataFrame(all_data)
        df.to_excel(OUTPUT_FILE, index=False)
        genera_tutti_i_grafici(df, OUTPUT_IMG_DIR)
        print(f"\n[SUCCESSO] Report Excel: {OUTPUT_FILE}")
        print(f"[SUCCESSO] Grafici salvati in: {OUTPUT_IMG_DIR}")
    else:
        print("[ERRORE] Nessun dato trovato.")

if __name__ == "__main__":
    main()