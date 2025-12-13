# Reti_di_calcolatori
Progetto Universitario: Matteo Mazzella, Matteo D'Orazio

Linkedin Profile Matteo Mazzella: "https://www.linkedin.com/public-profile/settings?trk=d_flagship3_profile_self_view_public_profile"

Analisi traffico di rete da PCAP (Android) — Script per elaborato di Reti

Librerie: pandas,seaborn,scapy

Questo script supporta un’analisi comparativa del traffico di rete generato da due dispositivi Android (Xiaomi vs Pixel) durante l’uso di applicazioni AI (Gemini, Copilot, Perplexity, ChatGPT) su due tipologie di task:

Text (prompt/testo)

Image (prompt + contenuto immagine / richiesta con immagine)

L’obiettivo è trasformare una raccolta di file traffic.pcap in:

un riepilogo quantitativo (volume, durata, throughput),

una vista TCP/UDP,

indicatori utili per identificare destinazioni (DNS, SNI TLS, HTTP Host),

(se disponibile) arricchimento con WHOIS/ASN e una stima del package Android che ha aperto le connessioni.




Per ogni cattura che contiene traffic.pcap, lo script:

Legge il PCAP pacchetto-per-pacchetto con Scapy (PcapReader).

Calcola un riepilogo:

durata cattura (s)

numero pacchetti

byte totali

bitrate medio (bps)

stima dell’IP del dispositivo (device_ip_guess) tramite l’IP privato più frequente nel traffico

Estrae indicatori applicativi:

DNS Answers: associazione IP

TLS SNI: hostname indicato nel ClientHello

HTTP Host header: hostname richiesto in HTTP (se presente traffico non cifrato)

Costruisce le conversazioni TCP/UDP (stile Wireshark “Conversations”):

conteggio pacchetti/byte per direzione e totali

Arricchisce ogni conversazione:

remote_ip: IP remoto “pubblico” (se rilevabile)

dns_names: domini associati a quell’IP via DNS

remote_org: organizzazione/ASN da whois_metadata.json (se presente)

app_package: stima del package Android tramite parsing di file netstat/log (se presenti)

Produce un riepilogo globale di tutte le sessioni (CSV + XLSX) e grafici comparativi:

traffico totale per sessione (MB)

traffico normalizzato per durata (MB/s)



