import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('TkAgg')
from collections import Counter
import numpy as np
from collections import Counter




tls_keylog_file = './sslkeylog.log'

pcap_files = {
    "Chrome (regular)": "chrom.pcapng",
    "Chrome (YouTube)": "chromeyoutube.pcapng",
    "Chrome (SoundCloud)": "soundcloud.pcapng",
    "Firefox (regular)": "firefox.pcapng",
    "Firefox (SoundCloud)": "firefoxsoundclude.pcapng",
    "Firefox (YouTube)": "firefoxyoutube.pcapng",
    "Zoom": "ZOOM.pcapng",
    "attecttest": "attecttest.pcapng"  
}


stats = []
tls_details_per_app = {}
ip_protocols_per_app = {}
tcp_flags_per_app = {}
port_counts_per_app = {}
window_sizes_per_app = {}

for app_name, pcap_filename in pcap_files.items():
    print(f"📊 Analyzing {app_name} from {pcap_filename}...")
    
    tls_versions = Counter()
    http2_count = 0
    packet_count = 0
    total_bytes = 0
    timestamps = []
    packet_sizes = []
    ip_protocols = Counter()
    tcp_flags = Counter()
    port_counts = Counter()
    window_sizes = []
    
    custom_params = []
    if tls_keylog_file:
        custom_params = ["-o", f"tls.keylog_file:{tls_keylog_file}"]
    
    try:
        capture = pyshark.FileCapture(
            pcap_filename,
            custom_parameters=custom_params,
            keep_packets=False
        )
    except Exception as e:
        print(f"⚠️ Error opening file {pcap_filename}: {e}")
        continue
    
    for packet in capture:
        try:
            ts = float(packet.sniff_timestamp)
            length = int(packet.length)
            packet_count += 1
            total_bytes += length
            timestamps.append(ts)
            packet_sizes.append(length)
            
            # IP Header Analysis
            if 'ip' in packet:
                ip_protocols[packet.ip.proto] += 1
            
            # TCP Header Analysis
            if 'tcp' in packet:
                port_counts[packet.tcp.dstport] += 1
                window_sizes.append(int(packet.tcp.window_size_value))
                
                # Check TCP flags
                flags = int(packet.tcp.flags, 16)
                if flags & 0x02:
                    tcp_flags['SYN'] += 1
                if flags & 0x10:
                    tcp_flags['ACK'] += 1
                if flags & 0x01:
                    tcp_flags['FIN'] += 1
                if flags & 0x04:
                    tcp_flags['RST'] += 1
                if flags & 0x08:
                    tcp_flags['PSH'] += 1
                if flags & 0x20:
                    tcp_flags['URG'] += 1
                
            # TLS Analysis
            if 'tls' in packet and hasattr(packet.tls, 'record_version'):
                tls_versions[packet.tls.record_version] += 1
            
            if 'tls' in packet and hasattr(packet.tls, 'handshake_extensions_alpn'):
                alpn = packet.tls.handshake_extensions_alpn.lower()
                if "h2" in alpn:
                    http2_count += 1

            if packet.highest_layer == "HTTP2":
                http2_count += 1
        
        except Exception:
            continue
    
    capture.close()
    
    avg_inter_arrival = sum([t2 - t1 for t1, t2 in zip(timestamps[:-1], timestamps[1:])]) / len(timestamps) if len(timestamps) > 1 else 0.0
    avg_packet_size = sum(packet_sizes) / packet_count if packet_count > 0 else 0.0
    
    stats.append({
        "App": app_name,
        "AvgPacketSize": avg_packet_size,
        "AvgInterArrival": avg_inter_arrival,
        "FlowSize": packet_count,
        "FlowVolume": total_bytes,
        "HTTP2_Count": http2_count,
        "IP_Protocols": str(dict(ip_protocols)),
        "TCP_Flags": str(dict(tcp_flags))
    })
    
    tls_details_per_app[app_name] = {
        "tls_versions": dict(tls_versions),
        "http2_count": http2_count
    }
    ip_protocols_per_app[app_name] = ip_protocols
    tcp_flags_per_app[app_name] = tcp_flags
    port_counts_per_app[app_name] = port_counts
    window_sizes_per_app[app_name] = window_sizes

# Convert stats to DataFrame
df = pd.DataFrame(stats)
print("\n=== 🟢 Generated Data Table ===")
print(df.to_string(index=False))

def plot_comparison(data, x, y, title, ylabel, color):
    plt.figure(figsize=(12,6))
    plt.bar(data[x], data[y], color=color)
    plt.title(title)
    plt.xlabel("Application")
    plt.ylabel(ylabel)
    plt.xticks(rotation=45, ha='right')
    plt.show()

plot_comparison(df, "App", "AvgPacketSize", "Average Packet Size per Application", "Average Packet Size (bytes)", "skyblue")
plot_comparison(df, "App", "AvgInterArrival", "Average Inter-Arrival Time per Application", "Average Inter-Arrival Time (seconds)", "orange")
plot_comparison(df, "App", "FlowSize", "Number of Packets (Flow Size) per Application", "Number of Packets", "green")
plot_comparison(df, "App", "FlowVolume", "Traffic Volume (Flow Volume) per Application", "Volume (bytes)", "red")
plot_comparison(df, "App", "HTTP2_Count", "HTTP/2 Count per Application", "HTTP/2 Count", "magenta")

# IP Protocols Comparison
ip_protocols_df = pd.DataFrame(ip_protocols_per_app).fillna(0)
ip_protocols_df.plot(kind='bar', figsize=(12,6))
plt.title("IP Protocol Usage per Application")
plt.xlabel("Application")
plt.ylabel("Count")
plt.xticks(rotation=45, ha='right')
plt.show()

# TCP Flags Comparison
tcp_flags_df = pd.DataFrame(tcp_flags_per_app).fillna(0)
tcp_flags_df.plot(kind='bar', figsize=(12,6))
plt.title("TCP Flags Distribution per Application")
plt.xlabel("TCP Flags")
plt.ylabel("Count")
plt.xticks(rotation=45, ha='right')
plt.show()


chrome_youtube_packet_sum = df[df['App'] == 'Chrome (YouTube)']['AvgPacketSize'].sum()
zoom_packet_sum = df[df['App'] == 'Zoom']['AvgPacketSize'].sum()

if chrome_youtube_packet_sum > zoom_packet_sum:
    print(f"\nAvgPacketSize: 'Chrome (YouTube)' ({chrome_youtube_packet_sum:.4f}) is greater than 'Zoom' ({zoom_packet_sum:.4f}).")
elif zoom_packet_sum > chrome_youtube_packet_sum:
    print(f"\nAvgPacketSize: 'Zoom' ({zoom_packet_sum:.4f}) is greater than 'Chrome (YouTube)' ({chrome_youtube_packet_sum:.4f}).")
else:
    print(f"\nAvgPacketSize: 'Chrome (YouTube)' and 'Zoom' are equal ({chrome_youtube_packet_sum:.4f}).")


chrome_youtube_interarrival_sum = df[df['App'] == 'Chrome (YouTube)']['AvgInterArrival'].sum()
zoom_interarrival_sum = df[df['App'] == 'Zoom']['AvgInterArrival'].sum()

if chrome_youtube_interarrival_sum > zoom_interarrival_sum:
    print(f"\nAvgInterArrival: 'Chrome (YouTube)' ({chrome_youtube_interarrival_sum:.4f}) is greater than 'Zoom' ({zoom_interarrival_sum:.4f}).")
elif zoom_interarrival_sum > chrome_youtube_interarrival_sum:
    print(f"\nAvgInterArrival: 'Zoom' ({zoom_interarrival_sum:.4f}) is greater than 'Chrome (YouTube)' ({chrome_youtube_interarrival_sum:.4f}).")
else:
    print(f"\nAvgInterArrival: 'Chrome (YouTube)' and 'Zoom' are equal ({chrome_youtube_interarrival_sum:.4f}).")


chrome_youtube_packet_sum = df[df['App'] == 'Chrome (YouTube)']['AvgPacketSize'].sum()
chrome_soundcloud_packet_sum = df[df['App'] == 'Chrome (SoundCloud)']['AvgPacketSize'].sum()

if chrome_youtube_packet_sum > chrome_soundcloud_packet_sum:
    print(f"\nAvgPacketSize: 'Chrome (YouTube)' ({chrome_youtube_packet_sum:.4f}) is greater than 'Chrome (SoundCloud)' ({chrome_soundcloud_packet_sum:.4f}).")
elif chrome_soundcloud_packet_sum > chrome_youtube_packet_sum:
    print(f"\nAvgPacketSize: 'Chrome (SoundCloud)' ({chrome_soundcloud_packet_sum:.4f}) is greater than 'Chrome (YouTube)' ({chrome_youtube_packet_sum:.4f}).")
else:
    print(f"\nAvgPacketSize: 'Chrome (YouTube)' and 'Chrome (SoundCloud)' are equal ({chrome_youtube_packet_sum:.4f}).")


chrome_youtube_interarrival_sum = df[df['App'] == 'Chrome (YouTube)']['AvgInterArrival'].sum()
chrome_soundcloud_interarrival_sum = df[df['App'] == 'Chrome (SoundCloud)']['AvgInterArrival'].sum()

if chrome_youtube_interarrival_sum > chrome_soundcloud_interarrival_sum:
    print(f"\nAvgInterArrival: 'Chrome (YouTube)' ({chrome_youtube_interarrival_sum:.4f}) is greater than 'Chrome (SoundCloud)' ({chrome_soundcloud_interarrival_sum:.4f}).")
elif chrome_soundcloud_interarrival_sum > chrome_youtube_interarrival_sum:
    print(f"\nAvgInterArrival: 'Chrome (SoundCloud)' ({chrome_soundcloud_interarrival_sum:.4f}) is greater than 'Chrome (YouTube)' ({chrome_youtube_interarrival_sum:.4f}).")
else:
    print(f"\nAvgInterArrival: 'Chrome (YouTube)' and 'Chrome (SoundCloud)' are equal ({chrome_youtube_interarrival_sum:.4f}).")




chrome_subset = df[df['App'].str.contains('Chrome')]
firefox_subset = df[df['App'].str.contains('Firefox')]


chrome_avg_packet = chrome_subset['AvgPacketSize'].mean()
firefox_avg_packet = firefox_subset['AvgPacketSize'].mean()

chrome_avg_interarrival = chrome_subset['AvgInterArrival'].mean()
firefox_avg_interarrival = firefox_subset['AvgInterArrival'].mean()

if chrome_avg_packet > firefox_avg_packet:
    print(f"\nAvgPacketSize (Average): Chrome's average ({chrome_avg_packet:.4f}) is greater than Firefox's ({firefox_avg_packet:.4f}).")
elif firefox_avg_packet > chrome_avg_packet:
    print(f"\nAvgPacketSize (Average): Firefox's average ({firefox_avg_packet:.4f}) is greater than Chrome's ({chrome_avg_packet:.4f}).")
else:
    print(f"\nAvgPacketSize (Average): Chrome and Firefox have equal average values ({chrome_avg_packet:.4f}).")

if chrome_avg_interarrival > firefox_avg_interarrival:
    print(f"\nAvgInterArrival (Average): Chrome's average ({chrome_avg_interarrival:.4f}) is greater than Firefox's ({firefox_avg_interarrival:.4f}).")
elif firefox_avg_interarrival > chrome_avg_interarrival:
    print(f"\nAvgInterArrival (Average): Firefox's average ({firefox_avg_interarrival:.4f}) is greater than Chrome's ({chrome_avg_interarrival:.4f}).")
else:
    print(f"\nAvgInterArrival (Average): Chrome and Firefox have equal average values ({chrome_avg_interarrival:.4f}).")



metrics = ['AvgPacketSize', 'AvgInterArrival']
chrome_values = [chrome_avg_packet, chrome_avg_interarrival]
firefox_values = [firefox_avg_packet, firefox_avg_interarrival]

x = np.arange(len(metrics))  
width = 0.35  

fig, ax = plt.subplots(figsize=(8, 6))
rects1 = ax.bar(x - width/2, chrome_values, width, label='Chrome')
rects2 = ax.bar(x + width/2, firefox_values, width, label='Firefox')

ax.set_ylabel('Average Value')
ax.set_title('Average Comparison: Chrome vs Firefox')
ax.set_xticks(x)
ax.set_xticklabels(metrics)
ax.legend()


def autolabel(rects):
    for rect in rects:
        height = rect.get_height()
        ax.annotate(f'{height:.4f}',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha='center', va='bottom')

autolabel(rects1)
autolabel(rects2)

plt.show()




weight_packet = 0.1       
weight_interarrival = 0.1  
weight_ip = 0.6            
weight_tcp = 0.2          


packet_min = df['AvgPacketSize'].min()
packet_max = df['AvgPacketSize'].max()
packet_range = packet_max - packet_min

interarrival_min = df['AvgInterArrival'].min()
interarrival_max = df['AvgInterArrival'].max()
interarrival_range = interarrival_max - interarrival_min

attacker_name = "attecttest"
attacker_row = df[df['App'] == attacker_name]

if attacker_row.empty:
    print("No data found for attecttest")
else:
    
    attacker_packet = attacker_row['AvgPacketSize'].values[0]
    attacker_interarrival = attacker_row['AvgInterArrival'].values[0]
    attacker_flow_size = attacker_row['FlowSize'].values[0]
    attacker_ip = ip_protocols_per_app.get(attacker_name, Counter())
    attacker_tcp = tcp_flags_per_app.get(attacker_name, Counter())
    

    attacker_ip_norm = {k: v / attacker_flow_size for k, v in attacker_ip.items()}
    attacker_tcp_norm = {k: v / attacker_flow_size for k, v in attacker_tcp.items()}
    
    similarities = []
    
    
    apps_to_compare = [
        "Chrome (regular)",
        "Chrome (YouTube)",
        "Chrome (SoundCloud)",
        "Firefox (regular)",
        "Firefox (SoundCloud)",
        "Firefox (YouTube)",
        "Zoom"
    ]
    
    for app in apps_to_compare:
        other_row = df[df['App'] == app]
        if other_row.empty:
            continue
        other_packet = other_row['AvgPacketSize'].values[0]
        other_interarrival = other_row['AvgInterArrival'].values[0]
        other_flow_size = other_row['FlowSize'].values[0]
        other_ip = ip_protocols_per_app.get(app, Counter())
        other_tcp = tcp_flags_per_app.get(app, Counter())
        
        
        other_ip_norm = {k: v / other_flow_size for k, v in other_ip.items()}
        other_tcp_norm = {k: v / other_flow_size for k, v in other_tcp.items()}
        
     
        norm_diff_packet = abs(attacker_packet - other_packet) / packet_range
        norm_diff_interarrival = abs(attacker_interarrival - other_interarrival) / interarrival_range
        
      
        all_ip_keys = set(attacker_ip_norm.keys()).union(other_ip_norm.keys())
        diff_ip = sum(abs(attacker_ip_norm.get(k, 0) - other_ip_norm.get(k, 0)) for k in all_ip_keys)
        
      
        all_tcp_keys = set(attacker_tcp_norm.keys()).union(other_tcp_norm.keys())
        diff_tcp = sum(abs(attacker_tcp_norm.get(k, 0) - other_tcp_norm.get(k, 0)) for k in all_tcp_keys)
        
        
        total_diff = (weight_packet * norm_diff_packet +
                      weight_interarrival * norm_diff_interarrival +
                      weight_ip * diff_ip +
                      weight_tcp * diff_tcp)
        
        similarities.append((app, total_diff))
    
    
    similarities.sort(key=lambda x: x[1])
    
    print("\n=== Comparing attecttest with Other Applications (Weighted & Normalized) ===")
    for comp in similarities:
        app, total_diff = comp
        print(f"Application: {app}  |  Total Weighted Difference: {total_diff:.4f}")
    
    if similarities:
        likely_app = similarities[0][0]
        print(f"\nBased on the metrics, attecttest is most similar to: {likely_app}")

