# NetworkTrafficAnalyzer
Project by Guy Levy, Estee Lemkin and Gal Maymon
## 🚀 Overview
**NetworkTrafficAnalyzer** is a Python tool that uses PyShark to analyze network traffic from Wireshark packet captures (pcapng). It extracts key metrics such as packet sizes, inter-arrival times, and protocol distributions, comparing traffic patterns across apps like Chrome YouTube and Firefox YouTube. It also identifies similarities between unknown and known traffic patterns.

## 📦 Features
- **Packet Analysis**: Analyzes packet sizes, inter-arrival times, and flow volumes.
- **Protocol Insights**: Tracks IP protocols, TCP flags, and HTTP/2 usage.
- **Visualization**: Generates comparison plots for key metrics.
- **Traffic Comparison**: Compares unknown traffic to app patterns to detect similarities.

## 🔧 Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/NetworkTrafficAnalyzer.git
   cd NetworkTrafficAnalyzer
   ```
2. Install dependencies:
   ```bash
   sudo apt-get update

   sudo apt-get install python3-pyshark
   sudo apt-get install python3-pandas
   sudo apt-get install python3-matplotlib
   sudo apt-get install python3-numpy

   sudo pip install --break-system-packages pyshark

   sudo apt-get update
   sudo apt-get install tshark
   ```

## 🚦 Usage
Ensure you have the necessary pcapng files in the project directory.

Run the main script:
```bash
python import_pyshark.py
```

## 📁 Data
The tool processes the following captures:
- **Chrome (YouTube):** `chromeyoutube.pcapng`
- **Firefox (YouTube):** `firefoxyoutube.pcapng`
- And more...

## 📊 Visualizations
The script generates visual comparisons for:
- Average Packet Size per App
- Inter-Arrival Time
- Flow Size (Packet Count)
- Flow Volume (Bytes)

## 🛡️ Similarity Detection
Compares the traffic from an unknown source (`attecttest.pcapng`) against known apps and identifies the closest match using weighted metrics.


---

Happy analyzing! 📡
