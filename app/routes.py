# Staff and Menu. Define URLs, etc.

from flask import Blueprint, render_template, request, jsonify
from .sniffer import start_sniffing
from scapy.layers.inet import IP, TCP, UDP, ICMP

bp = Blueprint('main', __name__)

@bp.route('/', methods=['GET', 'POST'])
def index():
    filter_val, count_val, timeout_val = None, 10, 10
    results = None

    if request.method == 'POST':
        filter_val = request.form.get('filter')
        count_val = int(request.form.get('count', 10))
        timeout_val = int(request.form.get('timeout', 10))

        filter_for_scapy = filter_val if filter_val else None

        captured_packets = start_sniffing(filter_for_scapy, count_val, timeout_val)

        results = []

        for packet in captured_packets:
            packet_info = { 'srsc': 'N/A', 'dst': 'N/A', 'proto': 'Other', 'summary': packet.summary() }
            if packet.haslayer(IP):
                packet_info['src'] = packet[IP].src
                packet_info['dst'] = packet[IP].dst
            if packet.haslayer(TCP): packet_info['proto'] = 'TCP'
            elif packet.haslayer(UDP): packet_info['proto'] = 'UDP'
            elif packet.haslayer(ICMP): packet_info['proto'] = 'ICMP'
            results.append(packet_info)

    return render_template('index.html', results=results, filter_val=filter_val, count_val=count_val, timeout_val=timeout_val)

@bp.route('/start-sniff', methods=['POST'])
def start_sniff_route():
        data = request.get_json()
        filter_str = data.get('filter')
        count = int(data.get('count', 10))
        timeout = int(data.get('timeout', 10))

        if not filter_str:
            filter_str = None

        print(f"API: Starting sniff with filter='{filter_str}', count={count}, timeout={timeout}")
        captured_packets = start_sniffing(filter_str, count, timeout)

        results = []
        for packet in captured_packets:
            packet_info = { 'src': 'N/A', 'dst': 'N/A', 'proto': 'Other', 'summary': packet.summary() }
            if packet.haslayer(IP):
                packet_info['src'] = packet[IP].src
                packet_info['dst'] = packet[IP].dst
            if packet.haslayer(TCP): packet_info['proto'] = 'TCP'
            elif packet.haslayer(UDP): packet_info['proto'] = 'UDP'
            elif packet.haslayer(ICMP): packet_info['proto'] = 'ICMP'
            results.append(packet_info)

        return jsonify(results)