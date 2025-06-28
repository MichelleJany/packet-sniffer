# Staff and Menu. Define URLs, etc.

from flask import Blueprint, render_template, request
from scapy.layers.inet import IP, TCP, UDP, ICMP

from .sniffer import start_sniffing

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