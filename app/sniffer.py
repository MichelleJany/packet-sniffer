from scapy.all import sniff

def packet_callback(packet):
    print(packet.summary())

def start_sniffing(filter_str, count, timeout):
    packets = sniff(
        filter=filter_str,
        prn=packet_callback,
        count=count,
        timeout=timeout
        )
    return packets