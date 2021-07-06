import sys
import dpkt
import datetime
from dpkt.utils import mac_to_str, inet_to_str


def print_packets(pcap):
    """Print out information about each packet in a pcap
       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:

        # Print out the timestamp in UTC
        # print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        # print('Ethernet Frame: ', mac_to_str(eth.src), mac_to_str(eth.dst), eth.type)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now access the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        ts = str(datetime.datetime.utcfromtimestamp(timestamp))
        if isinstance(ip.data, dpkt.udp.UDP): # or isinstance(ip.data, dpkt.tcp.TCP):
            protocol = ip.data.__class__.__name__
            udp = ip.data
            payload = len(udp)
            print('%s,%4d,%s,%s:%d,%s:%d' %
                (protocol, payload, ts, inet_to_str(ip.src), udp.sport, inet_to_str(ip.dst), udp.dport))

        # Print out the info, including the fragment flags and offset
        # print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' %
            #   (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, ip.df, ip.mf, ip.offset))

    # Pretty print the last packet
    # print('** Pretty print demo **\n')
    # print(eth)


def process_file(file_name):
    """Open up a test pcap file and print out the packets"""
    # with open('qnet_save/pcap/com.t3game.vs_2021_07_05_23_36_18.pcap', 'rb') as f:
    with open(file_name, 'rb') as f:
        if '.pcapng' in file_name:
            pcap = dpkt.pcapng.Reader(f)
        else:
            pcap = dpkt.pcap.Reader(f)
        print('protocol,bytes,timestamp,src,dst')
        print_packets(pcap)

if __name__ == '__main__':
    pcap_file = 'qnet_save/pcap/com.t3game.vs_2021_07_05_15_49_30_edited.pcapng'
    if len(sys.argv) > 1:
        pkg_csv = sys.argv[1]    
    process_file(pcap_file)
