import sys
import dpkt
import datetime
import json
from dpkt.utils import mac_to_str, inet_to_str

event_duration = 1000000

csv_file = None
json_file = None

def print_packets(pcap):
    """Print out information about each packet in a pcap
       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    chrome_trace_events = {
        "displayTimeUnit": "ms",
        # "name": "process_name", "ph": "M", "pid": "Main", "tid": "工作", "args": {"name": "时间线"}}
        'traceEvents': []
    }
    sum_events = []
    detailed_events = []
    global csv_file
    time_0 = None
    panels = {}
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:

        # Print out the timestamp in UTC
        # print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))
        time = datetime.datetime.utcfromtimestamp(timestamp)
        if not time_0:
            time_0 = time

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

        seconds = (time - time_0).total_seconds()

        ts = str(datetime.datetime.utcfromtimestamp(timestamp))
        if isinstance(ip.data, dpkt.udp.UDP): #  or isinstance(ip.data, dpkt.tcp.TCP):
            protocol = ip.data.__class__.__name__
            udp = ip.data
            payload = len(udp)
            csv_file.write('%s,%4d,%s,%s:%d,%s:%d\n' %
                (protocol, payload, ts, inet_to_str(ip.src), udp.sport, inet_to_str(ip.dst), udp.dport))

            hex_data = udp.data.hex()
            size = len(hex_data)
            nice_data = []
            row_size = 32
            for i in range(0, size, row_size):
                row = hex_data[i:i+row_size]
                nice_row = ''
                for j in range(0, row_size, 2):
                    nice_row += row[j:j+2]
                    nice_row += ' '
                nice_data.append(nice_row)

            time_key = int(seconds) * event_duration

            panel_label = "%s -> %s" % (inet_to_str(ip.src), inet_to_str(ip.dst))
            if panel_label not in panels:
                panels[panel_label] = {}
            panel = panels[panel_label]
            
            if time_key not in panel:
                panel[time_key] = []
            time_container = panel[time_key]

            event = {
                'bytes': payload,
                'time': ts.replace('000', ''),
                'src': '%s:%d' % (inet_to_str(ip.src), udp.sport),
                'dst': '%s:%d' % (inet_to_str(ip.dst), udp.dport),
                'data': '\n'.join(nice_data)
            }

            time_container.append(event)
            detailed_events.append({
                'name': str(payload),
                'cat':  protocol,
                'ph': 'X',
                'ts': time_key,
                'dur': event_duration,
                'pid': inet_to_str(ip.src),
                'tid': 'Src Port: %d' % udp.sport,
                'args': event
            })

    # sum events
    for panel_k, panel in panels.items():
        for time_key, events in panel.items():
            count = 0
            size = 0
            for event in events:
                count += 1
                size += event['bytes']
            sum_events.append({
                'name': str(count),
                'cat':  'count',
                'ph': 'X',
                'ts': time_key,
                'dur': event_duration,
                'pid': panel_k,
                'tid': 'pkg_count',
                # 'args': {}
            })
            sum_events.append({
                'name': str(size),
                'cat': 'size',
                'ph': 'X',
                'ts': time_key,
                'dur': event_duration,
                'pid': panel_k,
                'tid': 'pkg_bytes',
                # 'args': {}
            })
            
    chrome_trace_events['traceEvents'] = sum_events + detailed_events
    json.dump(chrome_trace_events, json_file, indent=4)

    
    # Pretty print the last packet
    # print('** Pretty print demo **\n')
    # print(eth)

def process_file(file_name):
    """Open up a test pcap file and print out the packets"""
    global csv_file, json_file
    # with open('qnet_save/pcap/com.t3game.vs_2021_07_05_23_36_18.pcap', 'rb') as f:
    with open(file_name, 'rb') as f:
        if '.pcapng' in file_name:
            pcap = dpkt.pcapng.Reader(f)
        else:
            pcap = dpkt.pcap.Reader(f)
        csv_file = open(file_name + '.csv', 'w')
        json_file = open(file_name + '.json', 'w')
        csv_file.write('protocol,bytes,timestamp,src,dst\n')
        print_packets(pcap)

if __name__ == '__main__':
    pcap_file = 'qnet_save/pcap/com.t3game.vs_2021_07_05_15_49_30_edited.pcapng'
    if len(sys.argv) > 1:
        pkg_csv = sys.argv[1]
    process_file(pcap_file)
