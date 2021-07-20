import sys
import datetime
import json
from pathlib import Path
import os
import subprocess
import dpkt
from dpkt.utils import mac_to_str, inet_to_str

event_duration = 1000000

WRITES_CSV = False

csv_file = None
json_file = None

cwd = Path(__file__).parent

def open_chrome_tracing():
    import webbrowser 
    # open a public URL, in this case, the webbrowser docs
    url = "http://rd.xindong.com/net-doctor/trace_viewer.html"
    webbrowser.open_new_tab(url)

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
            # print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now access the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        seconds = (time - time_0).total_seconds()

        ts = str(datetime.datetime.utcfromtimestamp(timestamp))
        if (isinstance(ip.data, dpkt.udp.UDP) and 'tmgp.cod' not in pcap.name) or (isinstance(ip.data, dpkt.tcp.TCP) and 'tmgp.cod' in pcap.name):
            protocol = ip.data.__class__.__name__
            udp = ip.data
            payload = len(udp)
            if WRITES_CSV:
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

            panel_label = "%s -> %s [Summary]" % (inet_to_str(ip.src), inet_to_str(ip.dst))
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
                'pid': "%s -> %s [Details]" % (inet_to_str(ip.src), inet_to_str(ip.dst)),
                'tid': 'packages_from_port: %d' % udp.sport,
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
                'tid': 'package_count',
                # 'args': {}
            })
            sum_events.append({
                'name': str(size),
                'cat': 'size',
                'ph': 'X',
                'ts': time_key,
                'dur': event_duration,
                'pid': panel_k,
                'tid': 'package_bytes',
                # 'args': {}
            })

            # sum_events.append({
            #     'name': 'package_count',
            #     'cat':  'count',
            #     'ph': 'C',
            #     'ts': time_key,
            #     'dur': event_duration,
            #     'pid': panel_k,
            #     'args': {
            #         'count': count,
            #     }
            # })
            # sum_events.append({
            #     'name': 'package_bytes',
            #     'cat':  'count',
            #     'ph': 'C',
            #     'ts': time_key,
            #     'dur': event_duration,
            #     'pid': panel_k,
            #     'args': {
            #         'size': size
            #     }
            # })            
            
    chrome_trace_events['traceEvents'] = sum_events + detailed_events
    json.dump(chrome_trace_events, json_file, indent=4)

def process_file(file_name):
    """Open up a test pcap file and print out the packets"""
    global csv_file, json_file
    file_path = Path(file_name)
    stem = file_path.stem.replace('_edited.pcapng', '')
    csv_filename = str(cwd / 'reports' / str(stem + '.csv'))
    json_filename = str(cwd / 'reports' / str(stem + '.json'))
    if file_path.suffix == '.pcap':
        pcapng = file_name.replace('.pcap', '_edited.pcapng')
        if not Path(pcapng).exists():
            wrangler_exe = str(cwd / 'bin' / 'TraceWrangler.exe')
            wrangler_task = str(cwd / 'bin' / 'cvt.task')
            subprocess.run([wrangler_exe, file_name, wrangler_task, '/autorun', '/exit'], shell=True)
            file_name = pcapng
        else:
            file_name = pcapng
            
    with open(file_name, 'rb') as f:
        # print('Reading', file_name)
        if Path(file_name).suffix == '.pcapng':
            pcap = dpkt.pcapng.Reader(f)
        else:
            pcap = dpkt.pcap.Reader(f)
        if WRITES_CSV:
            csv_file = open(csv_filename, 'w')
            csv_file.write('protocol,bytes,timestamp,src,dst\n')
        json_file = open(json_filename, 'w')
        print_packets(pcap)
        if WRITES_CSV:
            print('Writes: ', csv_filename)
        print(json_filename)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        pcap = sys.argv[1]
        print("Converting pcap file %s." % pcap)
        process_file(pcap)
    else:
        print("Pulling pcap files from qnet folder.")
        adb_exe = str(cwd / 'bin' / 'adb.exe')
        subprocess.run([adb_exe, 'pull', '/sdcard/qnet_save'], shell=True)
        pcap_dir = cwd / 'qnet_save' / 'pcap'
        if not pcap_dir.exists():
            exit(1)

        Path(cwd / 'reports').mkdir(parents=True, exist_ok=True)
        for pcap in pcap_dir.iterdir():
            if pcap.suffix == '.pcap':
                process_file(str(pcap))

    # open_chrome_tracing()