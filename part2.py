import sys
import csv
import json
import re
import regex
import datetime
import binascii
import base64
from urllib.parse import unquote
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

def execute_functions(pcap, ingest,
                        var_client_MAC_IP,
                        var_FTP_hostname,
                        var_facebook):
    mdns_ptr = {}
    src_clients = {}
    if var_client_MAC_IP.get():
        with open('CLIENT_MAC_IP_examiner.csv', mode='a', newline='') as examiner_csv:
            examiner_writer = csv.writer(examiner_csv, delimiter=',')
            ct = datetime.datetime.now()
            examiner_writer.writerow([f'Examined at: {ct}'])
            for packet in ingest:
                source = packet.get('_source', {})
                layers = source.get('layers', {})
                ip_src = layers.get('ip', {}).get('ip.src')
                ip_dst = layers.get('ip', {}).get('ip.dst')
                src_mac = layers.get('eth', {}).get('eth.src')
                src_oui = layers.get('eth', {}).get('eth.src_tree').get('eth.src.oui_resolved')
                dns_resp_flag = layers.get('dns', {}).get('dns.flags_tree', {}).get('dns.flags.response')
                mdns_ans = layers.get('mdns', {}).get('Answers', {})
                dhcp_hw_mac = layers.get('dhcp', {}).get('dhcp.hw.mac_addr')
                dhcp6 = layers.get('dhcpv6', {})
                http = layers.get('http', {})

                if ip_src is not None and ip_src.startswith('10.'):
                    if src_mac not in src_clients:
                        src_clients[src_mac] = {'src_ip': {ip_src}, 'dns_count': 0, 'dhcp_count': 0, 'http_count': 0, 'src_oui': src_oui}
                    else:
                        src_clients[src_mac]['src_ip'].add(ip_src)

                if dns_resp_flag == '1':
                    if src_mac in src_clients:
                        src_clients[src_mac]['src_ip'].add(ip_src)
                        src_clients[src_mac]['dns_count'] += 1
                    else:
                        src_clients[src_mac] = {'src_ip': {ip_src}, 'dns_count': 1, 'dhcp_count': 0, 'http_count': 0, 'src_oui': src_oui}

                if src_mac is not None and dhcp_hw_mac is not None and src_mac in dhcp_hw_mac:
                    if src_mac in src_clients:
                        src_clients[src_mac]['dhcp_count'] += 1
                    else:
                        src_clients[src_mac] = {'src_ip': {ip_src}, 'dns_count': 0, 'dhcp_count': 1, 'http_count': 0, 'src_oui': src_oui}

                for key in http.keys():
                    http_resp = http[key]
                    if isinstance(http_resp, dict):
                        http_resp = http_resp.get('http.response.code', '')
                        if src_mac is not None and http_resp != '':
                            if src_mac in src_clients:
                                src_clients[src_mac]['http_count'] += 1
                            else:
                                src_clients[src_mac] = {'src_ip': {ip_src}, 'dns_count': 0, 'dhcp_count': 0, 'http_count': 1, 'src_oui': src_oui}
                               
                for key in mdns_ans:
                    mdns_name = mdns_ans[key].get('dns.ptr.domain_name', '')
                    if mdns_name != '':                        
                        name = regex.findall(r'(?!\s)(\D{2,}.*o)(?:\.)', mdns_name)
                        if src_mac not in mdns_ptr:
                            mdns_ptr[src_mac] = name

            for src_mac, val in src_clients.items():
                if len(val['src_ip']) >= 1 and val['dns_count'] >= 0 and val['dhcp_count'] >= 0 and val['http_count'] >=0:
                    examiner_writer.writerow([f'SRC MAC: {src_mac}; SRC IP: {list(val["src_ip"])[0]}; DNS RESPs: {val["dns_count"]}; DHCP RESPs: {val["dhcp_count"]}; HTTP RESPs: {val["http_count"]};  OUI: {val["src_oui"]}'])
                    if src_mac in mdns_ptr:
                        examiner_writer.writerow([f'CLIENT MAC: {src_mac} == {mdns_ptr[src_mac][0]}'])

            examiner_writer.writerow(['\n'])

    ftp_srv = {}
    ftp_ips = set()
    if var_FTP_hostname.get():
        with open('FTP_examiner.csv', mode='a', newline='') as examiner_csv:
            examiner_writer = csv.writer(examiner_csv, delimiter=',')
            ct = datetime.datetime.now()
            examiner_writer.writerow([f'Examined at: {ct}'])
            for packet in ingest:
                source = packet.get('_source', {})
                layers = source.get('layers', {})
                frame_num = layers.get('frame', {}).get('frame.number')
                ip_src = layers.get('ip', {}).get('ip.src')
                ip_dst = layers.get('ip', {}).get('ip.dst')
                src_mac = layers.get('eth', {}).get('eth.src')
                dst_mac = layers.get('eth', {}).get('eth.dst')

                ftp = layers.get('ftp', {})
                ftp_request = ftp.get('ftp.request', {})
                ftp_response = ftp.get('ftp.response', {})

                if ftp_request == '1':
                    examiner_writer.writerow([f'FTP REQUEST IN - FRAME: {frame_num}; SRC IP: {ip_src} & SRC MAC: {src_mac}; DST IP: {ip_dst} & DST MAC: {dst_mac}'])

                    for key in ftp.keys():
                        ftp_get = ftp.get(key, {})
                        if isinstance(ftp_get, dict):
                            ftp_req_cmd = ftp[key].get('ftp.request.command', '')
                            examiner_writer.writerow([f'FTP request.command: {ftp_req_cmd}'])

                            ftp_req_arg = ftp[key].get('ftp.request.arg', '')
                            if ftp_req_arg != '':
                                examiner_writer.writerow([f'FTP request.arg: {ftp_req_arg}'])
                                
                    examiner_writer.writerow(['\n'])                    
                if ftp_request == '0':
                    examiner_writer.writerow([f'FTP RESPONSE IN - FRAME: {frame_num}; SRC IP: {ip_src} & SRC MAC: {src_mac}; DST IP: {ip_dst} & DST MAC: {dst_mac}'])

                    for key in ftp.keys():
                        ftp_get = ftp.get(key, {})
                        if isinstance(ftp_get, dict):
                            ftp_resp_code = ftp[key].get('ftp.response.code', '')
                            examiner_writer.writerow([f'FTP response.code: {ftp_resp_code}'])

                            if key.startswith('220 '):
                                ftp_srv[ip_src] = [frame_num, src_mac, ip_dst, dst_mac]
                                ftp_ips.add(ip_src)
                            ftp_resp_arg = ftp[key].get('ftp.response.arg', '')
                            if ftp_resp_arg != '':
                                examiner_writer.writerow([f'FTP response.arg: {ftp_resp_arg}'])

                    examiner_writer.writerow(['\n'])                 
            for ip_src, ftp_list in ftp_srv.items():
                examiner_writer.writerow([f'FTP connection in frame: {ftp_list[0]}; FTP IP: {ip_src} & FTP MAC: {ftp_list[1]}; Client IP: {ftp_list[2]} & Client MAC: {ftp_list[3]}'])

            for packet in ingest:
                source = packet.get('_source', {})
                layers = source.get('layers', {})
                dns = layers.get('dns', {})
                dns_answer = dns.get('Answers', {})     

                for key, value in dns_answer.items():
                    dns_a = value.get('dns.a', '').strip()
                    if dns_a in ftp_ips:  
                        dns_ns = value.get('dns.resp.name', {})
                        examiner_writer.writerow([f'FTP server hostname is: {dns_ns}'])
                        examiner_writer.writerow(['\n'])
        
    if var_facebook.get():
        with open('FACEBOOK_examiner.csv', mode='a', newline='') as examiner_csv:
            examiner_writer = csv.writer(examiner_csv, delimiter=',')
            ct = datetime.datetime.now()
            examiner_writer.writerow([f'Examined at: {ct}'])
            for packet in ingest:
                source = packet.get('_source', {})
                layers = source.get('layers', {})
                frame = layers.get('frame', {})
                frame_num = frame.get('frame.number')
                ip_src = layers.get('ip', {}).get('ip.src')
                src_mac = layers.get('eth', {}).get('eth.src')

                http = layers.get('http', {})
                http_host = http.get('http.host')
                http_request = http.get('http.request.line')
                http_cookie = http.get('http.cookie')
                http_req_uri = http.get('http.request.full_uri') 

                if http_host is not None and 'facebook' in http_host:
                    if http_cookie is not None:
                        examiner_writer.writerow([f'FRAME NUMBER: {frame_num}; Client IP: {ip_src}; Client MAC: {src_mac}'])
                        decoded = unquote(http_cookie)
                        examiner_writer.writerow([f'FACEBOOK COOKIE: {decoded}'])

                if http_req_uri is not None and 'facebook' in http_req_uri:
                    examiner_writer.writerow([f'FRAME NUMBER: {frame_num}; Client IP: {ip_src}; Client MAC: {src_mac}'])
                    decoded = unquote(http_req_uri)
                    examiner_writer.writerow([f'FACEBOOK URI: {decoded}'])

def main():
    root = tk.Tk()
    root.withdraw()

    filename = filedialog.askopenfilename(title="Select a file", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
    if filename:

        with open(filename, 'r', encoding='utf-8') as pcap:
            ingest = json.load(pcap)
            
            root = tk.Tk()
            tk.Label(root, text = 'Make one or more selections:').pack(pady=10)

            var_client_MAC_IP =     tk.IntVar(value=0, master=root)
            var_FTP_hostname =      tk.IntVar(value=0, master=root)
            var_facebook =          tk.IntVar(value=0, master=root)

            ttk.Checkbutton(root, text = 'All client MACs and IPs',     variable = var_client_MAC_IP).pack(anchor='w')            
            ttk.Checkbutton(root, text = 'FTP session and hostname',    variable = var_FTP_hostname).pack(anchor='w')
            ttk.Checkbutton(root, text = 'Facebook URIs',               variable = var_facebook).pack(anchor='w')
            
            ttk.Button(root, text='Execute Selected Functions', command = lambda: [execute_functions(pcap, ingest,
                                                                                                    var_client_MAC_IP,
                                                                                                    var_FTP_hostname,
                                                                                                    var_facebook), re_execute(root)]).pack(pady=10)
            root.mainloop()

    else:
        print("No file selected")
        sys.exit()

def re_execute(root):
    root.destroy()

    run_again = messagebox.askyesno(title='', message='Would you like to run another function?')
    if run_again:
        main()
    if not run_again:
        sys.exit()

if __name__ == '__main__':
    main()
