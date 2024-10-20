from scapy.all import *
import os
import time
import curses
from threading import Thread, Lock
from queue import Queue
import nmap
import requests
import psutil

ifaces = [iface for iface in psutil.net_if_addrs().keys() if iface != 'lo']
answer = input(f"Hangi Arayüz Kullanmak İstersiniz (Sizin Bilgisayarınızda Tespit edilenler: {ifaces}) :  ")
numbers_of_packets_processed = 0
autoscroll = True
filters = {"TCP": True, "UDP": True, "ARP": True, "ICMP": True}

def get_location(ip_address):
    try:
        response = requests.get(f'https://ipapi.co/{ip_address}/json/').json()
        location_data = {
            "ip Adresi": ip_address,
            "Şehir": response.get("city"),
            "Bölge": response.get("region"),
            "Ülke": response.get("country_name")
        }
        return location_data
    except Exception as e:
        return {"Hata": str(e)}

def autoscroll_thread(lock, current_index, packets, stdscr, selected_packet):
    global autoscroll
    while True:
        if autoscroll:
            with lock:
                height, _ = stdscr.getmaxyx()
                current_index[0] = max(0, len(packets) - height + 3)
                selected_packet[0] = current_index[0]
        time.sleep(0.1)

def handle_input(stdscr, current_index, packets, lock, selected_packet, content_scroll, tab_index, nmap_queue, nmap_results):
    global autoscroll, filters
    while True:
        key = stdscr.getch()
        with lock:
            height, _ = stdscr.getmaxyx()
            if key == ord('q'):
                break
            elif key == curses.KEY_UP and not autoscroll:
                if selected_packet[0] > 0:
                    selected_packet[0] -= 1
                    if selected_packet[0] < current_index[0]:
                        current_index[0] -= 1
            elif key == curses.KEY_DOWN and not autoscroll:
                if selected_packet[0] < len(packets) - 1:
                    selected_packet[0] += 1
                    if selected_packet[0] >= current_index[0] + height - 2:
                        current_index[0] += 1
            elif key == ord('r'):
                autoscroll = not autoscroll
                if not autoscroll:
                    selected_packet[0] = current_index[0]
            elif key == ord('c'):
                current_index[0] = max(0, selected_packet[0] - height + 3)
            elif key == curses.KEY_PPAGE:
                content_scroll[0] = max(0, content_scroll[0] - (height // 2))
            elif key == curses.KEY_NPAGE:
                content_scroll[0] += height // 2
            elif key == ord('\t'):
                tab_index[0] = (tab_index[0] + 1) % 5
            elif key == ord('t'):  # TCP filtresini aç / kapat
                filters["TCP"] = not filters["TCP"]
            elif key == ord('u'):  # UDP filtresini aç / kapat
                filters["UDP"] = not filters["UDP"]
            elif key == ord('a'):  # ARP filtresini aç / kapat
                filters["ARP"] = not filters["ARP"]
            elif key == ord('i'):  # ICMP filtresini aç / kapat
                filters["ICMP"] = not filters["ICMP"]
            elif key == ord('n'):  # Manuel Nmap taraması başlat
                if packets and 0 <= selected_packet[0] < len(packets):
                    packet = packets[selected_packet[0]][1]
                    if IP in packet:
                        src_ip = packet[IP].src
                        if src_ip not in nmap_results:
                            nmap_thread = Thread(target=perform_nmap_scan, args=(src_ip, nmap_queue))
                            nmap_thread.daemon = True
                            nmap_thread.start()

def process_packet(packet):
    return f"Paket: {packet.summary()}"

def perform_nmap_scan(ip, nmap_queue):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-F')
    nmap_queue.put((ip, nm[ip]))

def display_packets(stdscr, packet_queue, nmap_queue):
    global autoscroll, filters
    try:
        packets = []
        filtered_packets = []
        current_index = [0]
        selected_packet = [0]
        content_scroll = [0]
        tab_index = [0]
        lock = Lock()
        nmap_lock = Lock()
        nmap_results = {}

        curses.start_color()
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
        curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(5, curses.COLOR_MAGENTA, curses.COLOR_BLACK)

        autoscroll_t = Thread(target=autoscroll_thread, args=(lock, current_index, filtered_packets, stdscr, selected_packet))
        autoscroll_t.daemon = True
        autoscroll_t.start()

        input_t = Thread(target=handle_input, args=(stdscr, current_index, filtered_packets, lock, selected_packet, content_scroll, tab_index, nmap_queue, nmap_results))
        input_t.daemon = True
        input_t.start()

        while True:
            if not packet_queue.empty():
                new_packet = packet_queue.get()
                packet_info = process_packet(new_packet)
                with lock:
                    packets.append((packet_info, new_packet))
                    if (filters["TCP"] and TCP in new_packet) or \
                       (filters["UDP"] and UDP in new_packet) or \
                       (filters["ARP"] and ARP in new_packet) or \
                       (filters["ICMP"] and ICMP in new_packet):
                        filtered_packets.append((packet_info, new_packet))
                    
                    if IP in new_packet:
                        src_ip = new_packet[IP].src
                        with nmap_lock:
                            if src_ip not in nmap_results:
                                nmap_thread = Thread(target=perform_nmap_scan, args=(src_ip, nmap_queue))
                                nmap_thread.daemon = True
                                nmap_thread.start()

            # Process Nmap results
            if not nmap_queue.empty():
                ip, scan_result = nmap_queue.get()
                with nmap_lock:
                    nmap_results[ip] = scan_result

           # Sayfayı temizle
            stdscr.clear()
            height, width = stdscr.getmaxyx()

            packet_list_width = width // 3

            
            stdscr.attron(curses.color_pair(1))
            stdscr.addstr(0, 0, f"Paket Analiz Aracı - @yusuffenes (Tab İle Etkileşime Girin: {['Özet', 'Tüm İçerik', 'Hexdump(16 sistem)', 'Nmap Taraması', 'Çoğrafi Tarama'][tab_index[0]]})", curses.A_BOLD)
            stdscr.attroff(curses.color_pair(1))

            # Aktif filtreler
            filter_str = "Filtreler: "
            for proto, state in filters.items():
                filter_str += f"{proto}: {'Açık' if state else 'Kapalı'}  "
            stdscr.addstr(1, 0, filter_str.strip(), curses.color_pair(1))

            # Paket listesi
            for i in range(2, height - 4):  # Adjust to leave space for footer
                if current_index[0] + i - 2 < len(filtered_packets):
                    packet_info = filtered_packets[current_index[0] + i - 2][0]
                    display_str = f"{current_index[0] + i - 1}. {packet_info}"
                    if len(display_str) > packet_list_width - 1:
                        display_str = display_str[:packet_list_width-4] + "..."
                    color = curses.color_pair(3) if "TCP" in display_str else curses.color_pair(4) if "UDP" in display_str else curses.color_pair(5)
                    if current_index[0] + i - 2 == selected_packet[0]:
                        stdscr.attron(curses.A_REVERSE)
                    stdscr.attron(color)
                    stdscr.addstr(i, 0, display_str[:packet_list_width-1])
                    stdscr.attroff(color)
                    if current_index[0] + i - 2 == selected_packet[0]:
                        stdscr.attroff(curses.A_REVERSE)

            
            if filtered_packets and 0 <= selected_packet[0] < len(filtered_packets):
                packet_info, packet = filtered_packets[selected_packet[0]]

                if tab_index[0] == 0:  # Summary
                    summary = packet.summary().splitlines()
                    for i, line in enumerate(summary[content_scroll[0]:]):
                        if i + 2 >= height - 2:
                            break
                        stdscr.addstr(i + 2, packet_list_width + 1, line[:width - packet_list_width - 2])
                elif tab_index[0] == 1:  # Content 
                    content = packet.show(dump=True).splitlines()
                    for i, line in enumerate(content[content_scroll[0]:]):
                        if i + 2 >= height - 1:
                            break
                        stdscr.addstr(i + 2, packet_list_width + 1, line[:width - packet_list_width - 2])
                elif tab_index[0] == 2:  # Hexdump 
                    hexdump_lines = hexdump(packet, dump=True).splitlines()
                    for i, line in enumerate(hexdump_lines[content_scroll[0]:]):
                        if i + 2 >= height - 1:
                            break
                        stdscr.addstr(i + 2, packet_list_width + 1, line[:width - packet_list_width - 2])
                elif tab_index[0] == 3:  # Nmap Taraması
                    if IP in packet:
                        src_ip = packet[IP].src
                        with nmap_lock:
                            if src_ip in nmap_results:
                                scan_result = nmap_results[src_ip]
                                scan_lines = [f"Nmap Taraması Sonuçları {src_ip}:"]
                                if 'tcp' in scan_result:
                                    scan_lines.extend([f"Port {port}: {scan_result['tcp'][port]['state']}" for port in scan_result['tcp']])
                                else:
                                    scan_lines.append("Açık TCP Portu bulunamadı.")
                                for i, line in enumerate(scan_lines[content_scroll[0]:]):
                                    if i + 2 >= height:
                                        break
                                    stdscr.addstr(i + 2, packet_list_width + 1, line[:width - packet_list_width - 2])
                            else:
                                stdscr.addstr(2, packet_list_width + 1, "Nmap Bulunamadı.")
                    else:
                        stdscr.addstr(2, packet_list_width + 1, "Bu pakatte aktif bir IP bulunamadı.")
                elif tab_index[0] == 4:  # Coğrafi Tarama
                    if IP in packet:
                        src_ip = packet[IP].src
                        location_data = get_location(src_ip)
                        location_str = f"IP: {location_data.get('IP', 'N/A')}\n"
                        location_str += f"Şehir: {location_data.get('Şehir', 'N/A')}\n"
                        location_str += f"Bölge: {location_data.get('Bölge', 'N/A')}\n"
                        location_str += f"Ülke: {location_data.get('Ülke', 'N/A')}\n"
                        for i, line in enumerate(location_str.splitlines()):
                            if i + 2 >= height - 1:
                                break
                            stdscr.addstr(i + 2, packet_list_width + 1, line[:width - packet_list_width - 2])

            # Footer: Extended commands info
            stdscr.attron(curses.color_pair(2))
            footer_text = "Otomatik kaydırma için r | Görünüm için 'Tab' | Nmap taraması için 'n' | Filtreler için 't/u/a/i' (TCP/UDP/ARP/ICMP) | 'Ctrl-C' to quit"
            stdscr.addstr(height - 1, 0, footer_text[:width], curses.A_BOLD)
            stdscr.attroff(curses.color_pair(2))

            stdscr.refresh()
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
def main():
    packet_queue = Queue()
    nmap_queue = Queue()

    def packet_sniffer(packet):
        global numbers_of_packets_processed
        packet_queue.put(packet)
        numbers_of_packets_processed += 1

    sniff_thread = Thread(target=sniff, kwargs={"iface": answer, "prn": packet_sniffer})
    sniff_thread.daemon = True
    sniff_thread.start()

    curses.wrapper(display_packets, packet_queue, nmap_queue)
if __name__ == '__main__':
   main()