import tkinter as tk
from tkinter import scrolledtext, Toplevel, messagebox, ttk
from threading import Thread
import psutil
from scapy.all import sniff, IP, TCP, UDP, ICMP, hexdump
import requests
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import time

# Kullanılabilir arayüzleri listele
ifaces = [iface for iface in psutil.net_if_addrs().keys() if iface != 'lo']

class PacketAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Gelişmiş Paket Analiz Aracı")

        self.sniffing = False
        self.display_mode = 'summary'
        self.sniffed_packets = []
        self.bytes_sent = []
        self.bytes_recv = []
        self.times = []
        self.start_time = time.time()
        self.packet_delay = 0.1  # Varsayılan paket gecikmesi (saniye)

        self.modes = ['Özet', 'Coğrafi Bilgi', 'Protokol Analizi', 'Paket İçeriği']
        self.current_mode = tk.StringVar(value=self.modes[0])

        # Ana pencereyi iki ana frame'e böl
        main_frame = tk.PanedWindow(root, orient=tk.HORIZONTAL)
        main_frame.pack(fill=tk.BOTH, expand=1)

        # Sol tarafta grafik alanı
        left_frame = tk.Frame(main_frame)
        main_frame.add(left_frame)

        self.fig, self.ax = plt.subplots(figsize=(5, 4))
        self.canvas = FigureCanvasTkAgg(self.fig, master=left_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        # Sağ tarafta kontrol ve gösterim alanı
        right_frame = tk.Frame(main_frame)
        main_frame.add(right_frame)

        # Üst kısım: Kontroller
        control_frame = tk.Frame(right_frame)
        control_frame.pack(side=tk.TOP, fill=tk.X)

        self.interface_label = tk.Label(control_frame, text="Arayüz Seçimi:", font=("Arial", 12, "bold"))
        self.interface_label.pack(side=tk.LEFT, padx=5)

        self.interface_var = tk.StringVar(root)
        self.interface_var.set(ifaces[0])
        self.interface_menu = tk.OptionMenu(control_frame, self.interface_var, *ifaces, command=self.change_interface)
        self.interface_menu.config(width=15)
        self.interface_menu.pack(side=tk.LEFT, padx=5)

        self.mode_label = tk.Label(control_frame, text="Görüntüleme Modu:", font=("Arial", 10, "bold"))
        self.mode_label.pack(side=tk.LEFT, padx=5)

        self.mode_menu = tk.OptionMenu(control_frame, self.current_mode, *self.modes, command=self.change_mode)
        self.mode_menu.config(width=15)
        self.mode_menu.pack(side=tk.LEFT, padx=5)

        # Paket gecikmesi için kaydırıcı
        self.delay_label = tk.Label(control_frame, text="Paket Gecikmesi (ms):", font=("Arial", 10, "bold"))
        self.delay_label.pack(side=tk.LEFT, padx=5)

        self.delay_slider = ttk.Scale(control_frame, from_=0, to=1000, orient=tk.HORIZONTAL, length=200, 
                                      command=self.update_delay)
        self.delay_slider.set(self.packet_delay * 1000)
        self.delay_slider.pack(side=tk.LEFT, padx=5)

        self.delay_value = tk.Label(control_frame, text=f"{int(self.packet_delay * 1000)} ms", width=5)
        self.delay_value.pack(side=tk.LEFT, padx=5)

        # Orta kısım: Paket gösterimi
        self.packet_display = scrolledtext.ScrolledText(right_frame, height=10, width=60, bg="#f0f0f0", font=("Consolas", 10))
        self.packet_display.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)
        self.packet_display.bind("<Double-1>", self.show_packet_details)

        # Alt kısım: Coğrafi bilgi ve Hexdump
        bottom_frame = tk.Frame(right_frame)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        self.geo_display = scrolledtext.ScrolledText(bottom_frame, height=5, width=30, bg="#e0e0e0", font=("Consolas", 10))
        self.geo_display.pack(side=tk.LEFT, pady=5, padx=5, fill=tk.BOTH, expand=True)

        self.hexdump_display = scrolledtext.ScrolledText(bottom_frame, height=5, width=30, bg="#e0e0e0", font=("Consolas", 10))
        self.hexdump_display.pack(side=tk.RIGHT, pady=5, padx=5, fill=tk.BOTH, expand=True)

        # Butonlar
        button_frame = tk.Frame(right_frame)
        button_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.start_button = tk.Button(button_frame, text="Sniff Başlat", command=self.start_sniffing, bg="green", fg="white", font=("Arial", 10, "bold"))
        self.start_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.stop_button = tk.Button(button_frame, text="Sniff Durdur", command=self.stop_sniffing, bg="red", fg="white", font=("Arial", 10, "bold"))
        self.stop_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.exit_button = tk.Button(button_frame, text="Çıkış", command=root.quit, font=("Arial", 10, "bold"))
        self.exit_button.pack(side=tk.RIGHT, padx=5, pady=5)

        self.selected_interface = self.interface_var.get()
        self.prev_bytes_sent = psutil.net_io_counters(pernic=True)[self.selected_interface].bytes_sent
        self.prev_bytes_recv = psutil.net_io_counters(pernic=True)[self.selected_interface].bytes_recv

        self.monitor_thread = Thread(target=self.update_graph)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def start_sniffing(self):
        iface = self.interface_var.get()
        self.sniffing = True
        self.sniffed_packets = []
        self.packet_display.delete(1.0, tk.END)
        self.geo_display.delete(1.0, tk.END)
        self.hexdump_display.delete(1.0, tk.END)
        sniff_thread = Thread(target=self.sniff_packets, kwargs={"iface": iface})
        sniff_thread.daemon = True
        sniff_thread.start()

    def sniff_packets(self, iface):
        sniff(iface=iface, prn=self.process_packet, stop_filter=lambda x: not self.sniffing)

    def process_packet(self, packet):
        self.sniffed_packets.append(packet)
        packet_info = self.get_packet_info(packet)
        self.packet_display.insert(tk.END, packet_info + "\n")
        self.packet_display.see(tk.END)

        # Coğrafi bilgi güncelleme
        geo_info = self.get_geo_info(packet)
        self.geo_display.delete(1.0, tk.END)
        self.geo_display.insert(tk.END, geo_info)

        # Hexdump güncelleme
        hexdump_info = hexdump(packet, dump=True)
        self.hexdump_display.delete(1.0, tk.END)
        self.hexdump_display.insert(tk.END, hexdump_info)

        # Paket gecikmesi
        time.sleep(self.packet_delay)

    def get_packet_info(self, packet):
        if self.current_mode.get() == 'Özet':
            return packet.summary()
        elif self.current_mode.get() == 'Coğrafi Bilgi':
            return self.get_geo_info(packet)
        elif self.current_mode.get() == 'Protokol Analizi':
            return self.get_protocol_analysis(packet)
        elif self.current_mode.get() == 'Paket İçeriği':
            return self.get_packet_content(packet)

    def get_geo_info(self, packet):
        if IP in packet:
            ip = packet[IP].src
            try:
                response = requests.get(f"https://geolocation-db.com/json/{ip}&position=true").json()
                country = response.get("country_name", "Bilinmiyor")
                city = response.get("city", "Bilinmiyor")
                return f"IP: {ip}\nÜlke: {country}\nŞehir: {city}"
            except:
                return f"IP: {ip}\nCoğrafi bilgi bulunamadı."
        else:
            return "Bu paket IP bilgisi içermiyor."

    def get_protocol_analysis(self, packet):
        analysis = []
        if IP in packet:
            analysis.append(f"IP: {packet[IP].src} -> {packet[IP].dst}")
        if TCP in packet:
            analysis.append(f"TCP: Port {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            analysis.append(f"UDP: Port {packet[UDP].sport} -> {packet[UDP].dport}")
        elif ICMP in packet:
            analysis.append("ICMP")
        return " | ".join(analysis) if analysis else "Bilinmeyen protokol"

    def get_packet_content(self, packet):
        return packet.show(dump=True)

    def stop_sniffing(self):
        self.sniffing = False

    def show_packet_details(self, event):
        if not self.sniffing:
            try:
                selected_packet_index = int(self.packet_display.index(f"@{event.x},{event.y}").split('.')[0]) - 1
                packet = self.sniffed_packets[selected_packet_index]

                detail_window = Toplevel(self.root)
                detail_window.title("Paket Detayları")

                text_display = scrolledtext.ScrolledText(detail_window, height=30, width=80, font=("Consolas", 10))
                text_display.pack()
                text_display.insert(tk.END, packet.show(dump=True))
                text_display.see(tk.END)

            except IndexError:
                messagebox.showerror("Hata", "Geçersiz bir paket seçimi!")
        else:
            messagebox.showwarning("Uyarı", "Lütfen sniff işlemini durdurun ve tekrar deneyin.")

    def change_mode(self, *args):
        self.packet_display.delete(1.0, tk.END)
        for packet in self.sniffed_packets:
            packet_info = self.get_packet_info(packet)
            self.packet_display.insert(tk.END, packet_info + "\n")
        self.packet_display.see(tk.END)

    def change_interface(self, *args):
        self.selected_interface = self.interface_var.get()
        self.prev_bytes_sent = psutil.net_io_counters(pernic=True)[self.selected_interface].bytes_sent
        self.prev_bytes_recv = psutil.net_io_counters(pernic=True)[self.selected_interface].bytes_recv
        self.bytes_sent = []
        self.bytes_recv = []
        self.times = []
        self.start_time = time.time()

    def update_delay(self, value):
        self.packet_delay = float(value) / 1000
        self.delay_value.config(text=f"{int(float(value))} ms")

    def update_graph(self):
        while True:
            current_time = time.time() - self.start_time
            net_io = psutil.net_io_counters(pernic=True)[self.selected_interface]
            
            bytes_sent = net_io.bytes_sent - self.prev_bytes_sent
            bytes_recv = net_io.bytes_recv - self.prev_bytes_recv
            
            self.prev_bytes_sent = net_io.bytes_sent
            self.prev_bytes_recv = net_io.bytes_recv

            self.times.append(current_time)
            self.bytes_sent.append(bytes_sent / 1024 / 1024)  # MB cinsinden
            self.bytes_recv.append(bytes_recv / 1024 / 1024)  # MB cinsinden

            # Son 60 saniyeyi göster
            if len(self.times) > 60:
                self.times = self.times[-60:]
                self.bytes_sent = self.bytes_sent[-60:]
                self.bytes_recv = self.bytes_recv[-60:]

            self.ax.clear()
            self.ax.plot(self.times, self.bytes_sent, label="Gönderilen Veri (MB/s)", color="blue")
            self.ax.plot(self.times, self.bytes_recv, label="Alınan Veri (MB/s)", color="green")
            self.ax.set_title(f"Ağ Trafiği - {self.selected_interface}")
            self.ax.set_xlabel("Süre (saniye)")
            self.ax.set_ylabel("Veri Miktarı (MB/s)")
            self.ax.legend()

            self.canvas.draw()
            time.sleep(1)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketAnalyzerGUI(root)
    root.mainloop()