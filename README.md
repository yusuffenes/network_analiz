# Paket Analiz Aracı

Bu proje, Bilgisayar Ağları dersi ödevi kapsamında geliştirilmiştir.
Ağ trafiğini izlemek, analiz etmek ve çeşitli protokolleri (TCP, UDP, ARP, ICMP) filtrelemek için basit bir Paket Analiz Aracıdır.
Kullanıcılar, gerçek zamanlı olarak paketleri görüntüleyebilir, nmap ile port taraması yapabilir ve IP tabanlı coğrafi konum bilgilerini sorgulayabilir.

# Projenin Amacı
Bu proje ile ağ trafiği üzerinde canlı bir analiz yapılabilmesi, belirli protokol filtreleri ile istenen paketlerin izlenmesi ve incelemelerin interaktif bir terminal arayüzü üzerinden yönetilmesi hedeflenmiştir. Ayrıca, seçilen IP adresleri üzerinde otomatik veya manuel nmap taraması yapma ve IP coğrafi bilgilerini sorgulama özellikleri eklenmiştir.

# Gereksinimler
Proje aşağıdaki Python modüllerini kullanmaktadır. Gerekli kütüphaneleri yüklemek için şu komutu kullanabilirsiniz:
```
pip install scapy nmap requests psutil curses
```
- Scapy: Ağ paketlerini yakalama ve analiz etme.
- nmap: IP adresi üzerinden port taraması yapma.
- requests: IP coğrafi konum bilgilerini almak için HTTP isteği gönderme.
- psutil: Sistem arayüzlerini listelemek için.
- curses: Terminal arayüzü oluşturma.
