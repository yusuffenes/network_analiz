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
- <b>Scapy</b> : Ağ paketlerini yakalama ve analiz etme.
- <b>nmap</b>: IP adresi üzerinden port taraması yapma.
- <b>request</b>: IP coğrafi konum bilgilerini almak için HTTP isteği gönderme.
- <b>psutil</b>: Sistem arayüzlerini listelemek için.
- <b>curses</b>: Terminal arayüzü oluşturma.

# Nasıl Kullanılır?
1. Projeyi çalıştırdığınızda, sisteminizde tespit edilen ağ arayüzleri listelenecek ve hangisini kullanmak istediğinizi soracaktır.
2. Arayüz seçildikten sonra, program ağ trafiğini dinlemeye başlayacak.
3. Klavye kısayolları kullanarak paketleri görüntüleyebilir, filtreleri değiştirebilir veya seçili paket üzerinde nmap taraması ve coğrafi sorgulama yapabilirsiniz.

# Klavye Kısayolları:
### Tab: Görüntüleme modları arasında geçiş yapar (Özet, İçerik, Hexdump, Nmap Tarama, Coğrafi Konum).
### r: Otomatik kaydırmayı aç/kapat.
### t/u/a/i: TCP, UDP, ARP, ICMP filtrelerini aç/kapat.
### n: Manuel olarak seçili paket üzerindeki IP adresine nmap taraması yapar.
### q: Programı sonlandırır.




<b>Geliştirici</b>: @yusuffenes

<b>Ders</b>: Bilgisayar Ağları

<b>Tarih</b>: Ekim 2024
