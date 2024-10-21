# Gelişmiş Paket Analiz Aracı
Bu proje, Python kullanarak ağ trafiğini izlemek ve analiz etmek için geliştirilmiş bir paket analiz aracıdır. Kullanıcı dostu bir arayüze sahip olan bu araç, farklı ağ arayüzlerini seçerek canlı ağ trafiğini izleme, protokol bazlı analiz yapma, paketlerin içeriklerini görüntüleme ve coğrafi bilgi elde etme gibi çeşitli işlevleri destekler.

# Özellikler
- ### Canlı Ağ Trafiği İzleme: Seçilen ağ arayüzünde paketleri canlı olarak yakalar.
- ### Protokol Analizi: IP, TCP, UDP, ICMP gibi farklı protokollerdeki paketleri analiz eder.
- ### Paket İçeriği Görüntüleme: Paket içeriklerini hexdump formatında detaylı olarak gösterir.
- ### Coğrafi Bilgi Sorgulama: IP adresine dayalı coğrafi bilgileri (ülke ve şehir) gösterir.
- ### Paket Gecikmesi Ayarı: Kullanıcı, paket yakalama sürecinde gecikme süresini belirleyebilir.
- ### Ağ Trafiği Grafiği: Seçilen arayüzde geçen veri miktarını (MB/s) grafiksel olarak gösterir.

# Gereksinimler
Bu proje aşağıdaki Python kütüphanelerini kullanmaktadır:
- tkinter
- scapy
- psutil
- requests
- matplotlib
Bu kütüphaneleri kurmak için aşağıdaki komutu çalıştırabilirsiniz:
```
pip install scapy psutil requests matplotlib
```
# Kullanım
1. Projeyi yerel makinenize klonlayın:

```
git clone https://github.com/kullanici_adi/gelismis-paket-analiz-araci.git
```
2. Gereksinimleri kurduktan sonra, main.py dosyasını çalıştırın:
```
python main.py
```
3. Uygulama arayüzü açıldığında, bir ağ arayüzü seçin ve sniff işlemini başlatmak için "Sniff Başlat" butonuna basın.
4. Paket analizini durdurmak için "Sniff Durdur" butonuna basabilirsiniz.
5. Canlı ağ trafiğini görsel olarak izlemek için soldaki grafik alanını kullanabilirsiniz.


<b>Geliştirici</b>: @yusuffenes

<b>Ders</b>: Bilgisayar Ağları

<b>Tarih</b>: Ekim 2024
