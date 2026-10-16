<div align="center">
  <img src="assets/noxtrace.svg" width="210" alt="NOXTRACE: elektrik mavisi kuru kafa ve yılan amblemi" />
  <br />
  <img src="assets/noxtrace-intro.gif" width="780" alt="NOXTRACE için özgün, animasyonlu cyber-fox skull açılışı" />

  <h1>NOXTRACE</h1>
  <p><strong>Tek komut. Çoklu motor. Daha net bir güvenlik görünümü.</strong></p>
  <p>İzinli ağ denetimi, web yapılandırma incelemesi, yerel adli analiz ve raporlama için modüler bir siber güvenlik çalışma istasyonu.</p>

  <p>
    <img alt="Python 3.10+" src="https://img.shields.io/badge/Python-3.10%2B-60A5FA?logo=python&logoColor=white" />
    <img alt="MIT License" src="https://img.shields.io/badge/License-MIT-64748B.svg" />
    <img alt="Core runtime dependencies none" src="https://img.shields.io/badge/Core%20runtime%20dependencies-None-334155.svg" />
    <a href="https://github.com/raxwqx/NOXTRACE/actions/workflows/tests.yml"><img alt="Tests" src="https://github.com/raxwqx/NOXTRACE/actions/workflows/tests.yml/badge.svg?branch=main" /></a>
  </p>
  <p><code>Python · Go · Rust · C · Java · Bash</code></p>
  <p><a href="README_EN.md">🇬🇧 Read in English</a></p>
</div>

---

## 🌑 NOXTRACE nedir?

**NOXTRACE**, tek bir terminal komutuyla açılan, farklı analiz modüllerini bir araya getiren bir güvenlik aracıdır. Amacı, her işi yaptığını iddia eden dev bir program olmak değil; her modülün ne yaptığını, neye dokunduğunu ve ne bulduğunu açıkça anlatan, test edilebilir bir çalışma ortamı sunmaktır.

Arayüz siyah, beyaz ve grafit tonlarına elektrik mavisi vurgular ekler. Etkileşimli menü açılmadan önce internet gerektirmeyen kısa bir terminal animasyonu oynatılır. Python ana uygulamadır; Go, Rust, C, Java ve Bash bileşenleri belirli görevler için kullanılabilen yardımcı motorlardır.

> [!IMPORTANT]
> **Yalnızca kendi sistemlerinde veya açık iznin olan hedeflerde etkin denetim yap.** NOXTRACE; DDoS saldırısı, gizlenme/evasion, parola deneme saldırısı, kimlik bilgisi hırsızlığı veya otomatik açık istismarı içermez.

## 👀 Önce nasıl göründüğüne bak

### Animasyonlu açılış

Program açılırken terminalde ayrı bir açılış animasyonu oynar. README'de görünen GIF önizlemesidir; gerçek terminal animasyonu paketin içindeki önceden hazırlanmış ANSI karelerinden oynatılır. Dolayısıyla GIF oynatıcı, Pillow veya internet bağlantısı gerekmez.

### Terminal menüsü

![NOXTRACE etkileşimli terminal menüsü](assets/screenshots/menu.png)

### IP Intelligence çıktısı

![NOXTRACE IP Intelligence komutundan yakalanan terminal çıktısı](assets/screenshots/ip-intelligence.png)

### Yerel makinede sınırlandırılmış port kontrolü

![NOXTRACE yalnızca 127.0.0.1 üzerindeki örnek TCP port kontrolü](assets/screenshots/local-port-scan.png)

<sub>Görseller gerçek NOXTRACE komutlarının çıktılarından hazırlanmıştır. IP ve tarama sonuçları örnek çalıştırmaya aittir; başka bir bilgisayarda sonuçlar farklı olabilir. Port tarama örneği yalnızca yerel döngü adresi olan <code>127.0.0.1</code> üzerinde çalıştırılmıştır.</sub>

## ✨ Özellikler

| Modül | Ne yapar? | Ağ bağlantısı kurar mı? |
| --- | --- | --- |
| **IP Intelligence** | IPv4/IPv6 adresini global, özel, loopback, link-local, multicast, reserved gibi sınıflara ayırır. İstenirse ters DNS (PTR) sorgusu yapar. | Sınıflandırma yereldir; PTR yalnızca açıkça istenirse sorgulanır. |
| **DNS Intelligence** | A ve AAAA kayıtlarını sistem çözümleyicisiyle sorgular. İsteğe bağlı `dnspython` eklentisiyle MX, NS, TXT ve CNAME kayıtlarını da sorabilir. | Evet, DNS sorgusu yapılandırılmış çözümleyiciye gider. |
| **Domain Validator** | Domain/hostname biçimini ve IDN normalizasyonunu çevrimdışı kontrol eder. | Hayır. |
| **URL Inspector** | URL biçimini inceler ve bazı şüpheli sözdizimi işaretlerini belirtir; siteyi açmaz. | Hayır. |
| **Bounded TCP Scan** | Seçilen TCP portlarına sınırlandırılmış bağlantı kontrolleri yapar. En fazla 256 port ve 32 eşzamanlı iş parçacığı. | Evet; `--authorized` onayı zorunludur. |
| **Web Header Audit** | Tek bir HTTP `HEAD` isteğiyle temel güvenlik başlıklarını ve çerez bayraklarını inceler. Yönlendirme izlemez, saldırı yükü göndermez. | Evet; izin onayı zorunludur. |
| **TLS Inspection** | Sertifikayı yerel güven deposuna göre doğrular; TLS sürümü ve bağlantı parametrelerini raporlar. | Evet; izin onayı zorunludur. |
| **File Fingerprint** | Yerel dosyanın SHA-256, SHA-512 ve BLAKE2b özetlerini hesaplar. | Hayır; dosya değiştirilmez ve yüklenmez. |
| **Log Triage** | Yerel loglarda gözden geçirilmeye değer örüntüleri arar; tam log satırları yerine kural ve satır numarası raporlar. | Hayır. |
| **Source Code Audit** | Kaynak kodunda riskli olabilecek yaygın örüntüleri çevrimdışı tarar. | Hayır; kaynak kodu dışarı gönderilmez. |
| **Java/Maven Review** | Yerel `pom.xml` dosyasındaki bağımlılıkları listeler. Bu tek başına CVE taraması değildir. | Hayır. |
| **OSV Package Check** | Belirtilen tek paket/sürüm için herkese açık OSV güvenlik kayıtlarını sorgular. | Yalnızca `--online` ile açıkça onaylanırsa; paket koordinatları OSV.dev'e gider. |
| **IOC Classifier** | IP, domain, URL veya hash benzeri girdiyi çevrimdışı biçim olarak sınıflandırır. | Hayır; itibar servisine başvurmaz. |
| **Password Test Audit** | Yerel bir test ifadesinin uzunluk ve karakter çeşitliliğini tahmin eder; girilen değeri rapora koymaz. | Hayır. Gerçek veya tekrar kullanılan parolanı girme. |
| **Case Notes & Reports** | Araştırmacı notlarını yapılandırır; terminal, JSON ve bağımsız HTML raporu üretir. | Rapor dosyaları yerel olarak yazılır. |
| **Polyglot Engines** | Go TCP taraması, Rust klasik-PCAP envanteri, C sistem özeti, Java Maven envanteri ve Bash laboratuvar kontrolü. | Seçilen motora bağlıdır; bazıları tamamen yereldir. |

**Önemli:** Eksik bir HTTP başlığı, açık bir port veya kodda eşleşen bir örüntü tek başına doğrulanmış bir güvenlik açığı değildir. Sonuçlar, insan tarafından incelenmesi gereken ipuçlarıdır. Hiçbir araç bütün güvenlik açıklarını bulmayı garanti edemez.

## 🧰 Gereksinimler

### Temel sürüm

- Kali Linux veya başka bir Linux dağıtımı. Diğer işletim sistemleri ek uyarlama gerektirebilir.
- Python **3.10 veya daha yeni**.
- ZIP kurulumunda `unzip`; Git üzerinden indirmek için `git`.
- Temel Python CLI için zorunlu üçüncü taraf çalışma zamanı paketi yoktur.

Python sürümünü kontrol et:

```bash
python3 --version
```

### İsteğe bağlı motorlar

| Araç | Ne zaman gerekir? |
| --- | --- |
| `dnspython` | MX, NS, TXT ve CNAME gibi daha geniş DNS kayıt desteği için. |
| Go | Go tabanlı TCP tarayıcı motoru için. |
| Rust + Cargo | Klasik PCAP dosyalarını inceleyen Rust motoru için. Bu motor PCAPNG desteği iddia etmez. |
| C derleyicisi (`cc`) | C tabanlı yerel sistem özeti için. |
| Java 11+ | Java kaynak dosyasını doğrudan çalıştıran Maven envanter motoru için. |
| İnternet erişimi | İsteğe bağlı OSV güvenlik kaydı sorgusu ve `./install.sh --dns` ile eklenti kurulumu için. |

İsteğe bağlı diller kurulu değilse ana Python arayüzü çalışmaya devam eder.

## 🚀 Kurulum: Kali Linux'ta adım adım

İki basit yol var: ZIP indirmek veya Git ile depoyu klonlamak. İlk kez kullanıyorsan **ZIP yöntemi** en kolay seçenek.

### Yöntem A — ZIP indirip açmak

**1.** GitHub'daki NOXTRACE deposuna git ve **Code → Download ZIP** seçeneğiyle projeyi indir. Alternatif olarak, bu projenin dağıtım ZIP'i verildiyse onu indir.

**2.** Terminali aç. İndirme klasöründeki `NOXTRACE.zip` dosyasını `~/projeler` altına çıkar:

```bash
mkdir -p ~/projeler
unzip ~/İndirilenler/NOXTRACE.zip -d ~/projeler
cd ~/projeler/NOXTRACE
```

> Dosyan `NOXTRACE (1).zip` gibi başka bir adla indiyse komutta gerçek dosya adını kullan. İngilizce sistemlerde klasör adı `~/Downloads` olabilir.

**3.** Başlatıcı dosyalarına çalıştırma izni ver:

```bash
chmod +x ./noxtrace ./install.sh
```

**4.** Aracı başlat:

```bash
./noxtrace
```

Animasyon oynatılır ve ardından numaralı menü açılır. Herhangi bir kurulum yapmadan da temel CLI çalışır.

### Yöntem B — `noxtrace` komutunu her klasörden kullanmak

Proje klasöründeyken şunu çalıştır:

```bash
./install.sh
```

Bu betik `~/.local/bin/noxtrace` adlı küçük bir başlatıcı oluşturur. Ardından yeni bir terminal açıp şunu yazabilirsin:

```bash
noxtrace
```

Eğer `command not found` hatası alırsan, `~/.local/bin` klasörünün PATH içinde olması gerekir. Kali'nin Zsh kabuğunda aşağıdaki satırı `~/.zshrc` dosyasına ekle:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Tekrar dene:

```bash
noxtrace --version
noxtrace
```

> **Not:** `./install.sh` temel CLI için sanal ortam veya paket indirmez. `./install.sh --dns` seçeneği ise isteğe bağlı DNS kayıtları için proje klasöründe `.venv` oluşturur ve internetten `dnspython` yükler.

### Yöntem C — Git ile indirmek

Depo GitHub'a yüklendikten sonra şu komutlarla kaynak kodunu indirebilirsin:

```bash
mkdir -p ~/projeler
cd ~/projeler
git clone https://github.com/raxwqx/NOXTRACE.git
cd NOXTRACE
./install.sh
noxtrace
```

Projeyi daha sonra güncellemek için:

```bash
cd ~/projeler/NOXTRACE
git pull
```

## 🎮 Kullanım rehberi

### Arayüzü açmak

```bash
# Proje klasöründeyken
./noxtrace

# install.sh çalıştırıldıysa, herhangi bir klasörden
noxtrace
```

Menüde istediğin seçeneğin numarasını yazıp `Enter` tuşuna bas. Çıkmak için `18` seçeneğini kullan.

Animasyonu atlamak için:

```bash
./noxtrace --no-intro
# veya
noxtrace --no-intro
```

Açılış animasyonunu bir oturum boyunca kapatmak için:

```bash
NOXTRACE_NO_INTRO=1 noxtrace
```

### 1. IP adresini incelemek

```bash
noxtrace ip 8.8.8.8
```

Bu komut IP adresinin sınıfını **yerel olarak** belirler. Gerçek ters DNS kaydı da sorgulansın istiyorsan `--ptr` ekle:

```bash
noxtrace ip 8.8.8.8 --ptr
```

`--ptr` DNS sorgusu yapabilir; normal IP sınıflandırması harici itibar veya konum servisine bağlanmaz.

### 2. DNS kayıtlarını sorgulamak

```bash
noxtrace dns example.com --types A AAAA
```

MX, NS, TXT ve CNAME kayıtları için önce opsiyonel DNS desteğini kur:

```bash
./install.sh --dns
noxtrace dns example.com --types A AAAA MX NS TXT CNAME
```

DNS sorgularının yapılandırılmış çözümleyicin tarafından görülebileceğini unutma.

### 3. Domain ve URL biçimini kontrol etmek

```bash
# Çevrimdışı domain biçimi kontrolü
noxtrace domain example.com

# URL biçimi incelemesi; sayfayı açmaz
noxtrace url 'https://example.com/login?campaign=test'
```

URL Inspector linki ziyaret etmez, yönlendirme izlemez ve URL'ye saldırı yükü göndermez.

### 4. TCP port kontrolü

Yalnızca kendi bilgisayarında veya test laboratuvarında dene:

```bash
noxtrace scan 127.0.0.1 --ports 22,80,443 --timeout 0.2 --authorized
```

`--authorized`, hedefi yönetme hakkın veya açık iznin olduğunu onaylar. Araç en fazla 256 portu ve 32 eşzamanlı bağlantıyı sınırlar. Yalnızca TCP bağlantı kontrolü yapar; UDP taraması veya servis istismarı yapmaz. **Açık port, otomatik olarak güvenlik açığı demek değildir.**

### 5. Web başlıkları ve TLS

Aşağıdaki örneklerde `YOUR-LAB-HOST` alanını kendi laboratuvarındaki veya açıkça izin aldığın hedefle değiştir:

```bash
noxtrace web-audit https://YOUR-LAB-HOST --authorized
noxtrace tls YOUR-LAB-HOST --port 443 --authorized
```

Web denetimi bir `HEAD` isteği gönderir ve yönlendirmeleri izlemez. TLS denetimi sertifika doğrulaması ile bağlantı parametrelerini raporlar. Bu komutlar ağ bağlantısı kurduğu için izinsiz hedeflerde çalıştırılmamalıdır.

### 6. Dosya hash'i hesaplamak

```bash
noxtrace hash ./examples/sample.log
```

Hash'ler dosyayı değiştirmeden, yerel olarak hesaplanır. Dosya internet üzerinden gönderilmez.

### 7. Yerel log veya kaynak kodunu incelemek

```bash
# Log dosyasındaki seçilmiş göstergeleri incele
noxtrace log ./examples/sample.log

# Kaynak kodunda yaygın riskli örüntüleri ara
noxtrace code-audit ./src
```

Bunlar statik kontrollerdir. Eşleşmeler yanlış pozitif olabilir; hiçbir eşleşme bulunmaması da kodun güvenli olduğunu kanıtlamaz. Log incelemesi tam satır içeriğini rapora kopyalamamaya çalışır.

### 8. Java/Maven bağımlılıklarını listelemek

```bash
noxtrace pom-audit ./examples/pom-sample.xml
```

Bu işlem `pom.xml` içindeki bağımlılıkları envantere alır ve elle incelemeye yardımcı olur. Kendi başına tüm CVE'leri doğrulayan bir tarayıcı değildir.

### 9. OSV ile bilinen paket zafiyetlerini sorgulamak

Bu özellik internet kullanır ve açık onay gerektirir. Örnek olarak aşağıdaki sorgu `requests` paketinin `2.31.0` sürümünü OSV.dev'e sorar:

```bash
noxtrace osv-check requests 2.31.0 --ecosystem PyPI --online
```

Yalnızca paket adı, sürüm ve ekosistem bilgisi gönderilir. Bir kaydın eşleşmesi, o paketin senin uygulamanda mutlaka istismar edilebilir olduğunu kanıtlamaz.

### 10. IOC biçimi, parola test denetimi ve vaka notları

```bash
# IP/domain/URL/hash biçimi sınıflandırma
noxtrace ioc 8.8.8.8

# Gerçek parolanı kullanma; test için uydurma bir ifade gir
noxtrace password-audit

# Araştırma gözlemini düzenli bir rapora dönüştür
noxtrace case-note lab-01 'Test servisi beklenen sonucu verdi'
```

Parola denetiminde değer girerken terminalde gizli giriş istemi görünür. Yine de **gerçek veya başka yerde kullandığın parolayı yazma**. Bu kontrol parola kırmaz, parola listesi denemez ve değeri raporda saklamaz.

## 📄 JSON ve HTML raporları

Çoğu analiz komutu çıktıyı terminalde gösterebilir, JSON olarak yazabilir veya bağımsız HTML raporu oluşturabilir.

```bash
mkdir -p reports

# JSON'u ekrana yaz
noxtrace ip 8.8.8.8 --json

# JSON'u dosyaya kaydet
noxtrace dns example.com --types A AAAA --output reports/dns.json

# HTML raporu üret (yalnızca yetkili bir hedefte)
noxtrace web-audit https://YOUR-LAB-HOST --authorized --html reports/web-audit.html
```

Raporları paylaşmadan önce gözden geçir. Hedef adresi, dosya yolu veya kendi girdiğin araştırma notları gibi bilgiler içerebilirler. `reports/` klasörünü ve rapor dosyalarını paylaşma kararı sana aittir.

## 🧬 Çok dilli motorlar (Python, Go, Rust, C, Java, Bash)

Python ana komut satırı ve modül yöneticisidir. Diğer diller süs olsun diye eklenmedi; her biri ayrı bir görev üstlenir.

| Dil | Motorun görevi | Komut |
| --- | --- | --- |
| **Python** | Ana CLI, analiz modülleri ve raporlama | `noxtrace --help` |
| **Go** | Sınırlandırılmış TCP bağlantı taraması | `noxtrace engine go-scan 127.0.0.1 22,80,443 --authorized` |
| **Rust** | Klasik PCAP dosyasının çevrimdışı meta veri incelemesi | `noxtrace engine rust-pcap ./examples/empty.pcap` |
| **C** | Yerel işletim sistemi özeti | `noxtrace engine c-system` |
| **Java** | Yerel Maven bağımlılık envanteri | `noxtrace engine java-pom ./examples/pom-sample.xml` |
| **Bash** | Yerel laboratuvar ve araçların hazır olup olmadığı | `noxtrace engine bash-check` |

Kurulu araçları kontrol et:

```bash
noxtrace engines
noxtrace engine bash-check
```

Go ve C ikilileri ihtiyaç duyulduğunda oluşturulur. Rust motoru Cargo gerektirir; Java motoru en iyi JDK 11+ ile çalışır. İsteğe bağlı derleyicilerin eksik olması, Python CLI'ın çalışmasını engellemez.

## 🧪 Testleri çalıştırmak

Proje klasöründe:

```bash
./scripts/check-all.sh
```

Bu betik Python derleme kontrolünü ve birim testlerini çalıştırır; kurulu olduklarında Go, C, Java ve Rust motorlarının kontrollerini de dener. Bir dil aracı bilgisayarında kurulu değilse o motor için kontrol atlanır. Python testlerini tek başına çalıştırmak için:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

GitHub Actions yapılandırması Python testlerini ve polyglot motorlarının temel kontrollerini otomatik çalıştırmak üzere `/.github/workflows/tests.yml` altında bulunur.

## 🗂️ Proje yapısı

```text
NOXTRACE/
├── assets/
│   ├── noxtrace.svg
│   ├── noxtrace-intro.gif
│   └── screenshots/             # README'de kullanılan terminal görüntüleri
├── docs/                        # Metodoloji ve işletim notları
├── engines/
│   ├── bash/                    # Yerel laboratuvar kontrolü
│   ├── c/                       # Yerel sistem özeti
│   ├── go/                      # TCP bağlantı motoru
│   ├── java/                    # Maven envanteri
│   └── rust/                    # Klasik PCAP meta veri incelemesi
├── examples/                    # Güvenli örnek log/POM/PCAP dosyaları
├── scripts/                     # Kontrol ve test betikleri
├── src/noxtrace/
│   ├── modules/                 # Bağımsız analiz modülleri
│   ├── intro.py                 # Açılış animasyonu oynatıcı
│   ├── intro_frames.ansi        # Çevrimdışı terminal animasyonu kareleri
│   ├── cli.py                   # Komutlar ve etkileşimli menü
│   ├── reporting.py             # JSON/HTML raporlama
│   └── ui.py                    # Koyu tema ve terminal bileşenleri
├── tests/
├── install.sh
├── noxtrace                     # Proje içinden çalışan başlatıcı
├── pyproject.toml
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── README.md
└── README_EN.md
```

## 🧯 Sorun giderme

### `python3: command not found`

Python 3 kurulu değilse Kali'de şunu çalıştırabilirsin:

```bash
sudo apt update
sudo apt install python3
```

### `unzip: command not found`

```bash
sudo apt install unzip
```

### `Permission denied: ./noxtrace`

Proje klasöründe:

```bash
chmod +x ./noxtrace ./install.sh
```

### `noxtrace: command not found`

Önce `./install.sh` çalıştır. Sonra gerekirse `~/.local/bin` yolunu `PATH` ortam değişkenine ekle (kurulum bölümündeki örnek). Proje klasöründen `./noxtrace` her zaman alternatif başlatıcıdır.

### Animasyon görünmüyor

Dar terminal penceresi, `NO_COLOR` değişkeni veya `TERM=dumb` gibi ortam ayarları animasyonu devre dışı bırakabilir. Menüye doğrudan geçmek için `./noxtrace --no-intro` kullanabilirsin. Animasyonun çalışmaması ana analiz modüllerini etkilememelidir.

### Go/Rust/C/Java motoru çalışmıyor

İlgili dilin çalışma zamanı veya derleyicisi kurulu olmayabilir. `noxtrace engines` komutuyla kontrol et. Eksik isteğe bağlı motorlar için Python komutları kullanılmaya devam edilebilir.

## 🔐 Gizlilik, güvenli kullanım ve sınırlar

- Ağ bağlantısı kuran komutları sadece kendi sistemlerinde veya açık izin verilen hedeflerde çalıştır.
- Port taraması üst sınırları ve işçi sayısı ile sınırlandırılmıştır.
- Web denetimi tek bir `HEAD` isteği gönderir; yönlendirme izlemez ve saldırı yükü eklemez.
- DNS sorguları yapılandırılmış sistem çözümleyicisini kullanır.
- Dosya hash'leri ve kaynak kodu incelemesi yerel çalışır; dosyalar yüklenmez.
- OSV sorgusu yalnızca açıkça `--online` verildiğinde seçilen paket koordinatlarını OSV.dev'e gönderir.
- Parola denetimini yalnızca uydurma/test değeriyle kullan.
- Raporlarda kişisel veya gizli bilgiler bulunup bulunmadığını paylaşmadan önce kontrol et.
- Bu proje DDoS, gizlenme, kimlik bilgisi çalma veya otomatik açık istismarı gerçekleştirmez.
- Heuristik bulgular uzman incelemesi gerektirir; temiz sonuç, sistemin tamamen güvenli olduğunu göstermez.

Daha fazla bilgi: [SECURITY.md](SECURITY.md), [docs/methodology.md](docs/methodology.md) ve [docs/operations.md](docs/operations.md).

## 🤝 Katkıda bulunmak

Yeni modüller küçük, test edilebilir ve dokümante edilmiş olmalı. Her yeni özellik hangi veriye eriştiğini, ağ bağlantısı kurup kurmadığını, sınırlarını ve hata durumlarını açıklamalıdır. Ayrıntılar için [CONTRIBUTING.md](CONTRIBUTING.md) dosyasına bak.

## 📜 Lisans

NOXTRACE, [MIT lisansı](LICENSE) ile yayımlanır.

<div align="center">
  <strong>NOXTRACE</strong><br />
  <sub>Ne kontrol edildiğini bil. Nelerin kontrol edilmediğini de bil. 🖤🔵</sub>
</div>
