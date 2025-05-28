# 🔐 AES Şifreleme & SHA256 Özet Aracı (Streamlit)

Bu proje, **AES-256 şifreleme/şifre çözme** ve **SHA256 özet (hash) alma** işlemlerini kolayca yapabileceğiniz, Python ve Streamlit ile geliştirilmiş bir web uygulamasıdır.

## 🚀 Özellikler

- **AES-256 ile Metin Şifreleme:** Girilen metni 32 karakterlik bir anahtar ile AES-256 algoritması kullanarak şifreler.
- **AES-256 ile Şifre Çözme:** Şifreli metni ve anahtarı girerek orijinal metni geri elde edebilirsiniz.
- **SHA256 ile Metin Özeti:** Girilen metnin SHA256 özetini (hash) hızlıca oluşturur.
- **SHA256 ile Dosya Özeti:** Yüklediğiniz herhangi bir dosyanın SHA256 özetini hesaplar.
- **Güçlü Anahtar Üretici:** Rastgele ve güçlü AES anahtarı üretir, kolayca kopyalayabilirsiniz.
- **Kullanım İstatistikleri:** Şifreleme, çözme ve anahtar üretme işlemleri sayaçlarla takip edilir.
- **Kullanıcı Dostu Arayüz:** Tüm işlemler sade ve anlaşılır bir arayüzde sunulur.

## 🖥️ Ekran Görüntüsü

> Uygulamanın arayüzü Streamlit ile sade ve kullanışlıdır.

## 🔧 Gereksinimler

Aşağıdaki kütüphanelerin yüklü olması gerekmektedir:

```bash
pip install streamlit pycryptodome
```

## ⚡ Kullanım

1. Proje klasörüne gidin:
    ```bash
    cd aes_sha256_app
    ```
2. Uygulamayı başlatın:
    ```bash
    streamlit run app.py
    ```
3. Tarayıcınızda açılan arayüzden metin/dosya girerek işlemlerinizi gerçekleştirin.

## 📁 Dosya Yapısı

- `app.py` : Uygulamanın ana kodları
- `istatistik.csv` : Kullanım sayaçlarını tutar (otomatik oluşur)
- `README.md` : Proje açıklamaları

## 📌 Notlar

- AES şifreleme için anahtarınız **tam olarak 32 karakter** olmalıdır.
- Şifreli veriyi çözmek için aynı anahtarı kullanmanız gerekir.
- Anahtarınızı güvenli bir yerde saklayın, unutursanız şifreli veriye erişemezsiniz.

## 📝 Lisans

Bu proje eğitim amaçlıdır. Her türlü katkıya açıktır.
