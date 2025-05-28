import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib
import csv
import os

# Sayaçları oku/yaz fonksiyonları
CSV_PATH = "istatistik.csv"

def read_counters():
    if not os.path.exists(CSV_PATH):
        return {"encrypt": 0, "decrypt": 0, "suggested_key": 0}
    with open(CSV_PATH, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            return {
                "encrypt": int(row.get("encrypt", 0)),
                "decrypt": int(row.get("decrypt", 0)),
                "suggested_key": int(row.get("suggested_key", 0))
            }
    return {"encrypt": 0, "decrypt": 0, "suggested_key": 0}

def write_counters(counters):
    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["encrypt", "decrypt", "suggested_key"])
        writer.writeheader()
        writer.writerow(counters)

counters = read_counters()

# Kullanım talimatları
with st.expander("ℹ️ Uygulama Nasıl Kullanılır?"):
    st.markdown("""
**AES Şifreleme & SHA256 Özet Aracı Kullanım Talimatları**

- **Metni girin:** Şifrelemek veya özetini almak istediğiniz metni üstteki kutuya yazın.
- **Şifreleme Anahtarı:** AES-256 için tam 32 karakterlik bir anahtar girin. Anahtarınız 32 karakterden kısa veya uzun olursa işlem yapılmaz.
- **Anahtar Üret:** Eğer güçlü ve rastgele bir anahtar istiyorsanız "Güçlü Anahtar Üret" butonunu kullanabilirsiniz. Üretilen anahtarı kopyalamak için "Kopyala" butonunu kullanın.
- **SHA256 Özetini Al:** Girilen metnin SHA256 özetini almak için bu butona tıklayın.
- **AES ile Şifrele:** Girilen metni ve anahtarı kullanarak AES ile şifrelemek için bu butona tıklayın.
- **AES ile Çöz:** Şifreli metni ve anahtarı girip bu butona tıklayarak şifreli metni çözebilirsiniz.

> **Not:** Anahtarınızı unutmayın! Şifreli veriyi çözmek için aynı anahtara ihtiyacınız olacak.
""")

st.title("🔐 AES Şifreleme & SHA256 Özet Aracı")

# Sekmeler (Tabs)
tab1, tab2 = st.tabs(["AES Şifreleme/Çözme", "SHA256 Özet"])

with tab1:
    # Kullanıcıdan veri al
    text = st.text_area("Metni girin:")

    # Anahtar üretimi ya da kullanıcıdan al
    col1, col2 = st.columns([3,1])
    with col1:
        key_input = st.text_input("Şifreleme Anahtarı (32 karakter - AES-256):", type="password")
    with col2:
        if "random_key" not in st.session_state:
            st.session_state["random_key"] = ""
        if st.button("Güçlü Anahtar Üret"):
            random_key = base64.urlsafe_b64encode(get_random_bytes(32)).decode()[:32]
            st.session_state["random_key"] = random_key
            st.info(f"Önerilen Anahtar: `{random_key}`")
            st.write("Kopyalayıp yukarıdaki alana yapıştırabilirsiniz.")
        if st.session_state["random_key"]:
            st.code(st.session_state["random_key"], language="text")
            if st.button("Kopyala (Önerilen Anahtar)"):
                st.session_state["copied"] = True
                counters["suggested_key"] += 1
                write_counters(counters)
                st.success("Anahtar kopyalandı (panoya kopyalama tarayıcıda otomatik olmaz, elle kopyalayabilirsiniz).")
            else:
                st.session_state["copied"] = False

    if key_input:
        if len(key_input.encode()) != 32:
            st.warning("Anahtar tam olarak 32 byte (256 bit) olmalı!")
            key = None
        else:
            key = key_input.encode()
    else:
        key = None

    # --- Butonları büyütmek için özel CSS ---
    st.markdown("""
        <style>
        .stButton > button {
            font-size: 1.2em !important;
            padding: 0.75em 2em !important;
            margin-bottom: 0.7em !important;
        }
        </style>
    """, unsafe_allow_html=True)

    # AES Şifreleme
    def aes_encrypt(data, key):
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data.encode())
        return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

    # AES Çözme
    def aes_decrypt(enc_data, key):
        try:
            data = base64.b64decode(enc_data.encode())
            nonce = data[:16]
            tag = data[16:32]
            ciphertext = data[32:]
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            return cipher.decrypt_and_verify(ciphertext, tag).decode()
        except Exception as e:
            return f"Hata: {e}"

    # Şifreleme
    if st.button("AES ile Şifrele"):
        if text and key:
            encrypted = aes_encrypt(text, key)
            st.success("Şifrelenmiş Metin:")
            st.code(encrypted, language='text')
            counters["encrypt"] += 1
            write_counters(counters)
        else:
            st.warning("Hem metin hem geçerli bir anahtar girmen lazım.")

    st.markdown("<br>", unsafe_allow_html=True)  # Butonlar arası boşluk

    # Çözme
    enc_input = st.text_area("Çözülecek Şifreli Metin:")
    if st.button("AES ile Çöz"):
        if enc_input and key:
            decrypted = aes_decrypt(enc_input, key)
            st.success("Çözülmüş Metin:")
            st.code(decrypted, language='text')
            counters["decrypt"] += 1
            write_counters(counters)
        else:
            st.warning("Hem şifreli metin hem geçerli bir anahtar girmen lazım.")

with tab2:
    st.markdown("---")  # Alt çizgi ile ayır

    # SHA256 özeti en altta ve sabit gösterim
    if "sha256_result" not in st.session_state:
        st.session_state["sha256_result"] = ""

    sha256_col1, sha256_col2 = st.columns([2,2])
    with sha256_col1:
        sha_text = st.text_area("SHA256 için metin girin:", key="sha256_text")
        if st.button("SHA256 (Metin) Özetini Al"):
            if sha_text:
                hashed = hashlib.sha256(sha_text.encode()).hexdigest()
                st.session_state["sha256_result"] = hashed
            else:
                st.warning("Lütfen önce bir metin girin.")

    with sha256_col2:
        uploaded_file = st.file_uploader("SHA256 için dosya seçin", type=None, key="sha256_file")
        if st.button("SHA256 (Dosya) Özetini Al"):
            if uploaded_file is not None:
                file_bytes = uploaded_file.read()
                file_hash = hashlib.sha256(file_bytes).hexdigest()
                st.session_state["sha256_result"] = file_hash
            else:
                st.warning("Lütfen bir dosya seçin.")

    if st.session_state["sha256_result"]:
        st.info("SHA256 Özeti: ")
        st.code(st.session_state["sha256_result"], language='text')
