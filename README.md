# QS-Tunnel — مستندات فنی نحوه کارکرد

## معماری کلی

QS-Tunnel یک تونل **نامتقارن** است که مسیر رفت و برگشت ترافیک از دو مکانیزم کاملاً متفاوت استفاده می‌کند:

- **مسیر رفت (Client → Server):** داده داخل **DNS Query (UDP/53)** فرستاده می‌شود
- **مسیر برگشت (Server → Client):** داده با **IP Spoofing از طریق Raw Socket** فرستاده می‌شود

این نامتقارن بودن عمدی است — DNS Query تقریباً همیشه از فیلترینگ رد می‌شود، و پکت برگشتی چون Source IP جعلی دارد، قابل ردیابی نیست.

### جریان کلی ترافیک

```
[Xray Client xhttp/h3]
        │ UDP data
        ▼
[QS Client]  ──── DNS Query (UDP/53) ────►  [QS Server]
                                                  │
                                            [Xray Server] ←→ اینترنت آزاد
                                                  │
[QS Client]  ◄─── Raw UDP (IP Spoofed) ────  [QS Server]
        │
        ▼
[Xray Client xhttp/h3]
```

---

## حالت‌های کارکرد

| حالت | `client_id` | توضیح |
|------|------------|-------|
| `1-1` | خالی (`b""`) | یک کلاینت، یک سرور |
| `n-1` | ۷ کاراکتر base32 رندوم | چند کلاینت همزمان به یک سرور |

در حالت `n-1`، مقدار `client_id` نقش **Session Identifier** را دارد و در ابتدای هر پکت قرار می‌گیرد. این مقدار هنگام راه‌اندازی کلاینت به صورت رندوم تولید می‌شود.

---

## ساختار پکت‌های DNS (مسیر رفت)

### دو نوع پکت

#### ۱. Data Packet

حامل داده واقعی از Xray است. محتوای labels در QNAME (بدون domain) به شکل زیر است:

```
[client_id (7 char, فقط در n-1)]
[data_offset (3 char base32)]
[fp_char (1 char base32)]
[magic (1 byte)]
[chunk_data (base32 encoded)]
```

این رشته با `insert_dots` هر `max_sub_len` کاراکتر به یک DNS label تبدیل می‌شود و در نهایت domain اضافه می‌شود.

**فیلد magic چهار حالت دارد:**

| magic | ASCII | fragment_part | last_fragment | توضیح |
|-------|-------|---------------|---------------|-------|
| `'0'` | 48 | fp_val (0–31) | False | تکه میانی، رنج پایین |
| `'1'` | 49 | fp_val (0–31) | True  | تکه آخر، رنج پایین |
| `'8'` | 56 | fp_val\|32 (32–63) | False | تکه میانی، رنج بالا |
| `'9'` | 57 | fp_val\|32 (32–63) | True  | تکه آخر، رنج بالا |

`last_fragment = True` یعنی این آخرین تکه از یک پکت بزرگ است و سرور باید reassembly را کامل کند.

---

#### ۲. Info Packet

حامل اطلاعات ثبت (registration) کلاینت است — **نه داده واقعی.** محتوای labels:

```
[client_id (7 char, فقط در n-1)]
[info_offset (3 char base32)]
["7"]   ← sentinel: fp_char = 31
["8"]   ← sentinel: magic=56 → fragment_part = 63
[encrypted_payload (base32)]
```

سرور با شرط `fragment_part == 63 AND last_fragment == False` این پکت را تشخیص می‌دهد. مقدار `"78"` یک **Sentinel Value** طراحی‌شده است که هرگز در پکت‌های داده معمولی ظاهر نمی‌شود.

---

### محتوای `encrypted_payload` در Info Packet

قبل از encode شدن، ۱۲ بایت خام با XOR رمزگذاری می‌شوند:

```python
bytes_xor(
    my_public_ip (4 bytes)         +   # IP واقعی Client VPS
    wan_main_socket_port (2 bytes) +   # پورت رندوم کلاینت
    fake_send_ip (4 bytes)         +   # IP جعلی برای پکت برگشتی
    fake_send_port (2 bytes)           # Port جعلی برای پکت برگشتی
, sha256(password))
```

| بایت | فیلد | کاربرد در سرور |
|------|------|----------------|
| `[0:4]`   | `client_ip`        | سرور پکت spoofed را به این IP می‌فرستد |
| `[4:6]`   | `client_open_port` | سرور پکت spoofed را به این Port می‌فرستد |
| `[6:10]`  | `fake_send_ip`     | سرور این IP را به عنوان Source IP جعل می‌کند |
| `[10:12]` | `fake_send_port`   | سرور این Port را به عنوان Source Port جعل می‌کند |

**چرا این مقادیر نمی‌توانند از پیش در config سرور تعریف شوند:**

`wan_main_socket_port` هر بار که کلاینت راه‌اندازی می‌شود توسط OS به صورت رندوم تخصیص داده می‌شود. بنابراین کلاینت باید این مقدار را در هر session به سرور اعلام کند.

---

### زمان ارسال Info Packet

کلاینت در دو شرط Info Packet می‌فرستد:

1. **اولین پکت** بعد از راه‌اندازی — سرور هنوز کلاینت را نمی‌شناسد
2. **بیش از ۲۵ ثانیه** از آخرین دریافت پکت از سرور گذشته باشد — session refresh

```python
if (last_wan_recv_time is None) or (loop.time() - last_wan_recv_time > 25):
    contain_info = True
```

---

## پردازش پکت در سرور

### مرحله ۱ — Parse DNS Query

سرور روی پورت `receive_port` (UDP) گوش می‌دهد. پکت ورودی را parse کرده و labels QNAME را استخراج می‌کند. Domain های مجاز (`recv_domains`) از انتهای labels جدا می‌شوند و بقیه به عنوان `data_with_header` پردازش می‌شوند.

### مرحله ۲ — شناسایی Info یا Data

```python
client_id, data_offset, fragment_part, last_fragment, chunk_data = get_chunk_data(data_with_header, ...)

if fragment_part == 63 and not last_fragment:
    # Info Packet
else:
    # Data Packet
```

### مرحله ۳ — Reassembly با DataHandler

اگر یک پکت بزرگ به چند chunk تقسیم شده باشد، سرور آن‌ها را با کلید `data_offset` جمع‌آوری می‌کند. وقتی پکتی با `last_fragment=True` رسید و تعداد fragment‌ها کامل بود، همه با هم base32 decode شده و به Xray فرستاده می‌شوند.

زمان timeout برای reassembly: **13 ثانیه** — پس از آن buffer پاک می‌شود.

### مرحله ۴ — DNS Response

سرور یک **DNS Response خالی** (بدون Answer Record) برمی‌گرداند تا پکت DNS کلاینت بی‌جواب نماند و DPI آن را غیرعادی نبیند.

---

## مسیر برگشت: پکت Spoofed

وقتی Xray server جواب می‌گیرد، سرور با **Raw Socket** و `IP_HDRINCL = 1` یک پکت دستی می‌سازد:

```
IP Header:
  Src IP   = fake_send_ip     ← جعلی (همان که کلاینت در Info Packet خواسته بود)
  Dst IP   = client_ip        ← واقعی کلاینت
  TTL      = 128
  Protocol = UDP (17)

UDP Header:
  Src Port = fake_send_port   ← جعلی
  Dst Port = client_open_port ← پورت رندوم کلاینت
  Checksum = محاسبه‌شده با pseudo-header

Payload:
  داده واقعی از Xray (بدون هیچ encoding اضافی)
```

`ip_id` با یک counter افزایشی (`& 0xFFFF`) مدیریت می‌شود تا هر پکت IP شناسه یکتا داشته باشد.

---

## دریافت پکت Spoofed در کلاینت

کلاینت از یک **Socket معمولی** (`wan_main_socket`) استفاده می‌کند — نه Raw Socket، نه pcap.

این ممکن است چون `nat_keep_alive` هر ۲ ثانیه به `fake_send_ip:fake_send_port` پکت می‌فرستد:

```python
async def nat_keep_alive():
    while True:
        await asyncio.sleep(2)
        data = os.urandom(random.randint(257, 499))
        await loop.sock_sendto(wan_main_socket, data, (fake_send_ip, fake_send_port))
```

این عمل یک **Conntrack Entry** در kernel می‌سازد:

```
src=client_vps_ip  dst=fake_send_ip  sport=wan_port  dport=fake_port  [ESTABLISHED]
```

حالا وقتی پکت برگشتی از سرور با `src=fake_send_ip:fake_send_port` می‌رسد، kernel آن را به عنوان **Reply** همان flow می‌شناسد و مستقیم به `wan_main_socket` تحویل می‌دهد.

> **نکته:** این مکانیزم برای VPS بدون NAT هم لازم است، چون iptables با `ESTABLISHED,RELATED` پکت‌های ناشناخته را drop می‌کند.

---

## جریان کامل End-to-End

```
[Xray Client xhttp/h3]
        │ UDP data
        ▼
[QS Client - h_recv()]
  1. base32 encode data
  2. chunk به اندازه max_sub_len
  3. اضافه کردن header: [client_id][offset][fp_char][magic]
  4. insert_dots → DNS labels
  5. ساخت DNS Query (UDP/53)
        │
        ▼  DNS Query → dns_ip:53
        │
[QS Server - wan_recv()]
  1. parse DNS Question → labels
  2. join labels → data_with_header
  3. get_chunk_data → extract fields
  4. اگر fragment_part==63: Info Packet
     → ذخیره client_ip, port, spoof_ip, spoof_port در active_clients
  5. اگر Data Packet: DataHandler.assemble
  6. base32 decode → send به Xray server
  7. DNS Response خالی → کلاینت
        │
        ▼
[Xray Server xhttp/h3]  ←→  اینترنت آزاد
        │ response data
        ▼
[QS Server - client_h_recv()]
  1. build_udp_payload_v4(data, spoof_src_port, client_port)
  2. build_ipv4_header(src=fake_ip, dst=client_ip, TTL=128)
  3. raw_sender_sock.sendto
        │
        ▼  Raw UDP (IP Spoofed)
        │
[QS Client - wan_recv()]
  conntrack → wan_main_socket دریافت می‌کند
        │
        ▼
[Xray Client xhttp/h3]
```

---

## خلاصه نکات کلیدی طراحی

| چالش | راه‌حل |
|------|--------|
| چند کلاینت همزمان | `client_id` رندوم ۷ کاراکتری در مد `n-1` |
| پکت‌های بزرگتر از ظرفیت یک DNS Query | Chunking + `fragment_part` + `data_offset` |
| Session refresh بعد از قطعی | Info Packet اگر ۲۵ ثانیه پاسخی نباشد |
| تغییر IP/Port کلاینت | Info Packet مقادیر را در `active_clients` به‌روز می‌کند |
| Conntrack/NAT عبور | `nat_keep_alive` هر ۲ ثانیه پکت می‌فرستد |
| امنیت Info Packet | XOR با `sha256(password)` |
| یکتا بودن IP ID در Raw packets | Counter افزایشی با `& 0xFFFF` |
| پورت رندوم کلاینت | از طریق Info Packet به سرور اعلام می‌شود |
