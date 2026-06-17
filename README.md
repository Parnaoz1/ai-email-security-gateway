# AI Email Security Gateway

## პროექტის აღწერა

AI Email Security Gateway წარმოადგენს ქცევაზე დაფუძნებულ ელფოსტის საფრთხეების აღმოჩენისა და რეაგირების პლატფორმას.

სისტემა ავტომატურად იღებს ელფოსტებს Gmail-დან, აანალიზებს მათ სხვადასხვა უსაფრთხოების კრიტერიუმის მიხედვით, აფასებს რისკის დონეს და უსაფრთხოების ადმინისტრატორს აძლევს შესაბამისი რეაგირების შესაძლებლობას ვებ-დეშბორდის საშუალებით.

---

## ძირითადი ფუნქციონალი

### ელფოსტის მიღება

სისტემა:

- უკავშირდება Gmail-ს IMAP პროტოკოლით;
- ამოწმებს შემოსულ წერილებს ავტომატურად;
- ამუშავებს Inbox და Spam საქაღალდეებს.

### საფრთხეების ანალიზი

ელფოსტა მოწმდება შემდეგი კრიტერიუმებით:

- Header-ის ანომალიები;
- Reply-To მისამართის შეუსაბამობა;
- Return-Path მისამართის შეუსაბამობა;
- SPF შემოწმება;
- DKIM შემოწმება;
- DMARC შემოწმება;
- საეჭვო საკვანძო სიტყვები;
- საშიში ბმულები;
- საეჭვო მიმაგრებული ფაილები;
- გამომგზავნის რეპუტაცია;
- AI მოდელის შეფასება.

### რისკის ქულის გამოთვლა

თითოეულ წერილს ენიჭება რისკის ქულა 0-დან 100-მდე.

საბოლოო გადაწყვეტილებებია:

- SAFE
- SPAM
- QUARANTINE
- DELETE

### ვებ-დეშბორდი

დეშბორდის საშუალებით შესაძლებელია:

- წერილების მონიტორინგი;
- რისკის ქულის ნახვა;
- აღმოჩენილი მიზეზების ნახვა;
- წერილის დეტალების დათვალიერება;
- უსაფრთხოების ქმედებების განხორციელება.

### რეაგირების მექანიზმები

ადმინისტრატორს შეუძლია:

- Mark Safe
- Move To Spam
- Quarantine
- Delete
- Block Sender
- Block Domain

### მოქმედებების ლოგირება

სისტემა ინახავს ყველა შესრულებული მოქმედების ისტორიას:

- ვინ რა გადაწყვეტილება მიიღო;
- რომელი წერილის მიმართ განხორციელდა ქმედება;
- შესრულების დრო.

### VirusTotal ინტეგრაცია

სისტემა იყენებს VirusTotal API-ს დამატებითი ანალიზისთვის და ცნობილი საფრთხეების იდენტიფიცირებისთვის.

---

## სისტემის არქიტექტურა

```
Gmail Inbox
     │
     ▼
Email Receiver
     │
     ▼
Threat Analyzer
     │
     ▼
Risk Scoring Engine
     │
     ▼
SQLite Database
     │
     ▼
Web Dashboard
     │
     ▼
Security Actions
```

---

## გამოყენებული ტექნოლოგიები

### Backend

- Python 3
- FastAPI
- SQLite

### უსაფრთხოების მექანიზმები

- SPF Validation
- DKIM Validation
- DMARC Validation
- VirusTotal API

### Frontend

- HTML
- CSS

### ინფრასტრუქტურა

- Gmail IMAP
- GitHub

---

## პროექტის სტრუქტურა

```
ai-email-security-gateway/

├── main.py
├── email_receiver.py
├── analyzer.py
├── ai_model.py
├── database.py
├── reputation.py
├── virustotal.py
├── .gitignore
└── README.md
```

---

## ინსტალაცია

### რეპოზიტორიის ჩამოტვირთვა

```bash
git clone https://github.com/Parnaoz1/ai-email-security-gateway.git
cd ai-email-security-gateway
```

### ვირტუალური გარემოს შექმნა

```bash
python -m venv .venv
```

### ვირტუალური გარემოს გააქტიურება

Windows:

```bash
.venv\Scripts\activate
```

Linux:

```bash
source .venv/bin/activate
```

### საჭირო ბიბლიოთეკების დაყენება

```bash
pip install fastapi uvicorn python-dotenv requests python-multipart itsdangerous scikit-learn
```

### .env ფაილის კონფიგურაცია

```env
GMAIL_EMAIL=your_email@gmail.com
GMAIL_APP_PASSWORD=your_app_password
VT_API_KEY=your_virustotal_api_key
CHECK_INTERVAL_SECONDS=5
```

---

## პროექტის გაშვება

### დეშბორდის გაშვება

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

### ელფოსტის მიმღების გაშვება

```bash
python email_receiver.py
```

ბრაუზერში გახსენით:

```
http://127.0.0.1:8000
```

---

## ავტორი

ფარნაოზ სონიშვილი

კავკასიის უნივერსიტეტი

კომპიუტერული მეცნიერება

საბაკალავრო ნაშრომი

„ქცევაზე დაფუძნებული ელფოსტის საფრთხეების აღმოჩენისა და ავტომატური რეაგირების პლატფორმის არქიტექტურა და იმპლემენტაცია“