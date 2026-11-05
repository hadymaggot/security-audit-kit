# Perintah pendek untuk Linux/macOS. Windows: pakai audit.ps1 (make tak selalu ada).
# Semua target meneruskan ke `python audit.py`, jadi perilakunya identik lintas-OS.

PYTHON ?= python3

.PHONY: help install audit all zap zap-api zap-full authz upload auth-policy \
        clientleak tls headers deps report clean

help:
	@echo "Target:"
	@echo "  make install       - pasang dependensi Python"
	@echo "  make audit | all   - jalankan semua modul + susun laporan"
	@echo "  make zap           - OWASP ZAP baseline (passive)"
	@echo "  make zap-api       - OWASP ZAP dari OpenAPI (butuh 'openapi' di targets.yml)"
	@echo "  make zap-full      - OWASP ZAP active scan (HANYA dev/staging sendiri)"
	@echo "  make authz         - regresi kontrol akses per peran"
	@echo "  make upload        - uji penolakan unggahan berbahaya"
	@echo "  make auth-policy   - uji kebijakan sandi & captcha"
	@echo "  make clientleak    - cache klien, rahasia JS/HTML, berkas ter-ekspos"
	@echo "  make tls           - uji protokol/cipher TLS"
	@echo "  make headers       - uji security header respons"
	@echo "  make deps          - CVE dependensi + SAST + rahasia ter-commit"
	@echo "  make report        - gabungkan hasil jadi reports/laporan.html"
	@echo "  make clean         - hapus isi reports/"

install:
	$(PYTHON) -m pip install -r requirements.txt

audit all:
	$(PYTHON) audit.py all

zap:
	$(PYTHON) audit.py zap baseline
zap-api:
	$(PYTHON) audit.py zap api
zap-full:
	$(PYTHON) audit.py zap full

authz:
	$(PYTHON) audit.py authz
upload:
	$(PYTHON) audit.py upload
auth-policy:
	$(PYTHON) audit.py auth-policy
clientleak:
	$(PYTHON) audit.py clientleak
tls:
	$(PYTHON) audit.py tls
headers:
	$(PYTHON) audit.py headers
deps:
	$(PYTHON) audit.py deps
report:
	$(PYTHON) audit.py report

clean:
	$(PYTHON) -c "import shutil,glob,os; [os.remove(f) for f in glob.glob('reports/*') if os.path.isfile(f) and not f.endswith('.gitkeep')]"
	@echo "reports/ dibersihkan."
