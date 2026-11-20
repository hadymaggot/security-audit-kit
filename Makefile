# Short commands for Linux/macOS. On Windows use audit.ps1 (make is not always available).
# Every target forwards to `python audit.py`, so behavior is identical across OSes.

PYTHON ?= python3
# Multi-project: make all PROJECT=my-app  (name -> projects/<name>, or a folder path)
PROJECT ?=
AUDIT = $(PYTHON) audit.py $(if $(PROJECT),--project "$(PROJECT)")

.PHONY: help install audit all zap zap-api zap-full authz upload auth-policy \
        clientleak tls headers deps report clean init

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
	@echo "  make init PROJECT=x MODULES=authz,upload - siapkan folder project"
	@echo "  (semua target menerima PROJECT=<nama|folder> untuk multi-project paralel)"

install:
	$(PYTHON) -m pip install -r requirements.txt

audit all:
	$(AUDIT) all

zap:
	$(AUDIT) zap baseline
zap-api:
	$(AUDIT) zap api
zap-full:
	$(AUDIT) zap full

authz:
	$(AUDIT) authz
upload:
	$(AUDIT) upload
auth-policy:
	$(AUDIT) auth-policy
clientleak:
	$(AUDIT) clientleak
tls:
	$(AUDIT) tls
headers:
	$(AUDIT) headers
deps:
	$(AUDIT) deps
report:
	$(AUDIT) report

clean:
	$(AUDIT) clean

# make init PROJECT=my-app MODULES=authz,upload
init:
	$(AUDIT) init $(MODULES)
