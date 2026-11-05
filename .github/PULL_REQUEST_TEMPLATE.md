## Ringkasan

<!-- Apa yang diubah dan kenapa. 1-2 kalimat. -->

## Tipe

- [ ] feat — fitur/check baru
- [ ] fix — perbaikan bug
- [ ] ci / docs / refactor / test

## Modul terdampak

<!-- authz / zap / clientleak / upload / auth-policy / scanners / report / - -->

## Checklist

- [ ] Pengujian tetap non-destruktif (nggak nge-exploit / brute-force)
- [ ] Temuan baru punya entri remediasi di `remediation.py` (deskripsi, dampak, severity, solusi, rujukan)
- [ ] `python -m py_compile` lolos untuk file yang diubah
- [ ] Nggak ada kredensial/target asli ke-commit (cek `config/*.yml` & `tests/*/*.yml`)
- [ ] Commit mengikuti Conventional Commits
