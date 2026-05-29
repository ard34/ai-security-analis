# AI Security Analyst

AI Security Analyst adalah platform untuk authorized black-box web/API reconnaissance yang aman dan semi-otomatis. Project ini membantu analyst melakukan reconnaissance, asset discovery, passive security analysis, attack surface mapping, potential finding analysis, dashboard visualization, dan reporting.

This tool is intended only for authorized security testing, defensive assessment, lab environments, and security reporting. It does not perform active exploitation, brute force, denial-of-service, credential theft, or unauthorized access.

## Safety Boundaries

- Tidak melakukan exploit aktif.
- Tidak melakukan brute force.
- Tidak melakukan denial-of-service.
- Tidak melakukan credential theft.
- Tidak melakukan bypass authentication.
- Tidak melakukan persistence.
- Tidak membaca source code, server, database, atau internal log target.
- Tidak menjalankan payload destruktif.
- Semua temuan adalah potential finding sampai divalidasi manual.
- Semua scanning wajib berada dalam authorized scope.

## MVP Scope

Alur target MVP:

```text
Input target
-> Scope validation
-> Subdomain discovery
-> DNS resolution
-> Live host check
-> Port/service detection
-> Web technology fingerprinting
-> Security headers review
-> WAF/CDN detection
-> Endpoint crawling with Katana
-> OWASP ZAP spider and passive scan
-> Nuclei safe templates
-> Burp/HAR import
-> Normalize findings
-> Attack surface mapping
-> Streamlit dashboard
-> HTML/PDF report
```

Tahap fondasi saat ini hanya berisi guardrail inti dan unit test. Dashboard dan pipeline awal harus memakai dummy pipeline sampai guardrail stabil.

## Current Foundation

- `core/scope.py`: target normalization dan scope validation tanpa network request.
- `core/policies.py`: scan mode strict/safe/standard dengan exploit, brute force, dan active ZAP selalu disabled.
- `core/models.py`: dataclass standar untuk target, asset, endpoint, finding, session, tool result, dan report metadata.
- `core/risk.py`: severity/confidence normalization dan passive risk scoring.
- `tests/test_scope.py`: coverage scope validation.
- `tests/test_policies.py`: coverage safety policy.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Running Tests

```bash
pytest -q
```

Optional coverage:

```bash
pytest --cov=.
```

## Running Streamlit Dashboard

Dashboard modular baru akan berada di:

```bash
streamlit run app/dashboard.py
```

Untuk tahap awal, dashboard hanya boleh menjalankan dummy pipeline dan tidak boleh memanggil Nmap, Katana, ZAP, Nuclei, atau tool eksternal lain.

## Scan Modes

- `strict`: recon sangat rendah risiko, port scan dan crawler eksternal disabled.
- `safe`: safe reconnaissance dengan passive ZAP dan safe templates.
- `standard`: mode aman yang lebih lengkap, tetap tanpa exploit/bruteforce/active scan.

Capability berikut selalu dilarang:

- `allow_zap_active`
- `allow_bruteforce`
- `allow_exploit`

## Reporting Output

Report HTML/PDF akan memuat:

- Project name
- Target dan scope
- Scan mode dan scan time
- Executive summary
- Attack surface summary
- Findings table
- Evidence dan recommendation
- Disclaimer bahwa findings adalah potential findings dan perlu validasi manual

