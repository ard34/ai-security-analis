from __future__ import annotations


OWASP_WEB_TOP_10 = [
    ("A01", "Broken Access Control", "Kontrol akses lemah dapat memungkinkan user mengakses data atau fungsi di luar izin.", ["idor", "bola", "bfla", "admin"], ["object id", "admin endpoint", "profile/account"], ["Validasi dengan dua akun test dan role berbeda."], "Gunakan akun uji berizin; jangan mengakses data produksi."),
    ("A02", "Cryptographic Failures", "Kegagalan perlindungan data sensitif saat transit atau tersimpan.", ["sensitive", "token", "secret", "tls"], ["response sensitif", "cookie", "transport"], ["Cek data sensitif dan konfigurasi TLS/header secara manual."], "Jangan menyalin data sensitif asli."),
    ("A03", "Injection", "Input tidak tervalidasi dapat memicu injection.", ["injection", "sqli", "xss", "command"], ["search", "query", "form", "api parameter"], ["Gunakan payload benign di lingkungan berizin."], "Jangan gunakan payload destruktif."),
    ("A04", "Insecure Design", "Desain flow bisnis atau kontrol keamanan tidak memadai.", ["business", "logic", "workflow"], ["checkout", "payment", "coupon"], ["Uji manipulasi flow dengan akun test."], "Jangan melakukan transaksi nyata."),
    ("A05", "Security Misconfiguration", "Konfigurasi header, CORS, debug, atau server exposure tidak aman.", ["header", "cors", "debug", "misconfiguration"], ["headers", "cookies", "server version"], ["Review konfigurasi dan hardening."], "Validasi pasif dan manual saja."),
    ("A06", "Vulnerable and Outdated Components", "Komponen usang atau rentan dapat meningkatkan risiko.", ["cve", "vulnerable", "outdated", "component"], ["server", "framework", "cms", "js library"], ["Konfirmasi versi dan advisory resmi."], "Jangan menjalankan exploit publik."),
    ("A07", "Identification and Authentication Failures", "Autentikasi atau sesi dapat lemah.", ["auth", "session", "cookie", "jwt"], ["login", "logout", "reset password"], ["Cek cookie flags, token, CSRF, invalidasi sesi."], "Jangan credential stuffing atau brute force."),
    ("A08", "Software and Data Integrity Failures", "Integritas software/data tidak terjamin.", ["integrity", "supply chain", "unsigned"], ["third-party script", "update mechanism"], ["Review SRI, dependency, dan deployment pipeline."], "Tidak mengubah supply chain."),
    ("A09", "Security Logging and Monitoring Failures", "Logging/monitoring tidak cukup untuk deteksi insiden.", ["logging", "monitoring", "audit"], ["auth events", "admin events"], ["Validasi dengan tim aplikasi secara manual."], "Jangan memicu aktivitas berbahaya."),
    ("A10", "Server-Side Request Forgery", "Endpoint dapat meminta resource internal/eksternal yang tidak semestinya.", ["ssrf", "url", "webhook", "fetch"], ["url parameter", "webhook", "import"], ["Gunakan URL benign dan allowlist check."], "Jangan targetkan jaringan internal."),
]

OWASP_API_TOP_10 = [
    ("API1", "Broken Object Level Authorization", "Object ID dapat diakses lintas user tanpa otorisasi.", ["idor", "bola", "object id"], ["id", "order_id", "invoice_id"], ["Validasi dengan User A dan User B."], "Gunakan akun uji."),
    ("API2", "Broken Authentication", "Autentikasi API atau sesi lemah.", ["auth", "session", "token"], ["login", "token", "cookie"], ["Cek token, session invalidation, cookie flags."], "Jangan brute force."),
    ("API3", "Broken Object Property Level Authorization", "Properti object sensitif dapat terbaca/tertulis tanpa izin.", ["excessive", "property", "sensitive"], ["json response", "profile"], ["Cek field sensitif dan writable fields."], "Jangan dump data."),
    ("API4", "Unrestricted Resource Consumption", "Operasi berat tanpa pembatasan dapat menguras resource.", ["upload", "export", "search", "resource"], ["upload", "export", "search"], ["Review limit/rate secara manual."], "Jangan DoS."),
    ("API5", "Broken Function Level Authorization", "Fungsi admin/staff dapat diakses role biasa.", ["bfla", "admin", "role"], ["admin", "manage", "users"], ["Validasi status 401/403."], "Gunakan akun uji low privilege."),
    ("API6", "Unrestricted Access to Sensitive Business Flows", "Flow bisnis sensitif tidak dibatasi.", ["business", "payment", "coupon"], ["checkout", "payment", "coupon"], ["Uji flow bisnis aman."], "Jangan transaksi nyata."),
    ("API7", "Server Side Request Forgery", "API dapat memicu request server-side tidak aman.", ["ssrf", "url", "webhook"], ["webhook", "fetch", "url"], ["Cek allowlist."], "Jangan akses internal network."),
    ("API8", "Security Misconfiguration", "Konfigurasi API tidak aman.", ["cors", "header", "misconfiguration"], ["headers", "cors"], ["Review config."], "Validasi pasif."),
    ("API9", "Improper Inventory Management", "Inventori/versioning API tidak rapi atau usang.", ["v1", "beta", "deprecated", "outdated"], ["/v1", "/beta", "old API"], ["Review lifecycle API."], "Tidak menghapus endpoint."),
    ("API10", "Unsafe Consumption of APIs", "Konsumsi API pihak ketiga tidak aman.", ["third-party", "external", "webhook"], ["third-party API", "dependency"], ["Review dependency dan trust boundary."], "Jangan scan pihak ketiga tanpa izin."),
]


def _item(row: tuple[str, str, str, list[str], list[str], list[str], str]) -> dict[str, object]:
    return {"id": row[0], "name": row[1], "explanation_id": row[2], "detection_signals": row[3], "example_affected_surfaces": row[4], "manual_validation_guidance": row[5], "safe_testing_note": row[6]}


def get_owasp_web_catalog() -> list[dict[str, object]]:
    return [_item(row) for row in OWASP_WEB_TOP_10]


def get_owasp_api_catalog() -> list[dict[str, object]]:
    return [_item(row) for row in OWASP_API_TOP_10]
