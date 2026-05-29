# PDF Report Setup

HTML reports are always generated first. PDF export uses WeasyPrint when available.

On Kali/Debian, install system dependencies:

```bash
sudo apt install -y libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info
```

If PDF generation fails, the dashboard will show:

`PDF gagal dibuat. HTML tetap tersedia. Pastikan dependensi WeasyPrint terinstall.`
