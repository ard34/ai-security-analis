# Setup Checklist

- Review `docs/scope.md`.
- Update `config/config.yaml` with authorized `target.base_url` and explicit `target.allowed_hosts`.
- Run `chmod +x scripts/setup_kali.sh scripts/run_zap_daemon.sh`.
- Run `./scripts/setup_kali.sh` if Kali dependencies are missing.
- Create and activate the Python virtual environment.
- Install requirements.
- Confirm Burp proxy listener is active on `127.0.0.1:8080`.
- Run recon only against authorized targets.
