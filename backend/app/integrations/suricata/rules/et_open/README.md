# ET Open Rules

Put extracted Emerging Threats Open rules (`*.rules`) in this directory for offline import.

Online import:

```bash
python -c "from app.integrations.suricata.rules import import_et_open_rules; print(len(import_et_open_rules()))"
```

Offline import:

```bash
python -c "from app.integrations.suricata.rules import import_et_open_rules; print(len(import_et_open_rules('/path/to/et-open-rules')))"
```
