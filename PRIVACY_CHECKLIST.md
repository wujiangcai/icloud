# Portable package privacy checklist

This package intentionally excludes:

- cookie.txt
- emails.txt
- all_generated_icloud_emails.txt
- server_icloud_code_api.sqlite3
- icloud-code-api/data
- icloud-code-api/config.json
- last_icloud_import_result.json
- Python virtual environments
- __pycache__ folders
- server IP/domain/private keys/passwords

Before sharing, do not add real runtime files back into this package.
