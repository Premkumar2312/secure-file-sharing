# Secure File Sharing System

A small beginner-level Flask project for sharing files with Fernet authenticated encryption. Upload a file to receive a private download link and a separate decryption key. The recipient needs both.

## How encryption works

Each upload gets a new Fernet key. Fernet encrypts and authenticates the file contents before the encrypted bytes are written to `storage/`. The original file is never saved as a plaintext file. The key is displayed once in the upload response and is not written to the metadata or encrypted file. Save it and share it with the recipient through a separate channel.

The lightweight `storage/metadata.json` file maps a random file ID to the sanitized original filename. It does not contain decryption keys. Stored files are named using random IDs, not their original names.

## Requirements

- Python 3.10 or newer
- pip

## Install on Windows

Open PowerShell in the `SecureFileSharing` project folder and run:

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks activation, you can invoke the environment's Python directly with `.venv\Scripts\python.exe`.

## Run the application

```powershell
python app.py
```

Open the local address printed by Flask (normally `http://127.0.0.1:5000`). Select a supported file up to 10 MB, then share the generated link and key separately. The app accepts common document, image, archive, and media extensions; add another extension to `ALLOWED_EXTENSIONS` in `app.py` if your class project needs it.

Flask's built-in server is intended for local demonstration and development, not public production hosting. When sharing the app over a network, use HTTPS so the key and upload form are protected in transit.

## Project structure

```text
SecureFileSharing/
├── app.py
├── encryption.py
├── requirements.txt
├── README.md
├── storage/
├── static/
│   └── style.css
└── templates/
    ├── download.html
    └── index.html
```
