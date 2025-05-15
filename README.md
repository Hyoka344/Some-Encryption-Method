# 🔐 Some Quantum-Resistant Encryption Suite i guess..

> A serious tool with a slightly unserious README.

## What is this?

A simple GUI app for encrypting files and messages using **Kyber** and **Dilithium** — post-quantum cryptography, minus the headache.

### Features

- 🔐 Encrypt files with AES-GCM or ChaCha20, using Kyber key exchange  
- ✍️ Sign data with Dilithium  
- 🔓 Decrypt files and verify signatures  
- 🧠 Use cutting-edge crypto without needing a PhD (hopefully)

## How to Use

1. **Generate Keys**  
   Pick a folder, click *Generate*, done.

2. **Encrypt File or Text**  
   Load your file or type a message, choose your algorithm, and click *Encrypt*.

3. **Decrypt File or Text**  
   Load the encrypted file or message, provide the keys, and click *Decrypt*.

4. **Sign / Verify**  
   Like signing birthday cards, but with math.

## Requirements

- Python 3.x  
- `cryptography`, `tkinter`, and other standard libraries

## Disclaimer

We are not responsible for:
- Lost private keys
- Accidentally encrypted tax documents
- Existential dread from learning about quantum computers

## Why?

Because quantum computers are coming. Probably. And you deserve to be ready.
