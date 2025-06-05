# 🧪 Cryptology Labs

A focused collection of cryptographic tools and decoding environments — modular, command-line driven, and built for precision. This lab serves as a launchpad for deeper exploration into classical encryption methods and their underlying mechanics.

---

## 📁 Repository Overview

Each folder contains a standalone module or utility designed to analyze, break, or demonstrate a specific cipher. All tools are kept lightweight, terminal-friendly, and compatible with modern Python 3 environments.

| Module | Description |
|--------|-------------|
| `caesar/` | Caesar Cipher decoding suite with scoring heuristics, brute-force, TUI slider, and GPT-backed fallback |
| `vigenere_cipher.py/` | Advanced Vigenère cracking CLI with IC & Kasiski analysis, wordfreq and n‑gram scoring, hill‑climb/annealing attacks, and batch/watch modes |
| `substitution/` | *(Planned)* Tools for breaking monoalphabetic substitution ciphers using statistical methods |
| `rsa/` | *(Planned)* Modular RSA demo with key generation, signing, and encryption primitives |
| `playfair/` | *(Planned)* Playfair cipher grid tools for encoding/decoding and visualization |
| `utils/` | Shared scoring engines, frequency data, and wordlists for internal use across modules |

---

## 🔧 Setup & Execution

1. Clone the repository:

```bash
git clone https://github.com/your-username/cryptology-labs.git
cd cryptology-labs
Activate the environment (optional but recommended):

bash
Copy
Edit
python3 -m venv venv
source venv/bin/activate
Install core dependencies (per module):

bash
Copy
Edit
pip install -r caesar/requirements.txt
Run a module:

bash
Copy
Edit
cd caesar
python3 c_decode.py "Encrypted Message Here"
📊 Tooling Philosophy
No fluff. Every tool is designed to run from the command line with minimal overhead.

Modular scoring. Multiple heuristics are used to evaluate candidate decryptions: segmentation, frequency, n-gram statistics, substrings, chi-squared, and ensemble methods.

Optional AI fallback. Selected tools support language model scoring for high-entropy ciphertexts.

Interactive modes. Tools offer both automated decoding and manual tuning via TUI sliders or prompt-driven input.

🚧 Roadmap
 Caesar Cipher decoder with scoring ensemble

 Vigenère pattern matching and key recovery

 Monoalphabetic substitution analysis

 RSA key gen + educational prime playground

 Web interface for tool visualization (TUI → GUI)

📂 Structure
pgsql
Copy
Edit
cryptology-labs/
├── caesar/
│   ├── c_decode.py
│   ├── examples.txt
│   └── known_plaintext_pairs.json
├── vigenere_cipher.py/
├── substitution/
├── utils/
└── README.md
🔒 License
MIT — use, modify, break things, improve them. Contributions welcome.


