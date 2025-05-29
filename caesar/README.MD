# 🔐 Caesar Cipher Suite

A modular Caesar cipher toolkit for both encoding and decoding text, featuring brute-force decryption, scoring heuristics, interactive CLI options, and support for optional language model fallback. Built for precision, extensibility, and terminal-native workflows.

---

## ⚙️ Features

- 🔓 **`c_decode.py`**  
  - Brute-force Caesar decryption across all 25 possible shifts
  - Multiple scoring strategies: word segmentation, word frequency, substring hits, chi-squared, ensemble
  - Interactive mode with prompts and optional perplexity rescoring using GPT-2
  - TUI slider interface for real-time decryption navigation
  - Clean JSON export for pipeline use or post-analysis

- 🔒 **`c_encode.py`**  
  - Caesar cipher encoder with interactive mode or CLI flag support
  - Useful for generating ciphertext to test decoders or obfuscate messages

---

## 🚀 Quickstart

### Encode
```bash
python3 c_encode.py -k 5 -t "Hello World"
Or leave out the flags to trigger interactive mode:

bash
Copy
Edit
python3 c_encode.py
# → Please enter key:
# → Please enter text:
Decode
bash
Copy
Edit
python3 c_decode.py "Mjqqt Btwqi"
With options:

bash
Copy
Edit
python3 c_decode.py "Mjqqt Btwqi" --strategy ensemble --top 5 --interactive
🧠 Scoring Strategies (for decoding)
segmentation — Breaks strings into words using language models and scores by word quality

wordfreq — Uses Zipf frequency rankings of real English words

substring — Detects presence of top N English substrings

chisquared — Compares character frequency distribution

ensemble — Combines segmentation and chi-squared heuristics

perplexity — Optional GPT-2 scoring for best candidate detection

📂 Files
bash
Copy
Edit
caesar/
├── c_decode.py                  # Full-featured Caesar cipher decoder
├── c_encode.py                  # Simple Caesar encoder with CLI or prompt mode
├── examples.txt                 # Sample ciphertexts for testing
├── known_plaintext_pairs.json  # Mapping of ciphertext to known solutions (for validation)
└── README.md
✅ Example Use Cases
Testing brute-force decryption against known plaintexts

Encoding obfuscated messages for challenges or demonstrations

Comparing scoring strategies across encrypted strings

Interactive teaching/demonstration of Caesar mechanics

📦 Requirements
Install dependencies (for decoding features only):

bash
Copy
Edit
pip install -r requirements.txt
Note: c_encode.py has no external dependencies.

🔓 License
MIT — use, fork, break, improve.

