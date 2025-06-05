#!/usr/bin/env python3
"""
Advanced Vigenère Cipher Cracker using wordfreq and wordsegment.

Features:
  1. Index of Coincidence (IC) to guess key lengths.
  2. (Optional) Kasiski examination for repeated substrings.
  3. Frequency-analysis-based key recovery for each guessed length.
  4. Final scoring of each candidate plaintext using:
       a) WordFreqStrategy (zipf_frequency from wordfreq)
       b) SegmentationStrategy (segment from wordsegment)
  5. (Optional) Dictionary fallback if you supply a custom wordlist file.

Usage:
    Import crack_vigenere() from this module, or run as a script.
"""

import re
import math
from collections import Counter, defaultdict
import random
from itertools import combinations
from typing import List, Tuple, Dict, Optional

# Import your core Vigenère functions:
from ciphers.vigenere import vigenere_decrypt, repeat_key

# ─── English Letter Frequencies for Chi-Squared ────────────────────────────────
ENGLISH_FREQ: Dict[str, float] = {
    'A': 0.08167, 'B': 0.01492, 'C': 0.02782, 'D': 0.04253, 'E': 0.12702,
    'F': 0.02228, 'G': 0.02015, 'H': 0.06094, 'I': 0.06966, 'J': 0.00153,
    'K': 0.00772, 'L': 0.04025, 'M': 0.02406, 'N': 0.06749, 'O': 0.07507,
    'P': 0.01929, 'Q': 0.00095, 'R': 0.05987, 'S': 0.06327, 'T': 0.09056,
    'U': 0.02758, 'V': 0.00978, 'W': 0.02360, 'X': 0.00150, 'Y': 0.01974,
    'Z': 0.00074
}

# ─── Text Cleaning & Subtext Splitting ─────────────────────────────────────────
def clean_text(text: str) -> str:
    """Remove non-letters, uppercase everything."""
    return ''.join(ch for ch in text.upper() if ch.isalpha())

def split_into_subtexts(ciphertext: str, key_length: int) -> List[str]:
    """
    Given a cleaned ciphertext, split into `key_length` interleaved substrings.
    """
    subtexts = [''] * key_length
    for idx, ch in enumerate(ciphertext):
        subtexts[idx % key_length] += ch
    return subtexts

# ─── Index of Coincidence (IC) ──────────────────────────────────────────────────
def index_of_coincidence(subtext: str) -> float:
    N = len(subtext)
    if N <= 1:
        return 0.0
    freqs = Counter(subtext)
    numerator = sum(f * (f - 1) for f in freqs.values())
    denominator = N * (N - 1)
    return numerator / denominator

def average_ic_for_length(ciphertext: str, key_length: int) -> float:
    parts = split_into_subtexts(ciphertext, key_length)
    ic_values = [index_of_coincidence(p) for p in parts if len(p) > 1]
    return sum(ic_values) / len(ic_values) if ic_values else 0.0

def guess_key_lengths_ic(ciphertext: str, max_length: int = 16, top_n: int = 3) -> List[int]:
    scored = []
    for L in range(1, max_length + 1):
        avg_ic = average_ic_for_length(ciphertext, L)
        scored.append((L, abs(0.065 - avg_ic)))
    scored.sort(key=lambda x: x[1])
    return [L for L, _ in scored[:top_n]]

# ─── Kasiski Examination ────────────────────────────────────────────────────────
def find_repeat_spacings(ciphertext: str, seq_len: int = 3) -> List[int]:
    positions: Dict[str, List[int]] = defaultdict(list)
    for i in range(len(ciphertext) - seq_len + 1):
        seq = ciphertext[i:i + seq_len]
        positions[seq].append(i)
    spacings = []
    for pos_list in positions.values():
        if len(pos_list) > 1:
            for (i1, i2) in combinations(pos_list, 2):
                spacings.append(i2 - i1)
    return spacings

def factorize(n: int) -> List[int]:
    facts = []
    for i in range(2, int(math.isqrt(n)) + 1):
        if n % i == 0:
            facts.append(i)
            if i != n // i:
                facts.append(n // i)
    return sorted(facts)

def guess_key_lengths_kasiski(ciphertext: str, seq_len: int = 3, top_n: int = 3) -> List[int]:
    spacings = find_repeat_spacings(ciphertext, seq_len=seq_len)
    factor_counts = Counter()
    for s in spacings:
        for f in factorize(s):
            factor_counts[f] += 1
    if not factor_counts:
        return []
    return [factor for factor, _ in factor_counts.most_common(top_n)]

# ─── Frequency‐Analysis‐Based Key Recovery ──────────────────────────────────────
def chi_squared_stat(obs_freq: Counter, length: int) -> float:
    chi2 = 0.0
    for letter, eng_f in ENGLISH_FREQ.items():
        O_i = obs_freq.get(letter, 0)
        E_i = eng_f * length
        chi2 += ((O_i - E_i) ** 2) / E_i
    return chi2

def find_caesar_shift_for_subtext(subtext: str) -> int:
    min_chi2 = float('inf')
    best_shift = 0
    length = len(subtext)
    for shift in range(26):
        decoded = []
        for ch in subtext:
            decoded_letter = chr(((ord(ch) - 65 - shift) % 26) + 65)
            decoded.append(decoded_letter)
        trial = ''.join(decoded)
        freq_counts = Counter(trial)
        chi2 = chi_squared_stat(freq_counts, length)
        if chi2 < min_chi2:
            min_chi2 = chi2
            best_shift = shift
    return best_shift

def recover_key_by_frequency(ciphertext: str, key_length: int) -> str:
    subtexts = split_into_subtexts(ciphertext, key_length)
    key_chars = []
    for sub in subtexts:
        shift = find_caesar_shift_for_subtext(sub)
        key_chars.append(chr(shift + 65))
    return ''.join(key_chars)

# ─── Scoring Strategies: WordFreq & Segmentation ───────────────────────────────
class ScoreStrategy:
    def score(self, text: str) -> Tuple[float, int, int]:
        raise NotImplementedError()

class WordFreqStrategy(ScoreStrategy):
    def __init__(self, min_zipf: float = 2.5):
        try:
            from wordfreq import zipf_frequency
        except ImportError:
            raise RuntimeError("`wordfreq` not installed; run `pip install wordfreq`")
        self.zipf = zipf_frequency
        self.threshold = min_zipf

    def score(self, text: str) -> Tuple[float, int, int]:
        tokens = re.findall(r"[A-Za-z']+", text.lower())
        total = len(tokens)
        if total == 0:
            return 0.0, 0, 0
        valid = sum(1 for w in tokens if self.zipf(w, 'en') >= self.threshold)
        return (valid / total, valid, total)

class SegmentationStrategy(ScoreStrategy):
    def __init__(self):
        try:
            from wordsegment import load as ws_load, segment as ws_segment
            ws_load()
            self.segment = ws_segment
        except ImportError:
            raise RuntimeError("`wordsegment` not installed; run `pip install wordsegment`")

    def score(self, text: str) -> Tuple[float, int, int]:
        tokens = self.segment(text.lower())
        total = len(tokens)
        if total == 0:
            return 0.0, 0, 0
        valid = sum(1 for w in tokens if w.isalpha())
        return (valid / total, valid, total)


class NGramStrategy(ScoreStrategy):
    """Score plaintext using simple n-gram log probabilities."""

    DEFAULT_TEXT = (
        "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG. "
        "THIS SAMPLE TEXT PROVIDES COMMON ENGLISH WORDS FOR NGRAM SCORING."
    )

    def __init__(self, n: int = 4, corpus: Optional[str] = None):
        self.n = n
        raw = clean_text(corpus or self.DEFAULT_TEXT)
        counts: Dict[str, int] = defaultdict(int)
        for i in range(len(raw) - n + 1):
            counts[raw[i:i + n]] += 1
        self.total = sum(counts.values())
        self.log_probs = {
            g: math.log10(c / self.total) for g, c in counts.items()
        }
        # floor value for unseen n-grams
        self.floor = math.log10(0.01 / self.total)

    def score(self, text: str) -> float:
        text = clean_text(text)
        if len(text) < self.n:
            return float('-inf')
        s = 0.0
        for i in range(len(text) - self.n + 1):
            g = text[i:i + self.n]
            s += self.log_probs.get(g, self.floor)
        return s

# ─── External Dictionary Fallback (optional) ─────────────────────────────────
def load_wordlist(path: str, min_len: int = 2, max_len: int = 6) -> List[str]:
    words: List[str] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                w = line.strip().upper()
                if w.isalpha() and min_len <= len(w) <= max_len:
                    words.append(w)
    except FileNotFoundError:
        pass
    return words

# ─── Main Cracking Routine (returns results) ─────────────────────────────────
def crack_vigenere(
    ciphertext_raw: str,
    use_kasiski: bool = True,
    wordlist_path: Optional[str] = None,
    max_key_length: int = 12,
    top_n_lengths: int = 3,
    top_n_results: int = 5
) -> List[Tuple[float, str, str, str]]:
    """
    Returns a list of (combined_score, method, key, plaintext) sorted descending.
    """
    ciphertext = clean_text(ciphertext_raw)
    if not ciphertext:
        raise ValueError("Input contains no alphabetic characters.")

    # 1) Guess lengths via IC
    ic_lengths = guess_key_lengths_ic(ciphertext, max_length=max_key_length, top_n=top_n_lengths)

    # 2) Guess lengths via Kasiski (optional)
    kasiski_lengths: List[int] = []
    if use_kasiski:
        kasiski_lengths = guess_key_lengths_kasiski(ciphertext, seq_len=3, top_n=top_n_lengths)

    # Merge, dedupe
    length_guesses = []
    for L in ic_lengths:
        if L not in length_guesses:
            length_guesses.append(L)
    for L in kasiski_lengths:
        if L not in length_guesses:
            length_guesses.append(L)
    if not length_guesses:
        length_guesses = list(range(1, max_key_length + 1))

    # Prepare scorers
    wf_scorer = WordFreqStrategy(min_zipf=2.5)
    try:
        seg_scorer = SegmentationStrategy()
    except RuntimeError:
        seg_scorer = None

    # Load external wordlist
    fallback_max_len = 4
    dictionary_keys: List[str] = []
    if wordlist_path:
        dictionary_keys = load_wordlist(wordlist_path, min_len=1, max_len=fallback_max_len)

    all_results: List[Tuple[float, str, str, str]] = []

    for L in length_guesses:
        if L <= 0 or L > max_key_length:
            continue

        # Frequency-based key recovery
        key_freq = recover_key_by_frequency(ciphertext, L)
        plaintext_freq = vigenere_decrypt(ciphertext_raw, key_freq)

        wf_ratio, wf_valid, wf_total = wf_scorer.score(plaintext_freq)
        if seg_scorer:
            seg_ratio, seg_valid, seg_total = seg_scorer.score(plaintext_freq)
            combined = wf_ratio + seg_ratio
            method = f"Freq+Seg(L={L})"
        else:
            combined = wf_ratio
            method = f"Freq(L={L})"

        all_results.append((combined, method, key_freq, plaintext_freq))

        # Dictionary fallback if length small
        if dictionary_keys and L <= fallback_max_len:
            candidates = [w for w in dictionary_keys if len(w) == L]
            for kw in candidates:
                pt = vigenere_decrypt(ciphertext_raw, kw)
                wf_r2, wf_v2, wf_t2 = wf_scorer.score(pt)
                if seg_scorer:
                    seg_r2, seg_v2, seg_t2 = seg_scorer.score(pt)
                    combined2 = wf_r2 + seg_r2
                    method2 = f"Dict(L={L})"
                else:
                    combined2 = wf_r2
                    method2 = f"Dict(L={L})"
                all_results.append((combined2, method2 + f"[{kw}]", kw, pt))

    # Fallback if no results
    if not all_results and dictionary_keys:
        for kw in [w for w in dictionary_keys if 1 <= len(w) <= fallback_max_len]:
            pt = vigenere_decrypt(ciphertext_raw, kw)
            wf_r3, wf_v3, wf_t3 = wf_scorer.score(pt)
            if seg_scorer:
                seg_r3, seg_v3, seg_t3 = seg_scorer.score(pt)
                combined3 = wf_r3 + seg_r3
                method3 = f"Dict(L={len(kw)})"
            else:
                combined3 = wf_r3
                method3 = f"Dict(L={len(kw)})"
            all_results.append((combined3, method3 + f"[{kw}]", kw, pt))

    all_results.sort(reverse=True, key=lambda x: x[0])
    return all_results[:top_n_results]


# ─── N-Gram Hill-Climb & Simulated Annealing Attacks ─────────────────────────

def hill_climb_search(ciphertext: str, key_length: int, scorer: NGramStrategy,
                      max_rounds: int = 20) -> Tuple[str, str, float]:
    ciphertext = clean_text(ciphertext)
    key = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(key_length))
    best_score = scorer.score(vigenere_decrypt(ciphertext, key))
    improved = True
    while improved:
        improved = False
        for pos in range(key_length):
            current_letter = key[pos]
            current_best = best_score
            best_char = current_letter
            for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                trial_key = key[:pos] + ch + key[pos+1:]
                pt = vigenere_decrypt(ciphertext, trial_key)
                sc = scorer.score(pt)
                if sc > current_best:
                    current_best = sc
                    best_char = ch
            if current_best > best_score:
                key = key[:pos] + best_char + key[pos+1:]
                best_score = current_best
                improved = True
    plaintext = vigenere_decrypt(ciphertext, key)
    return key, plaintext, best_score


def simulated_annealing_search(
    ciphertext: str,
    key_length: int,
    scorer: NGramStrategy,
    iterations: int = 1000,
    temp: float = 20.0,
    cooling: float = 0.995,
) -> Tuple[str, str, float]:
    ciphertext = clean_text(ciphertext)
    key = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(key_length))
    plain = vigenere_decrypt(ciphertext, key)
    score = scorer.score(plain)
    best_key, best_score = key, score

    for _ in range(iterations):
        pos = random.randrange(key_length)
        ch = random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        cand_key = key[:pos] + ch + key[pos+1:]
        cand_plain = vigenere_decrypt(ciphertext, cand_key)
        cand_score = scorer.score(cand_plain)
        if cand_score > score or math.exp((cand_score - score) / temp) > random.random():
            key, score = cand_key, cand_score
            if score > best_score:
                best_key, best_score = key, score
        temp = max(temp * cooling, 0.1)

    plaintext = vigenere_decrypt(ciphertext, best_key)
    return best_key, plaintext, best_score


def crack_vigenere_hill(
    ciphertext_raw: str,
    max_key_length: int = 12,
    top_n_lengths: int = 3,
    top_n_results: int = 5,
) -> List[Tuple[float, str, str, str]]:
    cipher = clean_text(ciphertext_raw)
    lengths = guess_key_lengths_ic(cipher, max_length=max_key_length, top_n=top_n_lengths)
    scorer = NGramStrategy()
    results = []
    for L in lengths:
        key, pt, sc = hill_climb_search(cipher, L, scorer)
        results.append((sc, f"Hill(L={L})", key, pt))
    results.sort(reverse=True, key=lambda x: x[0])
    return results[:top_n_results]


def crack_vigenere_anneal(
    ciphertext_raw: str,
    max_key_length: int = 12,
    top_n_lengths: int = 3,
    top_n_results: int = 5,
) -> List[Tuple[float, str, str, str]]:
    cipher = clean_text(ciphertext_raw)
    lengths = guess_key_lengths_ic(cipher, max_length=max_key_length, top_n=top_n_lengths)
    scorer = NGramStrategy()
    results = []
    for L in lengths:
        key, pt, sc = simulated_annealing_search(cipher, L, scorer)
        results.append((sc, f"Anneal(L={L})", key, pt))
    results.sort(reverse=True, key=lambda x: x[0])
    return results[:top_n_results]

# ─── Entry‐Point for Interactive Use ───────────────────────────────────────────
if __name__ == "__main__":
    print("🔑 Advanced Vigenère Cipher Cracker (wordfreq + wordsegment) 🔑\n")
    print("Instructions:")
    print("  • Paste your Vigenère-encrypted text (any punctuation/spacing is OK).")
    print("  • We’ll automatically guess likely key lengths, recover candidate keys,")
    print("    and rank plaintexts by English-likeness (using wordfreq & wordsegment).")
    print("  • If you have a local wordlist.txt for fallback, enter its path when prompted.\n")

    ciphertext_input = input("Enter the Vigenère‐encrypted message:\n> ").strip()
    use_kasiski_input = input("Use Kasiski examination? (Y/n) [default=Y]: ").strip().lower()
    use_kasiski = (use_kasiski_input != 'n')

    wordlist_input = input("Path to a local wordlist file for fallback (or press Enter to skip):\n> ").strip()
    if not wordlist_input:
        wordlist_input = None

    results = crack_vigenere(
        ciphertext_raw=ciphertext_input,
        use_kasiski=use_kasiski,
        wordlist_path=wordlist_input,
        max_key_length=12,
        top_n_lengths=3,
        top_n_results=5
    )

    print("\n🔓 Top Decryption Candidates:\n")
    for idx, (score, method, key, plaintext) in enumerate(results, start=1):
        print(f"{idx:2}. [{method}] Key = '{key}' | Score = {score:.5f}")
        print(f"    Plaintext: {plaintext}\n")
