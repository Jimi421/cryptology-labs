#!/usr/bin/env python3
"""
World-Class Caesar Cipher Decoder with Ensemble + Perplexity Fallback + TUI
- Scoring strategies: segmentation, wordfreq, substring, chisquared, ensemble
- Optional perplexity fallback using GPT-2
- Rich CLI UX: progress bars, styled tables, JSON output, interactive prompts
- TUI slider mode with live scoring metrics
- Logging with verbose debug details
"""
import argparse
import json
import logging
import re
import sys
from abc import ABC, abstractmethod
from collections import Counter
from typing import List, Tuple

# Attempt to import segmentation
USE_SEGMENT = False
try:
    from wordsegment import load as ws_load, segment as ws_segment
    ws_load()
    USE_SEGMENT = True
except ImportError:
    pass

# Attempt to import Rich for CLI enhancements
USE_RICH = False
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import track
    console = Console()
    USE_RICH = True
except ImportError:
    pass

# Attempt imports for TUI (prompt_toolkit)
USE_TUI = False
try:
    from prompt_toolkit.application import Application
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.layout import Layout
    from prompt_toolkit.layout.containers import HSplit, Window
    from prompt_toolkit.layout.controls import FormattedTextControl
    USE_TUI = True
except ImportError:
    pass

# Base scoring interface
class ScoreStrategy(ABC):
    name: str

    @abstractmethod
    def score(self, text: str) -> Tuple[float, int, int]:
        """Return (score, valid_count, total_count)"""
        pass

# 1) Segmentation-based scoring
class SegmentationStrategy(ScoreStrategy):
    name = 'segmentation'
    def __init__(self, min_zipf: float = 2.5):
        from wordfreq import zipf_frequency
        self.zipf = zipf_frequency
        self.threshold = min_zipf
        if not USE_SEGMENT:
            raise RuntimeError('wordsegment not installed; cannot use segmentation')
    def score(self, text: str) -> Tuple[float, int, int]:
        clean = re.sub(r"[^A-Za-z']", '', text).lower()
        tokens = ws_segment(clean)
        total = len(tokens)
        if total == 0:
            return 0.0, 0, 0
        valid = sum(1 for w in tokens if self.zipf(w, 'en') >= self.threshold)
        return valid / total, valid, total

# 2) Word frequency scoring
class WordFreqStrategy(ScoreStrategy):
    name = 'wordfreq'
    def __init__(self, min_zipf: float = 2.5):
        from wordfreq import zipf_frequency
        self.zipf = zipf_frequency
        self.threshold = min_zipf
    def score(self, text: str) -> Tuple[float, int, int]:
        words = re.findall(r"[A-Za-z']+", text.lower())
        total = len(words)
        if total == 0:
            return 0.0, 0, 0
        valid = sum(1 for w in words if self.zipf(w, 'en') >= self.threshold)
        return valid / total, valid, total

# 3) Substring scoring
class SubstringStrategy(ScoreStrategy):
    name = 'substring'
    def __init__(self, top_n: int = 5000, min_len: int = 4):
        from wordfreq import top_n_list
        common = top_n_list('en', top_n)
        self.common = {w for w in common if len(w) >= min_len}
    def score(self, text: str) -> Tuple[float, int, int]:
        lower = text.lower()
        hits = [w for w in self.common if w in lower]
        total = max(1, len(re.findall(r"[A-Za-z']+", text)))
        valid = len(hits)
        return valid / total, valid, total

# 4) Chi-squared scoring
class ChiSquaredStrategy(ScoreStrategy):
    name = 'chisquared'
    FREQUENCIES = {
        'A':0.08167,'B':0.01492,'C':0.02782,'D':0.04253,'E':0.12702,
        'F':0.02228,'G':0.02015,'H':0.06094,'I':0.06966,'J':0.00153,
        'K':0.00772,'L':0.04025,'M':0.02406,'N':0.06749,'O':0.07507,
        'P':0.01929,'Q':0.00095,'R':0.05987,'S':0.06327,'T':0.09056,
        'U':0.02758,'V':0.00978,'W':0.02360,'X':0.00150,'Y':0.01974,'Z':0.00074
    }
    def score(self, text: str) -> Tuple[float, int, int]:
        cleaned = re.sub(r'[^A-Za-z]', '', text).upper()
        N = len(cleaned)
        if N == 0:
            return 0.0, 0, 0
        counts = Counter(cleaned)
        chi2 = sum((counts.get(ch,0) - N*freq)**2/(N*freq)
                   for ch, freq in self.FREQUENCIES.items())
        return 1/(1+chi2), 0, N

# 5) Ensemble scoring
class EnsembleStrategy(ScoreStrategy):
    name = 'ensemble'
    def __init__(self, threshold: float = 2.5, chi_weight: float = 0.3):
        self.seg = SegmentationStrategy(threshold)
        self.chi = ChiSquaredStrategy()
        self.w_seg = 1 - chi_weight
        self.w_chi = chi_weight
    def score(self, text: str) -> Tuple[float, int, int]:
        seg_score, seg_v, seg_t = self.seg.score(text)
        chi_score, _, _ = self.chi.score(text)
        return (self.w_seg * seg_score + self.w_chi * chi_score), seg_v, seg_t

# 6) Perplexity scoring
class PerplexityStrategy(ScoreStrategy):
    name = 'perplexity'
    def __init__(self, model_name: str = 'gpt2'):
        from transformers import GPT2LMHeadModel, GPT2TokenizerFast
        import torch
        self.tokenizer = GPT2TokenizerFast.from_pretrained(model_name)
        self.model = GPT2LMHeadModel.from_pretrained(model_name).eval()
        self.torch = torch
    def score(self, text: str) -> Tuple[float, int, int]:
        tokens = self.tokenizer(text, return_tensors='pt')
        with self.torch.no_grad():
            outputs = self.model(**tokens, labels=tokens['input_ids'])
        return -outputs.loss.item(), 0, 0

# Caesar decryption
def caesar_decrypt(text: str, shift: int) -> str:
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch)-base-shift)%26 + base))
        else:
            result.append(ch)
    return ''.join(result)

# Brute-force
def brute_force(cipher: str, strategy: ScoreStrategy) -> List[Tuple[int,float,int,int,str]]:
    results = []
    shifts  = range(1,26)
    iterator= track(shifts, 'Decrypting...') if USE_RICH else shifts
    for s in iterator:
        p  = caesar_decrypt(cipher, s)
        sc, v, t = strategy.score(p)
        results.append((s, sc, v, t, p))
    return sorted(results, key=lambda x: x[1], reverse=True)

# TUI slider mode
def run_tui(ciphertext: str):
    if not USE_TUI:
        print("Error: prompt_toolkit not installed; cannot launch TUI.")
        sys.exit(1)

    strat = EnsembleStrategy()
    shift = 1

    def get_text():
        decrypted = caesar_decrypt(ciphertext, shift)
        score, valid, total = strat.score(decrypted)
        header = f"Shift {shift}/25 — Score: {score:.3f} ({valid}/{total} matches) — ←/→ or h/l, q to quit"
        return [
            ('class:header', header),
            ('', "\n" + decrypted)
        ]

    text_control = FormattedTextControl(get_text)
    root         = HSplit([ Window(text_control, always_hide_cursor=True) ])
    kb           = KeyBindings()

    @kb.add('left')
    @kb.add('h')
    def _(event):
        nonlocal shift
        shift = 25 if shift <= 1 else shift - 1
        event.app.invalidate()

    @kb.add('right')
    @kb.add('l')
    def _(event):
        nonlocal shift
        shift = 1 if shift >= 25 else shift + 1
        event.app.invalidate()

    @kb.add('q')
    @kb.add('c-c')
    def _(event):
        event.app.exit()

    app = Application(layout=Layout(root), key_bindings=kb, full_screen=True)
    app.run()

# Display
def display(results: List[Tuple[int,float,int,int,str]], args):
    best = results[0]
    if args.json:
        out = [{'key': s, 'score': sc, 'matches': v, 'total': t, 'plaintext': p}
               for s, sc, v, t, p in results[:args.top]]
        print(json.dumps({'best': out[0], 'candidates': out}, indent=2))
        return

    if USE_RICH:
        table = Table(title='Caesar Decoder Results')
        table.add_column('Key',    style='cyan')
        table.add_column('Score',  style='magenta')
        table.add_column('Matches',style='green')
        table.add_column('Output', style='white')
        for s, sc, v, t, p in results[:args.top]:
            style = 'bold yellow' if s == best[0] else ''
            table.add_row(str(s), f'{sc:.3f}', f'{v}/{t}', p, style=style)
        console.print(table)
        console.print(f'Best → key={best[0]}, score={best[1]:.3f}, matches={best[2]}/{best[3]}')
    else:
        print(f"Top {args.top} results:")
        for s, sc, v, t, p in results[:args.top]:
            mark = '*' if s == best[0] else ' '
            print(f"{mark}{s:2} | {sc:.3f} | {v}/{t} | {p}")
        print(f"Best → key={best[0]}, score={best[1]:.3f}, matches={best[2]}/{best[3]}")

# Main CLI
def main():
    parser = argparse.ArgumentParser(description='World-Class Caesar Cipher Decoder')
    parser.add_argument('ciphertext', nargs='?', help='Encrypted text')
    parser.add_argument('-s','--strategy',
                        choices=['segmentation','wordfreq','substring','chisquared','ensemble','perplexity'],
                        help='Scoring strategy (default: ensemble)')
    parser.add_argument('-t','--threshold', type=float, default=2.5, help='ZIPF threshold')
    parser.add_argument('-n','--top',       type=int,   default=25,  help='Number of candidates to show')
    parser.add_argument('--use-perplexity', action='store_true', help='Rescore top N with perplexity')
    parser.add_argument('-i','--interactive',action='store_true', help='Interactive mode')
    parser.add_argument('--tui',            action='store_true', help='Launch TUI slider mode')
    parser.add_argument('--json',           action='store_true', help='JSON output')
    parser.add_argument('--verbose',        action='store_true', help='Verbose logging')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='[%(levelname)s] %(message)s')

    if not args.ciphertext:
        print('Welcome to the Caesar Cipher Decoder!')
        args.ciphertext = input('Enter cipher text: ')

    if args.tui:
        run_tui(args.ciphertext)
        sys.exit(0)

    strat_name = args.strategy or 'ensemble'
    if strat_name == 'segmentation':
        strat = SegmentationStrategy(args.threshold)
    elif strat_name == 'wordfreq':
        strat = WordFreqStrategy(args.threshold)
    elif strat_name == 'substring':
        strat = SubstringStrategy()
    elif strat_name == 'chisquared':
        strat = ChiSquaredStrategy()
    elif strat_name == 'perplexity':
        strat = PerplexityStrategy()
    else:
        strat = EnsembleStrategy(args.threshold, chi_weight=0.3)

    results = brute_force(args.ciphertext, strat)

    if args.interactive:
        # prompt for perplexity fallback
        if not args.use_perplexity:
            choice = input('Use perplexity fallback? (y/n): ').strip().lower()
            if choice in ('y','yes'):
                args.use_perplexity = True
        # prompt for top-N
        top_str = input(f'How many top candidates to display? [{args.top}]: ').strip()
        if top_str:
            try:
                args.top = int(top_str)
            except ValueError:
                print(f"Invalid number '{top_str}', defaulting to {args.top}.")

    if args.use_perplexity:
        pstrat = PerplexityStrategy()
        rescored = []
        for s, _, v, t, p in results[:args.top]:
            sc, _, _ = pstrat.score(p)
            rescored.append((s, sc, v, t, p))
        results = sorted(rescored, key=lambda x: x[1], reverse=True)

    display(results, args)

if __name__ == '__main__':
    main()
