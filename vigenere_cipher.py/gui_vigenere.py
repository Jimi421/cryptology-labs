#!/usr/bin/env python3
"""
Tkinter-based GUI for the Advanced Vigenère Cipher Cracker.
This GUI supports both single-text cracking and batch-folder cracking,
with optional watch-folder behavior, progress bars, and result tables.
"""

import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from typing import List, Tuple

from batch_helpers import logger, process_watch_folder, archive_processed_file
from tools.vigenere_crack_core import crack_vigenere

class VigenereApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Vigenère Cracker (World-Class Edition)")
        root.geometry("800x600")

        # Attempt to auto-load data/wordlist.txt at startup
        default_path = os.path.join("data", "wordlist.txt")
        if os.path.isfile(default_path):
            self.wordlist_path = default_path
            default_label = f"Loaded: {default_path}"
            default_fg = "black"
        else:
            self.wordlist_path = None
            default_label = "No wordlist loaded"
            default_fg = "gray"

        # Create a Notebook (tabbed interface)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)

        # Two tabs: Single Crack and Batch Crack
        self.single_frame = ttk.Frame(self.notebook)
        self.batch_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.single_frame, text="Single Crack")
        self.notebook.add(self.batch_frame, text="Batch Crack")

        self._build_single_tab(default_label, default_fg)
        self._build_batch_tab()

    # ─── Single Cracker Tab ──────────────────────────────────────────────────────
    def _build_single_tab(self, label_text: str, label_fg: str):
        frame = self.single_frame

        # Ciphertext Label + Text Box
        ttk.Label(frame, text="Ciphertext:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.ct_box = tk.Text(frame, height=6, width=80)
        self.ct_box.grid(row=1, column=0, columnspan=3, padx=5)

        # Options: Use Kasiski and Load Wordlist button
        self.use_kasiski_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Use Kasiski", variable=self.use_kasiski_var).grid(row=2, column=0, sticky="w", padx=5)

        ttk.Button(frame, text="Load Wordlist…", command=self._load_wordlist).grid(row=2, column=1, sticky="w")
        self.wordlist_label = ttk.Label(frame, text=label_text, foreground=label_fg)
        self.wordlist_label.grid(row=2, column=2, sticky="w", padx=5)

        # Crack Button
        ttk.Button(frame, text="Crack!", command=self._start_single_crack).grid(row=3, column=0, pady=10)

        # Progress Bar (indeterminate while cracking)
        self.single_progress = ttk.Progressbar(frame, orient="horizontal", mode="indeterminate")
        self.single_progress.grid(row=4, column=0, columnspan=3, padx=10, sticky="ew")

        # Results Table
        columns = ("Rank", "Method", "Key", "Score", "Plaintext")
        self.single_tree = ttk.Treeview(frame, columns=columns, show="headings", height=10)
        for col in columns:
            self.single_tree.heading(col, text=col)
            self.single_tree.column(col, width=100, anchor="w")
        self.single_tree.grid(row=5, column=0, columnspan=3, padx=10, pady=10)

    def _load_wordlist(self):
        path = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
        )
        if path:
            self.wordlist_path = path
            self.wordlist_label.config(text=os.path.basename(path), foreground="black")

    def _start_single_crack(self):
        ct_raw = self.ct_box.get("1.0", "end").strip()
        if not ct_raw:
            messagebox.showwarning("Input Required", "Please paste or type the ciphertext.")
            return

        # Clear previous results
        for row in self.single_tree.get_children():
            self.single_tree.delete(row)

        # Start the progress bar
        self.single_progress.start()

        # Run cracking in a separate thread to avoid blocking the UI
        threading.Thread(target=self._do_single_crack, args=(ct_raw,)).start()

    def _do_single_crack(self, ct_raw: str):
        try:
            results = crack_vigenere(
                ct_raw,
                use_kasiski=self.use_kasiski_var.get(),
                wordlist_path=getattr(self, "wordlist_path", None),
                max_key_length=12,
                top_n_lengths=3,
                top_n_results=10
            )
            # Populate results in the UI thread
            self.root.after(0, lambda: self._populate_results(self.single_tree, results))
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        finally:
            self.root.after(0, self.single_progress.stop)

    # ─── Batch Cracker Tab ───────────────────────────────────────────────────────
    def _build_batch_tab(self):
        frame = self.batch_frame

        # Batch Folder Selection
        ttk.Label(frame, text="Batch Folder:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.batch_folder_var = tk.StringVar(value="")
        ttk.Entry(frame, textvariable=self.batch_folder_var, width=60).grid(row=0, column=1, padx=5)
        ttk.Button(frame, text="Browse…", command=self._browse_batch_folder).grid(row=0, column=2, padx=5)

        # Watch Folder Checkbox
        self.watch_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Watch Folder", variable=self.watch_var).grid(row=1, column=0, sticky="w", padx=5)

        ttk.Button(frame, text="Start Batch", command=self._start_batch_crack).grid(row=1, column=2, sticky="e", padx=5)

        # Progress Bar (determinate for batch count)
        self.batch_progress = ttk.Progressbar(frame, orient="horizontal", mode="determinate")
        self.batch_progress.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

        # Results Table
        cols = ("Filename", "Rank", "Method", "Key", "Score", "Plaintext")
        self.batch_tree = ttk.Treeview(frame, columns=cols, show="headings", height=10)
        for col in cols:
            self.batch_tree.heading(col, text=col)
            self.batch_tree.column(col, width=100, anchor="w")
        self.batch_tree.grid(row=3, column=0, columnspan=3, padx=10, pady=10)

    def _browse_batch_folder(self):
        path = filedialog.askdirectory(title="Select Batch Folder")
        if path:
            self.batch_folder_var.set(path)

    def _start_batch_crack(self):
        folder = self.batch_folder_var.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showwarning("Folder Required", "Please select a valid batch folder.")
            return

        # Clear previous results
        for row in self.batch_tree.get_children():
            self.batch_tree.delete(row)

        if self.watch_var.get():
            # Watch mode: process new files as they appear
            process_watch_folder(folder, self._process_batch_file)
        else:
            # One-time batch mode
            txt_files = list(Path(folder).glob("*.txt"))
            if not txt_files:
                messagebox.showinfo("No Files", f"No .txt files found in '{folder}'.")
                return

            self.batch_progress["maximum"] = len(txt_files)
            self.batch_progress["value"] = 0

            threading.Thread(target=self._do_batch_crack, args=(txt_files,)).start()

    def _process_batch_file(self, filepath: str):
        """
        Called by watch mode when a new file appears in the batch folder.
        """
        filename = os.path.basename(filepath)
        logger.info(f"Watch-processing: {filename}")
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                ct_raw = f.read()
            results = crack_vigenere(
                ct_raw,
                use_kasiski=True,
                wordlist_path=getattr(self, "wordlist_path", None),
                max_key_length=12,
                top_n_lengths=3,
                top_n_results=5
            )
            for rank, (score, method, key, pt) in enumerate(results, start=1):
                # Insert row into Treeview (capture current values via default args)
                self.root.after(
                    0,
                    lambda r=rank, m=method, k=key, sc=score, p=pt, fn=filename:
                        self.batch_tree.insert("", "end", values=(fn, r, m, k, f"{sc:.3f}", p[:60] + "..."))
                )
            archive_processed_file(filepath)
        except Exception as e:
            logger.error(f"Error processing '{filename}' in watch mode: {e}")

    def _do_batch_crack(self, txt_files: List[Path]):
        for idx, filepath in enumerate(txt_files, start=1):
            filename = os.path.basename(filepath)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    ct_raw = f.read()
                results = crack_vigenere(
                    ct_raw,
                    use_kasiski=True,
                    wordlist_path=getattr(self, "wordlist_path", None),
                    max_key_length=12,
                    top_n_lengths=3,
                    top_n_results=5
                )
                for rank, (score, method, key, pt) in enumerate(results, start=1):
                    self.root.after(
                        0,
                        lambda r=rank, m=method, k=key, sc=score, p=pt, fn=filename:
                            self.batch_tree.insert("", "end", values=(fn, r, m, k, f"{sc:.3f}", p[:60] + "..."))
                    )
                archive_processed_file(filepath)
            except Exception as e:
                logger.error(f"Error processing '{filename}' in batch: {e}")
            finally:
                self.root.after(0, lambda: self.batch_progress.step(1))

    def _populate_results(self, treeview: ttk.Treeview, results: List[Tuple[float, str, str, str]]):
        """
        Insert results into the given Treeview. Each entry is a tuple of
        (score: float, method: str, key: str, plaintext: str).
        """
        for idx, (score, method, key, plaintext) in enumerate(results, start=1):
            treeview.insert(
                "", "end",
                values=(idx, method, key, f"{score:.3f}", plaintext)
            )

if __name__ == "__main__":
    root = tk.Tk()
    app = VigenereApp(root)
    root.mainloop()
