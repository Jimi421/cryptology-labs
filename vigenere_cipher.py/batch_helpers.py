# batch_helpers.py

import os
import json
import csv
import shutil
import logging
from pathlib import Path
from datetime import datetime
import time

# ─── Attempt to import tqdm (guard if missing) ────────────────────────────────
try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

# ─── Logging Configuration ──────────────────────────────────────────────────
logger = logging.getLogger("vigenere_tool")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

# ─── Export to JSON ───────────────────────────────────────────────────────────
def export_to_json(results: list[tuple[float, str, str, str]], path: str) -> None:
    """
    Export cracking results to JSON. Each entry has:
      { "method": ..., "key": ..., "score": ..., "plaintext": ... }
    """
    data = []
    for score, method, key, plaintext in results:
        data.append({
            "method": method,
            "key": key,
            "score": round(score, 5),
            "plaintext": plaintext
        })
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    logger.info(f"Results exported to JSON: {path}")

# ─── Export to CSV ────────────────────────────────────────────────────────────
def export_to_csv(results: list[tuple[float, str, str, str]], path: str) -> None:
    """
    Export cracking results to CSV. Columns: Rank, Method, Key, Score, Plaintext
    """
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Rank", "Method", "Key", "Score", "Plaintext"])
        for idx, (score, method, key, plaintext) in enumerate(results, start=1):
            writer.writerow([idx, method, key, f"{score:.5f}", plaintext])
    logger.info(f"Results exported to CSV: {path}")

# ─── Archive Processed File ──────────────────────────────────────────────────
def archive_processed_file(filepath: str, archive_root: str = "archive") -> None:
    """
    Move processed file into an archive folder named by date (YYYY-MM-DD).
    """
    date_str = datetime.now().strftime("%Y-%m-%d")
    archive_dir = os.path.join(archive_root, date_str)
    os.makedirs(archive_dir, exist_ok=True)
    dest = os.path.join(archive_dir, os.path.basename(filepath))
    shutil.move(filepath, dest)
    logger.info(f"Archived '{filepath}' → '{dest}'")

# ─── Watch-Folder Handler (requires watchdog) ─────────────────────────────────
def process_watch_folder(input_folder: str, process_file_callback) -> None:
    """
    Monitor `input_folder` for newly created *.txt files.
    When a new file appears, call `process_file_callback(path_to_file)`.
    """
    try:
        from watchdog.observers import Observer
        from watchdog.events import FileSystemEventHandler
    except ImportError:
        logger.error(
            "watchdog not installed—cannot use watch mode. Install with `pip install watchdog`."
        )
        return

    class NewFileHandler(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory and event.src_path.lower().endswith(".txt"):
                logger.info(f"Detected new file: {event.src_path}")
                process_file_callback(event.src_path)

    event_handler = NewFileHandler()
    observer = Observer()
    observer.schedule(event_handler, path=input_folder, recursive=False)
    observer.start()
    logger.info(f"Watching folder: {input_folder}")
    try:
        while True:
            time.sleep(1)  # Keep running; use Ctrl+C to stop
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
