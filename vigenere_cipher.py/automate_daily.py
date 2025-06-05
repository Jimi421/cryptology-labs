# automate_daily.py

import os
import logging
from pathlib import Path
from datetime import datetime

# Correct import: crack_vigenere comes from vigenere_crack_core, not cli
from tools.vigenere_crack_core import crack_vigenere
from batch_helpers import export_to_json, archive_processed_file

# Configure logging to a file
logging.basicConfig(
    filename="automate_daily.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("vigenere_tool.automate")

def download_from_sftp(dest_folder: str):
    """
    Placeholder: connect to SFTP and download new ciphertexts into `dest_folder`.
    Implement with paramiko / pysftp if needed.
    """
    # Example (pseudo-code):
    # import pysftp
    # with pysftp.Connection(host, username, password) as sftp:
    #     sftp.chdir('remote_folder')
    #     for file in sftp.listdir():
    #         if file.endswith('.enc'):
    #             sftp.get(file, os.path.join(dest_folder, file))
    pass

def main():
    input_folder = "sftp_in"
    output_folder = "daily_output"
    os.makedirs(input_folder, exist_ok=True)
    os.makedirs(output_folder, exist_ok=True)

    # 1) Download new ciphertexts from SFTP (if implemented)
    download_from_sftp(input_folder)

    # 2) Process batch
    txt_files = list(Path(input_folder).glob("*.txt"))
    if not txt_files:
        logger.info("No new files to process.")
        return

    for filepath in txt_files:
        filename = os.path.basename(filepath)
        logger.info(f"Processing '{filename}' in scheduled run.")
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                ct_raw = f.read()

            results = crack_vigenere(
                ct_raw,
                use_kasiski=True,
                wordlist_path="data/wordlist.txt",
                max_key_length=12,
                top_n_lengths=3,
                top_n_results=5
            )
            base = os.path.splitext(filename)[0]
            json_out = os.path.join(output_folder, f"{base}_results.json")
            export_to_json(results, json_out)
            archive_processed_file(filepath, archive_root="archive")

        except Exception as e:
            logger.error(f"Error in automate_daily for '{filename}': {e}")

    # 3) (Optional) send a notification (email/Slack) if desired
    # For example:
    # from notify_helpers import send_email_report
    # summary = f"Processed {len(txt_files)} files on {datetime.now().date()}."
    # send_email_report( ... )

if __name__ == "__main__":
    main()
