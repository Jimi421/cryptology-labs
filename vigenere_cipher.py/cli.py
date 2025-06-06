# cli.py

import os
import logging
import json
import yaml
import click
from pathlib import Path
from typing import Optional

# Import our batch‐helper utilities
from batch_helpers import (
    logger,
    export_to_json,
    export_to_csv,
    archive_processed_file,
    process_watch_folder
)

# Import the core cracking function and also the preview helpers
from tools.vigenere_crack_core import (
    crack_vigenere,
    crack_vigenere_hill,
    crack_vigenere_anneal,
    clean_text,
    guess_key_lengths_ic,
    guess_key_lengths_kasiski
)

# ─── Load Config File ─────────────────────────────────────────────────────────
def load_config(profile: str, config_path: str = "config.yaml") -> dict:
    """
    Load `config.yaml` and return the dictionary under `profile`.
    If the file or profile is missing, return an empty dict.
    """
    if not os.path.isfile(config_path):
        logger.warning(f"Config file '{config_path}' not found; using defaults.")
        return {}
    with open(config_path, "r", encoding="utf-8") as f:
        all_conf = yaml.safe_load(f) or {}
    return all_conf.get(profile, {})

# ─── Main CLI ─────────────────────────────────────────────────────────────────
@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--profile", "-p", default="default", show_default=True,
              help="Config profile name from config.yaml")
@click.option("--ciphertext", "-c", type=str,
              help="Either a raw ciphertext string or path to a single .txt file.")
@click.option("--batch", "-b", type=click.Path(exists=True),
              help="Path to a folder containing .txt files to batch‐process.")
@click.option("--watch", "-w", type=click.Path(exists=True),
              help="Path to a folder to watch for new .txt files (real‐time).")
@click.option("--use-kasiski/--no-kasiski", default=None,
              help="Enable or disable Kasiski examination. Overrides config.")
@click.option("--wordlist", "-l", type=click.Path(exists=True),
              help="Path to a local wordlist file for dictionary fallback (length ≤ 4).")
@click.option("--variant", type=click.Choice(["standard", "autokey", "homophonic"]),
              default="standard", show_default=True,
              help="Vigenère variant to use for decryption.")
@click.option("--homophonic-map", type=click.Path(exists=True),
              help="JSON file describing homophonic mapping (for homophonic variant).")
@click.option("--crib", "-x", type=str,
              help="Known plaintext fragment used as a crib for key hints.")
@click.option("--max-keylen", "-k", type=int, default=None,
              help="Maximum key length for IC/frequency analysis. Overrides config.")
@click.option("--top-lengths", "-n", type=int, default=None,
              help="Number of candidate key lengths to attempt. Overrides config.")
@click.option("--top-results", "-r", type=int, default=None,
              help="Number of top candidate plaintexts to display. Overrides config.")
@click.option("--export-json", "-j", type=click.Path(),
              help="Export results to JSON at specified path.")
@click.option("--export-csv", "-s", type=click.Path(),
              help="Export results to CSV at specified path.")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging.")
@click.option("--dry-run", is_flag=True, help="Validate inputs and show planned actions without decrypting.")
@click.option("--preview", is_flag=True, help="Only run IC/Kasiski and show guessed lengths, then exit.")
@click.option("--hill-climb", is_flag=True, help="Use hill-climb search with n-gram scoring.")
@click.option("--anneal", is_flag=True, help="Use simulated annealing with n-gram scoring.")
def main(
    profile,
    ciphertext,
    batch,
    watch,
    use_kasiski,
    wordlist,
    variant,
    homophonic_map,
    crib,
    max_keylen,
    top_lengths,
    top_results,
    export_json,
    export_csv,
    verbose,
    dry_run,
    preview,
    hill_climb,
    anneal
):
    """
    Advanced Vigenère Cipher Cracking Tool
    """
    # ─── Set Logging Level ─────────────────────────────────────────────────────
    if verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")

    # ─── Load Config Profile ────────────────────────────────────────────────────
    conf = load_config(profile)
    use_kasiski = use_kasiski if use_kasiski is not None else conf.get("use_kasiski", True)
    wordlist = wordlist or conf.get("wordlist_path", None)
    variant = variant or conf.get("variant", "standard")
    homophonic_map = homophonic_map or conf.get("homophonic_map", None)
    mapping_dict = None
    if homophonic_map:
        try:
            with open(homophonic_map, "r", encoding="utf-8") as f:
                mapping_dict = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load homophonic map: {e}")
            mapping_dict = None
    max_keylen = max_keylen if max_keylen is not None else conf.get("max_key_length", 12)
    top_lengths = top_lengths if top_lengths is not None else conf.get("top_n_lengths", 3)
    top_results = top_results if top_results is not None else conf.get("top_n_results", 5)

    if hill_climb and anneal:
        click.echo("Error: --hill-climb and --anneal cannot be used together.")
        return

    # ─── Dry Run / Preview ─────────────────────────────────────────────────────
    if dry_run:
        click.echo("DRY RUN: The tool will run with the following parameters:")
        click.echo(f"  Profile:        {profile}")
        click.echo(f"  Use Kasiski:    {use_kasiski}")
        click.echo(f"  Wordlist Path:  {wordlist}")
        click.echo(f"  Variant:       {variant}")
        if mapping_dict:
            click.echo(f"  Homophonic Map: {homophonic_map}")
        click.echo(f"  Crib:          {crib}")
        click.echo(f"  Max Key Length: {max_keylen}")
        click.echo(f"  Top Lengths:    {top_lengths}")
        click.echo(f"  Top Results:    {top_results}")
        if hill_climb:
            click.echo("  Mode:          Hill-Climb")
        if anneal:
            click.echo("  Mode:          Simulated Annealing")
        if batch:
            click.echo(f"  Batch Folder:   {batch}")
        if watch:
            click.echo(f"  Watch Folder:   {watch}")
        if ciphertext:
            snippet = ciphertext if len(ciphertext) < 50 else ciphertext[:47] + "..."
            click.echo(f"  Ciphertext:     {snippet}")
        if export_json:
            click.echo(f"  JSON Export:    {export_json}")
        if export_csv:
            click.echo(f"  CSV Export:     {export_csv}")
        return

    # ─── Batch Mode ─────────────────────────────────────────────────────────────
    if batch:
        input_folder = batch
        output_folder = conf.get("output_folder", "output")
        os.makedirs(output_folder, exist_ok=True)
        format_json = export_json is not None
        format_csv = export_csv is not None

        def process_file(filepath: str):
            filename = os.path.basename(filepath)
            logger.info(f"Batch‐processing file: {filename}")
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    ct_raw = f.read()
                if preview:
                    cleaned = clean_text(ct_raw)
                    ic_lens = guess_key_lengths_ic(cleaned, max_length=max_keylen, top_n=top_lengths)
                    kas_lens = guess_key_lengths_kasiski(cleaned, seq_len=3, top_n=top_lengths) if use_kasiski else []
                    click.echo(f"[Preview] '{filename}': IC→{ic_lens}, Kasiski→{kas_lens}")
                else:
                    if hill_climb:
                        results = crack_vigenere_hill(
                            ct_raw,
                            variant=variant,
                            homophonic_map=mapping_dict,
                            max_key_length=max_keylen,
                            top_n_lengths=top_lengths,
                            top_n_results=top_results,
                        )
                    elif anneal:
                        results = crack_vigenere_anneal(
                            ct_raw,
                            variant=variant,
                            homophonic_map=mapping_dict,
                            max_key_length=max_keylen,
                            top_n_lengths=top_lengths,
                            top_n_results=top_results,
                        )
                    else:
                        results = crack_vigenere(
                            ct_raw,
                            use_kasiski=use_kasiski,
                            wordlist_path=wordlist,
                            crib=crib,
                            variant=variant,
                            homophonic_map=mapping_dict,
                            max_key_length=max_keylen,
                            top_n_lengths=top_lengths,
                            top_n_results=top_results,
                        )

                    base = os.path.splitext(filename)[0]
                    if format_json:
                        out_path = os.path.join(output_folder, f"{base}_results.json")
                        export_to_json(results, out_path)
                    if format_csv:
                        out_path = os.path.join(output_folder, f"{base}_results.csv")
                        export_to_csv(results, out_path)

                    click.echo(f"\n[Top candidates for {filename}]")
                    for idx, (score, method, key, pt) in enumerate(results, start=1):
                        click.echo(f"{idx}. [{method}] Key='{key}' Score={score:.3f}")
                        snippet = pt if len(pt) < 60 else pt[:57] + "..."
                        click.echo(f"    {snippet}")
                archive_processed_file(filepath)
            except Exception as e:
                logger.error(f"Error processing '{filename}': {e}")

        # If watch mode is also specified, start the watch-folder handler
        if watch:
            process_watch_folder(input_folder, process_file)
            return

        # Otherwise, do a one-time batch run
        click.echo(f"Batch‐processing all .txt files in '{input_folder}' → '{output_folder}'")
        txt_files = list(Path(input_folder).glob("*.txt"))
        if not txt_files:
            logger.warning(f"No .txt files found in '{input_folder}'.")
            return

        for filepath in txt_files:
            process_file(str(filepath))
        return

    # ─── Watch Mode Only (no batch) ─────────────────────────────────────────────
    if watch and not batch:
        def process_single(path_to_file: str):
            filename = os.path.basename(path_to_file)
            logger.info(f"Watch‐processing: {filename}")
            try:
                with open(path_to_file, "r", encoding="utf-8") as f:
                    ct_raw = f.read()
                if hill_climb:
                    results = crack_vigenere_hill(
                        ct_raw,
                        variant=variant,
                        homophonic_map=mapping_dict,
                        max_key_length=max_keylen,
                        top_n_lengths=top_lengths,
                        top_n_results=top_results,
                    )
                elif anneal:
                    results = crack_vigenere_anneal(
                        ct_raw,
                        variant=variant,
                        homophonic_map=mapping_dict,
                        max_key_length=max_keylen,
                        top_n_lengths=top_lengths,
                        top_n_results=top_results,
                    )
                else:
                    results = crack_vigenere(
                        ct_raw,
                        use_kasiski=use_kasiski,
                        wordlist_path=wordlist,
                        crib=crib,
                        variant=variant,
                        homophonic_map=mapping_dict,
                        max_key_length=max_keylen,
                        top_n_lengths=top_lengths,
                        top_n_results=top_results,
                    )
                click.echo(f"\n[Watch Mode Top Candidates for {filename}]")
                for idx, (score, method, key, pt) in enumerate(results, start=1):
                    snippet = pt if len(pt) < 60 else pt[:57] + "..."
                    click.echo(f"{idx}. [{method}] Key='{key}' Score={score:.3f}")
                    click.echo(f"    {snippet}")
                archive_processed_file(path_to_file)
            except Exception as e:
                logger.error(f"Error processing '{filename}': {e}")

        process_watch_folder(watch, process_single)
        return

    # ─── Single Cipher Mode ─────────────────────────────────────────────────────
    if ciphertext:
        if os.path.isfile(ciphertext):
            with open(ciphertext, "r", encoding="utf-8") as f:
                ct_raw = f.read()
        else:
            ct_raw = ciphertext

        if preview:
            cleaned = clean_text(ct_raw, variant, mapping_dict)
            ic_lens = guess_key_lengths_ic(cleaned, max_length=max_keylen, top_n=top_lengths)
            kas_lens = guess_key_lengths_kasiski(cleaned, seq_len=3, top_n=top_lengths) if use_kasiski else []
            click.echo(f"[Preview] IC→{ic_lens}, Kasiski→{kas_lens}")
            return

        if hill_climb:
            results = crack_vigenere_hill(
                ct_raw,
                variant=variant,
                homophonic_map=mapping_dict,
                max_key_length=max_keylen,
                top_n_lengths=top_lengths,
                top_n_results=top_results,
            )
        elif anneal:
            results = crack_vigenere_anneal(
                ct_raw,
                variant=variant,
                homophonic_map=mapping_dict,
                max_key_length=max_keylen,
                top_n_lengths=top_lengths,
                top_n_results=top_results,
            )
        else:
            results = crack_vigenere(
                ct_raw,
                use_kasiski=use_kasiski,
                wordlist_path=wordlist,
                crib=crib,
                variant=variant,
                homophonic_map=mapping_dict,
                max_key_length=max_keylen,
                top_n_lengths=top_lengths,
                top_n_results=top_results
            )
        click.echo("\n[Top Candidates]")
        for idx, (score, method, key, pt) in enumerate(results, start=1):
            click.echo(f"{idx}. [{method}] Key='{key}' Score={score:.3f}")
            click.echo(f"    {pt}")

        if export_json:
            export_to_json(results, export_json)
        if export_csv:
            export_to_csv(results, export_csv)
        return

    # ─── No Mode Specified ───────────────────────────────────────────────────────
    click.echo("Error: You must specify either --ciphertext, --batch, or --watch. See --help for details.")
    return

if __name__ == "__main__":
    main()
