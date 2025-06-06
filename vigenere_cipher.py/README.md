# Vigenère Cipher Toolkit

This module provides a flexible command-line interface for analysing and breaking Vigenère encrypted texts.

```
python3 cli.py -c "LXFOPVEFRNHR" -x HELLO --variant autokey
```

The `--variant` flag accepts `standard`, `autokey`, or `homophonic`. When using the homophonic variant, supply `--homophonic-map path/to/map.json` with a JSON dictionary describing the cipher symbol mapping.

