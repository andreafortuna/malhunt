# Malhunt

Search malware in memory dumps using Volatiliy and Yara.

## Requirements 

- Python
- git
- volatility

## How it works

The script applies my workflow for malware analysis:

- Performs image identification
- Scans processes with yara rules in order to find suspicious artifacts
- Saves memory dump and handles of suspicious processes


## ToDo

- OS identification and network analysis