# Malhunt

Search malware in memory dumps using Volatiliy.

## Requirements 

- Python
- Git
- Volatility
- Clamscan

## How it works

![Malhunt demo](/img/malhunt.gif)

The script applies my workflow for malware analysis:

- Performs image identification
- Scans processes with yara rules, malfind and network blacklist in order to find suspicious artifacts
- Saves memory dump and handles of suspicious processes
- Scans saved processes with clamscan

