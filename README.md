# Malhunt

Search malware in memory dumps using Volatiliy.

## Requirements 

- Python
- Git
- Volatility

## How it works

![Malhunt demo](/img/malhunt.gif)

The script applies my workflow for malware analysis:

- Performs image identification
- Scans processes with yara rules in order to find suspicious artifacts
- Saves memory dump and handles of suspicious processes
- Scans saved processes with clamscan (when available)

## ToDo

- OS identification and network analysis
