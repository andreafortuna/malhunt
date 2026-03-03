#!/usr/bin/env python3
"""Test YARA rules download and merge process."""

import sys
from pathlib import Path

sys.path.insert(0, 'src')

from malhunt.core import Malhunt
from malhunt.utils import clean_up

# Test
dump = Path('/Users/andrea/Downloads/stuxnet.vmem')

try:
    print("Initializing Malhunt...")
    mh = Malhunt(dump)
    
    print("\nCalling clean_up() to remove old caches...")
    clean_up(mh.malhunt_home)
    print("✅ Cleanup complete")
    
    print("\nTesting prepare_rules()...")
    success = mh.prepare_rules()
    print(f"Result: {success}")
    
    if success:
        rules_file = Path.home() / '.malhunt' / 'malware_rules.yar'
        if rules_file.exists():
            size_mb = rules_file.stat().st_size / (1024*1024)
            print(f"✅ Rules file created: {rules_file.name} ({size_mb:.1f} MB)")
            
            # Check content
            content = rules_file.read_text()
            lines = len(content.split('\n'))
            rule_count = content.count('rule ')
            print(f"   Lines: {lines}")
            print(f"   Rules: {rule_count}")
            
            # Check for duplicates
            elf_count = content.count('private rule is__elf')
            print(f"   Private rule is__elf: {elf_count}")
            if elf_count > 1:
                print("   ⚠️ WARNING: Multiple private rule is__elf found!")
            else:
                print("   ✅ No duplicate private rules")
        else:
            print("❌ Rules file not created!")
    else:
        print("❌ prepare_rules failed!")
        
    # Check rules directory
    rules_dir = Path.home() / '.malhunt' / 'rules'
    if rules_dir.exists():
        print(f"\n✅ Rules directory exists: {rules_dir}")
        malware_dir = rules_dir / 'malware'
        webshells_dir = rules_dir / 'Webshells'
        print(f"   - malware/: {malware_dir.exists()}")
        print(f"   - Webshells/: {webshells_dir.exists()}")
    else:
        print(f"\nℹ️ Rules directory cleaned up after processing")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
