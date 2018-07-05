#!/usr/bin/env python
# encoding: utf-8

import os,shutil,sys


def clean_up():
	shutil.rmtree("./rules", ignore_errors=True)

def get_rules_from_git():
	clean_up()
	os.system("git clone https://github.com/Yara-Rules/rules.git")

def list_yara_files():
	all_yara_files = []
	for root, directories, filenames in os.walk("./rules/malware"):
		filenames.sort()
		for file_name in filenames:
			rule_filename, rule_file_extension = os.path.splitext(file_name)
			if rule_file_extension == ".yar" or rule_file_extension == ".yara":
				all_yara_files.append(os.path.join(root, file_name))
	return all_yara_files

def remove_incompatible_imports(files):
	filtered_files = []
	for yara_file in files:
		with open(yara_file, 'r') as fd:
			yara_in_file = fd.read()
			if not (("import \"math\"" in yara_in_file) or ("import \"cuckoo\"" in yara_in_file) or ("import \"hash\"" in yara_in_file) or ("imphash" in yara_in_file)):
				filtered_files.append(yara_file)
	return filtered_files

def fix_duplicated_rules(files):
	filtered_files = []
	first_elf = True
	to_delete = False
	for yara_file in files:
		with open(yara_file, 'r') as fd:
			yara_in_file = fd.readlines()
			for line in yara_in_file:
				if line.strip() == "private rule is__elf {":
					if first_elf:
						first_elf = False
					else:
						to_delete = True
				if not to_delete:
					filtered_files.append(line)
				if (not first_elf) and line.strip() == "}":
					to_delete = False
			filtered_files.append("\n")
	return filtered_files

def merge_rules(all_rules):
	with open("malware_rules.yar", 'w') as fd:
		fd.write(''.join(all_rules))

def image_identification(filename):
	volimageInfo = os.popen("volatility -f " + filename +  " imageinfo  2>/dev/null | grep \"Suggested Profile(s)\" | awk '{print $4 $5 $6}'").read()
	volimageInfo = volimageInfo.rstrip()
	volProfiles = volimageInfo.split(",")
	for volProfile in volProfiles:
		profileCheck =  os.popen("volatility -f " + filename +  " --profile=" + volProfile + " pslist 2>/dev/null").read()
		print "	Check profile \033[1m" + volProfile + "\033[0m"
		if "Offset" in profileCheck:
			return volProfile
	return ""

def yarascan(filename, volProfile):
	volOutput = os.popen("volatility -f " + filename +  " yarascan --profile=" + volProfile + " -y malware_rules.yar  2>/dev/null").read()
	with open(filename + '.malware_search.txt', 'w') as f:
		f.write(volOutput)

def banner_logo():
	print """  __  __       _ _                 _   
 |  \/  |     | | |               | |  
 | \  / | __ _| | |__  _   _ _ __ | |_ 
 | |\/| |/ _` | | '_ \| | | | '_ \| __|
 | |  | | (_| | | | | | |_| | | | | |_ 
 |_|  |_|\__,_|_|_| |_|\__,_|_| |_|\__|
                                       
Hunt malware with Volatility and Yara!

Andrea Fortuna
andrea@andreafortuna.org
https://www.andreafortuna.org
"""

def banner_usage():
	print " Usage:"
	print "	" + sys.argv[0] + " imagefile"

def main():
	banner_logo()
	if len(sys.argv) <2:
		banner_usage()
		return ""
	imageFile = sys.argv[1]
	print "\033[1mStep1 - \033[0mUpdate malware yara rules..."
	get_rules_from_git()
	all_yara_files = list_yara_files()
	all_yara_filtered_1 = remove_incompatible_imports(all_yara_files)
	all_yara_filtered_2 = fix_duplicated_rules(all_yara_filtered_1)
	merge_rules(all_yara_filtered_2)
	clean_up()
	print "\033[1mStep2 - \033[0mStarting image identification for file \033[4m" + imageFile + "\033[0m..."
	volProfile = image_identification(imageFile)
	if (volProfile ==""):
		print "Image identification failed!"
		return ""
	print "Image \033[4m" + imageFile + "\033[0m identified as \033[1m" + volProfile + "\033[0m"
	print  "\033[1mStep3 - \033[0m Starting malware artifacts search..."
	yarascan(imageFile, volProfile)
	print "Scan results saved in \033[4m" + imageFile + ".malware_search.txt\033[0m"

# Main body
if __name__ == '__main__':
	main()
