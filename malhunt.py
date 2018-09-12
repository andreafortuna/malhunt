#!/usr/bin/env python
# encoding: utf-8

import os,shutil,sys,time, requests


global MALHUNTHOME, VOLATILITYBIN, EXCLUDEDWORDS
MALHUNTHOME = os.path.expanduser("~/.malhunt")
VOLATILITYBIN = os.popen("which volatility || which vol.py").read().rstrip()
CLAMSCANBIN = os.popen("which clamscan").read().rstrip()
EXCLUDEDWORDS = ['Str_Win32_', 'SurtrStrings']


class SProcess(object):
	def __init__(self, rule, process, pid):
		self.rule = rule
		self.process = process
		self.pid = pid



def check_exclusions(line):
	if any(c in line for c in EXCLUDEDWORDS):
		return False
	return True

def clean_up():
	shutil.rmtree(MALHUNTHOME + "/rules", ignore_errors=True)
	if os.path.isfile(MALHUNTHOME + '/malware_rules.yar'):
		st=os.stat(MALHUNTHOME + "/malware_rules.yar")
		max_age = time.time() - (60 * 60 * 24) #One day 
		mtime=st.st_mtime
		if mtime < max_age:
			os.unlink(MALHUNTHOME + "/malware_rules.yar")

def get_rules_from_git():
	clean_up()
	os.system("git clone https://github.com/Yara-Rules/rules.git " + MALHUNTHOME + "/rules")

def list_yara_files():
	all_yara_files = []
	for root, directories, filenames in os.walk(MALHUNTHOME + "/rules/malware"):
		filenames.sort()
		for file_name in filenames:
			rule_filename, rule_file_extension = os.path.splitext(file_name)
			if rule_file_extension == ".yar" or rule_file_extension == ".yara":
				all_yara_files.append(os.path.join(root, file_name))
	# BETA - Search for webshells
        for root, directories, filenames in os.walk(MALHUNTHOME + "/rules/Webshells"):
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
	with open(MALHUNTHOME + "/malware_rules.yar", 'w') as fd:
		fd.write(''.join(all_rules))

def image_identification(filename):
	if os.path.isfile(MALHUNTHOME + "/" + os.path.basename(filename) + ".imageinfo"):
		with open(MALHUNTHOME + "/" + os.path.basename(filename) + ".imageinfo",'r') as f:
    			output = f.read()
	 		return output.rstrip()
	volimageInfo = os.popen(VOLATILITYBIN + " -f " + filename +  " imageinfo  2>/dev/null | grep \"Suggested Profile(s)\" | awk '{print $4 $5 $6}'").read()
	volimageInfo = volimageInfo.rstrip()
	volProfiles = volimageInfo.split(",")
	for volProfile in volProfiles:
		profileCheck =  os.popen(VOLATILITYBIN + " -f " + filename +  " --profile=" + volProfile + " pslist 2>/dev/null").read()
		print "	Check profile \033[1m" + volProfile + "\033[0m"
		if "Offset" in profileCheck:
			with open(MALHUNTHOME + "/" + os.path.basename(filename) + ".imageinfo", 'w') as f:
				f.write(volProfile)
			return volProfile
	return ""


def maliciousIP(ipaddress):
	response = requests.get("http://check.getipintel.net/check.php?ip=" + ipaddress + "&contact=abuse@getipinterl.net")

	if response.text == "1":
		return True
	return False

def yarascan(filename, volProfile, processList):
	if os.path.isfile(MALHUNTHOME + "/" + os.path.basename(filename) + '.malware_search'):
		with open(MALHUNTHOME + "/" + os.path.basename(filename) + '.malware_search','r') as f:
                        volOutput = f.read()
	else:
 		volOutput = os.popen(VOLATILITYBIN + " -f " + filename +  " yarascan --profile=" + volProfile + " -y " + os.path.expanduser("~/.malhunt") +  "/malware_rules.yar  2>/dev/null").read()
	#report = []
	linereport = ""
	rule = ""
	process = ""
	pid = ""
	for line in volOutput.splitlines():
		if line.startswith("Rule"):
			rule = line.split(":")[1].lstrip().rstrip()
		if line.startswith("Owner"):
                        process = line.split(":")[1].lstrip().split()[1].lstrip().rstrip()
                        pid = line.split(":")[1].lstrip().split()[3].lstrip().rstrip()
			singleProcess = SProcess(rule,process,pid)

			if check_exclusions(rule):
				if len(filter(lambda SProcess: SProcess.pid == pid, processList)) ==0:
				#if singleProcess not in report:
					processList.append(singleProcess)
			rule = ""
			process = ""
			pid = ""
	with open(MALHUNTHOME + "/" + os.path.basename(filename) + '.malware_search', 'w') as f:
		f.write(volOutput)
	return processList

def malfindscan(filename, volProfile, processList):
        if os.path.isfile(MALHUNTHOME + "/" + os.path.basename(filename) + '.malfind_search'):
                with open(MALHUNTHOME + "/" + os.path.basename(filename) + '.malfind_search','r') as f:
                        volOutput = f.read()
        else:
                volOutput = os.popen(VOLATILITYBIN + " -f " + filename +  " malfind --profile=" + volProfile + "  2>/dev/null | grep \"Process: \"" ).read()
        linereport = ""
        rule = ""
        process = ""
        pid = ""
        for line in volOutput.splitlines():
		rule =  "malfind"
		process = line.split(" ")[1].lstrip().rstrip()
		pid = line.split(" ")[3].lstrip().rstrip()
		singleProcess = SProcess(rule,process,pid)
		if len(filter(lambda SProcess: SProcess.pid == pid, processList)) ==0:
			processList.append(singleProcess)
        with open(MALHUNTHOME + "/" + os.path.basename(filename) + '.malfind_search', 'w') as f:
                f.write(volOutput)
        return processList

def networkscan(filename, volProfile, processList):

	volCommand = "netscan"
	volFilter = " | grep -v \"LISTENING\""
	ipColumn = 3
	pidColumn = 5

	if volProfile.startswith("Win2003") or volProfile.startswith("WinXP"):
		volCommand = "connscan"
		volFilter = ""
		ipColumn = 2
		pidColumn = 3
        if os.path.isfile(MALHUNTHOME + "/" + os.path.basename(filename) + '.network_search'):
                with open(MALHUNTHOME + "/" + os.path.basename(filename) + '.network_search','r') as f:
                        volOutput = f.read()
        else:
                volOutput = os.popen(VOLATILITYBIN + " -f " + filename +  " " + volCommand + " --profile=" + volProfile + "  2>/dev/null " + volFilter ).read()
        for line in volOutput.splitlines():
                rule =  "network"
                process = "N.A."
		ip = line.split()[ipColumn].lstrip().rstrip()
                pid = line.split()[pidColumn].lstrip().rstrip()
		if (ip ==""):
			continue
		if (maliciousIP(ip.split(":")[0].lstrip().rstrip())):
	                singleProcess = SProcess(rule,process,pid)
        	        if len(filter(lambda SProcess: SProcess.pid == pid, processList)) ==0:
                	        processList.append(singleProcess)
        with open(MALHUNTHOME + "/" + os.path.basename(filename) + '.network_search', 'w') as f:
                f.write(volOutput)
        return processList



def dump_process(imagefile, profile, PID):
	if not os.path.isdir(os.getcwd() + "/" + os.path.basename(imagefile) + "_artifacts"):
		os.makedirs(os.getcwd() + "/" + os.path.basename(imagefile) + "_artifacts")	
	savedFile = os.popen(VOLATILITYBIN + " -f " + imagefile +  " --profile=" + profile + " procdump -D \"./" + os.path.basename(imagefile) +  "_artifacts/\" -p " + PID + " 2>/dev/null | grep OK: | awk '{print $5}'").read().lstrip().rstrip()
	volOutput = os.popen(VOLATILITYBIN + " -f " + imagefile +  " --profile=" + profile + " handles -p " + PID + " 2>/dev/null").read()
	with open(os.getcwd() + "/" + os.path.basename(imagefile) + '_artifacts/' + PID  + '.handles', 'w') as f:
		f.write(volOutput)

	return savedFile

def clamscan_artifact(imagefile, artifactfile):
	clamOutput = ""
	#print "DEBUG: " + os.getcwd() + "/" + os.path.basename(imagefile) + "_artifacts/" + artifactfile + " ------\n"
	clamOutput = os.popen(CLAMSCANBIN + " --no-summary " + os.getcwd() + "/" + os.path.basename(imagefile) + "_artifacts/" + artifactfile).read().lstrip().rstrip()	
	
	#print "--- DEBUG:" + clamOutput + " ------" 
	clamOutput = clamOutput.split(":")[1].rstrip().lstrip()
	return clamOutput.rstrip().lstrip()



def banner_logo():
	print """  __  __       _ _                 _   
 |  \/  |     | | |               | |  
 | \  / | __ _| | |__  _   _ _ __ | |_ 
 | |\/| |/ _` | | '_ \| | | | '_ \| __|
 | |  | | (_| | | | | | |_| | | | | |_ 
 |_|  |_|\__,_|_|_| |_|\__,_|_| |_|\__|
                                       
Hunt malware with Volatility!

Andrea Fortuna
andrea@andreafortuna.org
https://www.andreafortuna.org
"""

def banner_usage():
	print " Usage:"
	print "	" + sys.argv[0] + " imagefile"

def check_env():
	if  not os.path.exists(MALHUNTHOME):
		os.makedirs(MALHUNTHOME)

def main():
	banner_logo()
	check_env()
	if len(sys.argv) <2:
		banner_usage()
		return ""
	imageFile = sys.argv[1]
	clean_up()
	if CLAMSCANBIN == "":
		print ("\033[41mClamscan not installed...\033[0m")
	if not os.path.isfile(MALHUNTHOME + '/malware_rules.yar'):
		print "\033[1m* \033[0mUpdate malware yara rules..."
		get_rules_from_git()
		all_yara_files = list_yara_files()
		all_yara_filtered_1 = remove_incompatible_imports(all_yara_files)
		all_yara_filtered_2 = fix_duplicated_rules(all_yara_filtered_1)
		merge_rules(all_yara_filtered_2)
	else:
		print "\033[1m* \033[0mUsing cached yara rules..."
	print "\033[1m** \033[0mStarting image identification for file \033[4m" + imageFile + "\033[0m..."
	volProfile = image_identification(imageFile)
	if (volProfile ==""):
		print "Image identification failed!"
		return ""
	print "Image \033[4m" + imageFile + "\033[0m identified as \033[1m" + volProfile + "\033[0m"

	scanresult = []

	sys.stdout.write("\033[1m*** \033[0mStarting malware artifacts search...")
	sys.stdout.flush()
	sys.stdout.write("Yarascan...")
	sys.stdout.flush()
	scanresult = yarascan(imageFile, volProfile, scanresult)
	sys.stdout.write("Malfind...")
	sys.stdout.flush()
	scanresult = malfindscan(imageFile, volProfile, scanresult)
        sys.stdout.write("Network...")
        sys.stdout.flush()
        scanresult = networkscan(imageFile, volProfile, scanresult)
	sys.stdout.write("Done!\n")
	sys.stdout.flush()

	if (len(scanresult) > 0):
		print "\033[41m**** Suspicious processes ****\033[0m"
		for singleProcess in scanresult:
			sys.stdout.write("\t \033[1m" + singleProcess.rule + "\033[0m: \033[4m" + singleProcess.process + "\033[0m (" + singleProcess.pid + ")\n")
			sys.stdout.flush()
			sys.stdout.write('\t\tSaving process memory and handles...')
			sys.stdout.flush()
			artifactFile = dump_process(imageFile,volProfile,singleProcess.pid)
			if (artifactFile != ""):
				print "done!"
			else:
				print ("\x1b[6;30;42mNo file!\x1b[6;30;0m")
				continue
			sys.stdout.write('\t\tScanning artifact with ClamScan...')
			sys.stdout.flush()
			clamscanOutput = clamscan_artifact(imageFile,artifactFile)
			if (clamscanOutput != "OK"):
				print ("\033[41m" + clamscanOutput + "\033[0m")
			else:
				print ("\x1b[6;30;42mOK\x1b[6;30;0m")
		print "\nArtifacts saved into " + os.getcwd() + "/" + os.path.basename(imageFile) + "_artifacts/"
	else:
		print "\033[92mNo artifacts found!\033[0m"

	print "Full scan results saved in \033[4m" + MALHUNTHOME + "/"  + os.path.basename(imageFile) + ".malware_search\033[0m"

# Main body
if __name__ == '__main__':
	main()
