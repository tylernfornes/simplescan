#!/usr/bin/env python

#Filename: virusscan.py
#Author: Tyler Fornes
#Date: 12/6/15
#Purpose: Identifies malicious content within a given directory
# 	  using YARA string comparisons of known malicious signatures

import os
import sys
import yara

#array to store infected files
infected = []

#get search direcotry from command line 
base_dir = sys.argv[1]

#read in and compile YARA rule file
rules = yara.compile(filepath=sys.argv[2])

#Initiate virus scan
print"\n"
print "DIRECTORY SCAN INITIATED"
#Perform firectory walk
for dir_name, subdir_name, file_name in os.walk(base_dir):
	print "Directory: " + dir_name
	for name in file_name:
        	#ensures that yara rule file is not being checked
		if name != sys.argv[2]:
			print "    " + name
			matches = rules.match(name)
			#if a match is found, flag user and note filename
			if matches:
				print "        MALICIOUS CONTENT DETECTED!"
				infected.append(name)

#Print infection report for user
print "SCAN COMPLETED\n"
print "INFECTION REPORT"
print("\n".join(map(str, infected)))
print "\n"
