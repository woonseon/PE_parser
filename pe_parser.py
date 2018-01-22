#-*- coding: utf-8 -*-

#pip install pefile
import pefile
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

def total_pe(pe):
	f = open("./total_pe.txt", 'w')
	f.write(str(pe))
	f.write("\n")
	f.close()
	# total pe 출력
	print "=============================================="
	print pe
	print "=============================================="

def DOS_HEADER(pe):
	f = open("./Dos_Header.txt", 'w')
	f.write(str(pe.DOS_HEADER))
	f.write("\n")
	f.close()
	# IMAGE_DOS_HEADER 출력
	print "=============================================="
	print pe.DOS_HEADER
	print "=============================================="	

def NT_HEADERS(pe):
	# NT HEADERS Signature 출력
	print "=============================================="
	print pe.NT_HEADERS
	print "=============================================="

def FILE_HEADER(pe):
	f = open("./file_header.txt", 'w')
	f.write(str(pe.FILE_HEADER))
	f.write("\n")
	f.close()
	# IMAGE_FILE_HEADER 출력
	print "=============================================="
	print pe.FILE_HEADER
	print "=============================================="

def NumberOfSections(pe):
	f = open("./number_of_section.txt", 'w')
	f.write(str(pe.FILE_HEADER.NumberOfSections))
	f.write("\n")
	f.close()
	# section number
	print "=============================================="
	print u"섹션 개수:"
	print pe.FILE_HEADER.NumberOfSections
	print "=============================================="

def OPTIONAL_HEADER(pe):
	f = open("./Optional_Header.txt", 'w')
	f.write(str(pe.OPTIONAL_HEADER))
	f.write("\n")
	f.close()
	print "=============================================="	
	print pe.OPTIONAL_HEADER
	print "=============================================="

def Setion_Contents(pe):
	f = open("./Section_Contents.txt", 'ab')
	print "=============================================="
	print "OPTIONAL_HEADER"
	for section in pe.sections:
		f.write(str(section))
		f.write("\n")
		print section
		print "=============================================="
	f.close()
	print "=============================================="

def select_menu():
	print "\n***************************************************************"
	print "***************************************************************"
	print "Select Menu Please"
	print "\t1. Show all PE contents"
	print "\t2. Show DOS_HEADER"
	print "\t3. Show NT_HEADERS"
	print "\t4. Show FILE_HEADER"
	print "\t5. Show Number Of Sections"
	print "\t6. Show OPTIONAL_HEADER"
	print "\t7. Show section contents"
	print "\t8. Exit"
	print "***************************************************************"
	print "***************************************************************\n"
	selection = raw_input("Select menu : ")
	return selection

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print "Put \'python pe_parser.py <PE location>\'"
		sys.exit(1)
	if (".exe" not in sys.argv[1]) and (".dll" not in sys.argv[1]):
		print "put only pe file"
		sys.exit(1)

	pe = pefile.PE(sys.argv[1])

	while True:
		select = select_menu()
		if select is '1':
			total_pe(pe)
		elif select is '2':
			DOS_HEADER(pe)
		elif select is '3':
			NT_HEADERS(pe)
		elif select is '4':
			FILE_HEADER(pe)
		elif select is '5':
			NumberOfSections(pe)
		elif select is '6':
			OPTIONAL_HEADER(pe)
		elif select is '7':
			Setion_Contents(pe)
		else:
			print u"종료"
			sys.exit(1)
