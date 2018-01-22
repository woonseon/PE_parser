#-*- coding: utf-8 -*-

#pip install pefile
import pefile
import sys
reload(sys)
sys.setdefaultencoding('utf-8')


def main(file_location):
	pe = pefile.PE(file_location)

	#print pe

	#print pe.dump_info()

	# IMAGE_DOS_HEADER 출력
	print "=============================================="
	print pe.DOS_HEADER
	print "=============================================="

	# IMAGE_DOS_HEADER 출력
	print "=============================================="
	print pe.DOS_HEADER
	print "=============================================="	

	# NT HEADERS Signature 출력
	print "=============================================="
	print pe.NT_HEADERS
	print "=============================================="

	# IMAGE_FILE_HEADER 출력
	print "=============================================="
	print pe.FILE_HEADER
	print "=============================================="
	# section number
	print u"섹션 개수:"
	print pe.FILE_HEADER.NumberOfSections
	print "=============================================="

	print "=============================================="	
	print pe.OPTIONAL_HEADER
	print "=============================================="

	print "=============================================="
	print u"섹션 이름\t가상 주소(VA)"
	for section in pe.sections:
	    print section.Name + "\t" + hex(section.VirtualAddress)
	print "=============================================="
	#print pe.sections

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print "Put \'python pe_parser.py <PE location>\'"
		sys.exit(1)
	if (".exe" not in sys.argv[1]) and (".dll" not in sys.argv[1]):
		print "put only pe file"
		sys.exit(1)

	main(sys.argv[1])
