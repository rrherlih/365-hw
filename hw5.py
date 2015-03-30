#!/usr/bin/env python3

""" Ryan Herlihy
	CS365 - HW5
"""

import sys

def open_file(filename):
	fd = open(filename, 'rb')
	print(fd.read(2))

"""Usage method"""
def usage():
	print("Use this format:\n{} filename".format(sys.argv[0]))

def main():
	if len(sys.argv) != 2:
		usage()
	else:
		open_file(sys.argv[1])

if __name__ == '__main__':
    main()