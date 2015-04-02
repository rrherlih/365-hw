#!/usr/bin/env python3

""" Ryan Herlihy
	CS365 - HW5
"""

import sys
from struct import unpack


""" This is the class for processing the NTFS image. It take an integer as an argument
	and returns the corresponding MFT entry information.
"""
class NTFS:


	""" The the starting bytes of each MFT entry are stored in the self.MFT array."""
	def __init__(self, entry):
		self.entry = entry
		self.MFT = []


	""" Open the image file, then run process_bs which looks at the boot sector first.
		This file is then closed."""
	def open_file(self, filename):
		try:
			self.fd = open(filename, 'rb')
		except:
			print("Error occurred while opening the file.")
			sys.exit()
		self.process_bs()	
		self.fd.close()


	def process_bs(self):
		""" This skips to where the important information begins."""
		self.fd.seek(11)

		""" Finds bytes per sector and sectors per cluster."""
		self.bps = unpack("<H", self.fd.read(2))[0]
		self.spc = unpack("<B", self.fd.read(1))[0]

		""" Finds total sectors in the file system and the starting cluster of the MFT."""
		self.fd.seek(40)
		self.ts_in_fs = unpack("<Q", self.fd.read(8))[0]
		self.sc_MFT = unpack("<Q", self.fd.read(8))[0]

		""" Finds the size of each MFT entry and index record."""
		self.fd.seek(64)
		self.MFT_entry_size = unpack("<B", self.fd.read(1))[0] * self.spc * self.bps
		self.fd.seek(68)
		self.ir_size = unpack("<B", self.fd.read(1))[0]

		""" Calculates the starting byte of the MFT."""
		sb_MFT = self.sc_MFT * self.spc * self.bps

		""" Finds the MFT using starting byte and processes it for its data."""
		self.process_MFT(sb_MFT)


	def process_MFT(self, start):
		""" Seeks to MFT then reads in the first entry which is for the MFT itself.
			It then finds the offset to the attributes."""
		self.fd.seek(start)
		MFT_entry = self.fd.read(self.MFT_entry_size)
		ofs_attr = unpack("<H", MFT_entry[20:22])[0]
		
		""" This while loop starts at the first attribute. It gathers some info about the
			attribute and determines whether or not it is the DATA. If its not, it goes to
			the next attribute."""
		while True:
			attributes = MFT_entry[ofs_attr:self.MFT_entry_size]
			type_id = unpack("<L", attributes[0:4])[0]	
			attr_len = unpack("<L", attributes[4:8])[0]
			non_res_fl = attributes[8]
			if type_id == 128:
				break
			else:
				ofs_attr = ofs_attr + attr_len

		""" If the data is resident, then theres an error and we've found the wrong entry or attribute."""
		if non_res_fl != 1:
			print("Error occured during search for the MFT of this NTFS image.\nThis entry is resident.")
			sys.exit()
		
		""" This finds the offset to the runlist of where all the entries are on disk.
			Then a function process_nr_data takes the offset to retrieve the starting sectors
			and lengths of runs."""
		rl_offs = unpack("<H", attributes[32:34])[0]
		table_arr = self.process_nr_data(rl_offs, attributes)

		""" This loop makes sure any negative offsets in the runlist are converted to be the actual
			offset into the filesystem in sectors"""
		for i in range(1, len(table_arr)):
			table_arr[i][0] = table_arr[i][0] + table_arr[i-1[0]]

		""" This finds the number of clusters per MFT entry then calculates the starting byte of each 
			MFT entry and puts it into the array. So now all entries numbers correspond with
			the index in the array."""
		cls_per_entry = self.MFT_entry_size / (self.bps * self.spc)
		for entry in table_arr:
			b = self.bps * self.spc
			l = entry[1]
			c = entry[0] * b
			while l > 0:
				self.MFT.append(c)
				c = c + self.MFT_entry_size
				l = l - cls_per_entry

		if self.entry == 5:
			print("Boot Sector")
		else:
			""" Once the MFT is completed, the inputted MFT entry number is put into a function
				which will parse the entry."""		
			self.process_MFT_entry(self.MFT[self.entry])


	def process_MFT_entry(self, start):
		""" Finds the start of the entry and reads the whole entry into a variable"""
		self.fd.seek(start)
		MFT_entry = self.fd.read(self.MFT_entry_size)

		""" Finds signature, offset to fixup, # of entries in fixup. Then the function
			process_fixup will check the fixup values."""
		sig = MFT_entry[0:4]
		ofs_fixup = unpack("<H", MFT_entry[4:6])[0]
		e_in_fixup = unpack("<H", MFT_entry[6:8])[0]
		self.process_fixup(ofs_fixup, e_in_fixup, MFT_entry)

		""" Finds LSN, sequence value, and link count"""
		lsn = unpack("<Q", MFT_entry[8:16])[0]
		sequence = unpack("<H", MFT_entry[16:18])[0]
		link = unpack("<H", MFT_entry[18:20])[0]

		""" Offset to the first attribute"""
		ofs_attr = unpack("<H", MFT_entry[20:22])[0]

		""" Finds flags, used size, and allocated size"""
		flags = unpack("<H", MFT_entry[22:24])[0]
		usize_MFT = unpack("<L", MFT_entry[24:28])[0]
		asize_MFT = unpack("<L", MFT_entry[28:32])[0]

		""" This prints the first part containing the MFT head values."""
		print("\nMFT Entry Header Values:")
		print("Sequence: {}".format(sequence))
		print("$LogFile Sequence Number: {}".format(lsn))
		if flags == 1:
			print("Allocated File\nDirectory")
		else:
			print("Unallocated File")
		print("\nUsed size: {} bytes".format(usize_MFT))
		print("Allocated size: {} bytes".format(asize_MFT))

		""" The offset attribute and the mft entry are sent to a the process attribute
			function that print out the information for each attribute."""
		self.process_attr(ofs_attr, MFT_entry)


	def process_attr(self, start, mft_entry):
		""" The attributes portion of the mft entry are put into a variable to make 
			finding the offsets to values easier"""
		attributes = mft_entry[start:self.MFT_entry_size]

		""" Type ID, attribute length, non-resident flag, name length, offset to name, flags, attribure ID"""
		type_id = unpack("<L", attributes[0:4])[0]				
		attr_len = unpack("<L", attributes[4:8])[0]
		non_res_fl = unpack("<B", attributes[8:9])[0]
		name_len = unpack("<B", attributes[9:10])[0]
		name_offs = unpack("<H", attributes[10:12])[0]
		flags = unpack("<H", attributes[12:14])[0]
		attr_id = unpack("<H", attributes[14:16])[0]

		""" This checks for only the STANDARD_INFO, FILE_NAME, and DATA attributes"""
		if type_id in (16, 48, 128): 

			""" If the attributes data is non resident, the non_res_attr function processes it."""
			if non_res_fl == 1:
				self.non_res_attr(attributes)		
			else:
				""" If the data is resident, the content is parsed by the attribute type."""
				content_size = unpack("<L", attributes[16:20])[0]
				content_offs = unpack("<H", attributes[20:22])[0]
				content = attributes[content_offs:content_offs+attr_len]

				""" If the attribute is STANDARD_INFO, its content is parsed and printed out."""
				if type_id == 16:
					print("\n$STANDARD_INFO ({}-{}) Namelen: ({}) Resident size: {}"
						.format(attr_id, type_id, name_len, attr_len))
					self.parse_std_info(content)

				""" If the attribute is FILE_NAME, its content is parsed and printed out."""
				if type_id == 48:
					print("\n$FILE_NAME ({}-{}) Namelen: ({}) Resident size: {}"
						.format(attr_id, type_id, name_len, attr_len))
					self.parse_file_name(content)

		""" This makes sure that we stop processing attributes when there are no more left.
			If the next attribute has a length, then we make a recursive call with the
			attribute length which will process the next attribute."""
		if attr_len > 0:
			self.process_attr(attr_len, attributes)


	""" This parses the STANDARD_INFO attribute information and then prints it out."""
	def parse_std_info(self, content):
		create_time = unpack("<Q", content[0:8])[0]
		file_alt_time = unpack("<Q", content[8:16])[0]
		MFT_alt_time = unpack("<Q", content[16:24])[0]
		file_acc_time = unpack("<Q", content[24:32])[0]
		flags = unpack("<L", content[32:36])[0]
		max_num_vers = unpack("<L", content[36:40])[0]
		ver_num = unpack("<L", content[40:44])[0]
		class_id = unpack("<L", content[44:48])[0]
		owner_id = unpack("<L", content[48:52])[0]
		sec_id = unpack("<L", content[52:56])[0]
		quota_charge = unpack("<Q", content[56:64])[0]
		usn = unpack("<Q", content[64:72])[0]

		print("file_accessed: {}".format(file_acc_time))
		print("Owner ID: {}".format(owner_id))
		print("version number: {}".format(ver_num))
		print("create_time: {}".format(create_time))
		print("Security ID: {}".format(sec_id))
		print("mft altered: {}".format(MFT_alt_time))
		print("Update seq #: {}".format(usn))
		print("flags: {}".format(flags))
		print("max # versions: {}".format(max_num_vers))
		print("Class ID: {}".format(class_id))
		print("Quota Charged: {}".format(quota_charge))
		print("file altered: {}".format(file_alt_time))


	""" This parses the FILE_NAME attribute information and then prints it out."""
	def parse_file_name(self, content):
		file_ref = unpack("<Q", content[0:8])[0]
		create_time = unpack("<Q", content[8:16])[0]
		file_mod_time = unpack("<Q", content[16:24])[0]
		MFT_mod_time = unpack("<Q", content[24:32])[0]
		file_acc_time = unpack("<Q", content[32:40])[0]
		allc_size = unpack("<Q", content[40:48])[0]
		real_size = unpack("<Q", content[48:56])[0]
		flags = unpack("<L", content[56:60])[0]
		reparse = unpack("<L", content[60:64])[0]
		name_len = unpack("<B", content[64:65])[0]
		name_spc = unpack("<B", content[65:66])[0]

		print("Alloc. size of file: {}".format(allc_size))
		print("Length of name: {}".format(name_len))
		print("MFT mod time: {}".format(MFT_mod_time))
		print("Namespace: {}".format(name_spc))
		print("Parent dir: {}".format(file_ref))
		print("Real filesize: {}".format(real_size))
		print("Reparse value: {}".format(reparse))
		print("file access time: {}".format(file_acc_time))
		print("file creation time: {}".format(create_time))
		print("file mod time: {}".format(file_mod_time))
		print("flags: {}".format(flags))


	""" This function is used when an attribute is non resident and its data is in a runlist
		of sectors and lengths."""
	def non_res_attr(self, attr):
		""" This finds the run list offset (rl_offs)"""
		start_VCN = unpack("<Q", attr[16:24])[0]
		end_VCN = unpack("<Q", attr[24:32])[0]
		rl_offs = unpack("<H", attr[32:34])[0]
		cu_size = unpack("<H", attr[34:36])[0]
		content_size = unpack("<Q", attr[48:56])[0]

		""" Using the function process_nr_data, we get the runlist back in the form of
			an array."""
		run_list = self.process_nr_data(rl_offs, attr)

		""" This loop prints out the runlist for the DATA attribute in this assignment."""
		print("\nRunlist:")
		for i in run_list:
			for c in range(0, i[1]):
				print(i[0] + c, end=' ')
		print()


	def process_nr_data(self, start, attr):
		""" An array is created that will later return a runlist"""
		run_array = []

		""" This checks whether the byte split into 4 nibbles, representing the the bytes needed to 
			be unpacked for the length of the run and the offset to the run, is 0 or not. Meaning
			it has no more runs. It will keep processing runs until there are no more."""
		while unpack("<B", attr[start:start+1])[0] != 0:

			""" This uses bitwise operations to finds the number of bytes needed to be unpacked
				for the run length and the run starting cluster"""
			rl_start_b = unpack("<B", attr[start:start+1])[0] >> 4
			rl_len_b = unpack("<B", attr[start:start+1])[0] & 15

			""" Here the bytes found above are unpacked and the starting cluster of the run_list
				and the run length are found."""
			run_start = attr[start+rl_len_b+1:start+rl_len_b+1+rl_start_b]
			run_len = attr[start+1:start+1+rl_len_b]

			""" Here the numbers are padded and the run offset is checked for the correct sign."""
			start_cluster = getSigned(run_start)
			cl_run_length = getSigned(run_len)

			""" A tuple containing the run offset and the length are appended to the array."""
			run_array.append((start_cluster, cl_run_length))

			""" The next byte is found to process the next run in the next iteration of the while loop."""
			start = start + rl_start_b + rl_len_b + 1
		 
		""" array is returned"""
		return(run_array)


	def process_fixup(self, start, entries, mft_entry):
		""" Here the length of the fixup array is calculated to represent two byte groups.
			The bytes are put into a variable and then the signature value is unpacked."""
		fixup_len = entries * 2
		fixup_array = mft_entry[start:start + fixup_len]
		sig_value = unpack("<H", fixup_array[0:2])

		""" Here the last two bytes of each sector are checked. This first line starts at the 
			second to last byte of the first sector. Then a while loop unpacks the two bytes
			and compares them to the signature value. If they don't match there is something 
			wrong with the data structure. Otherwise the next two bytes in the next sector
			are checked."""
		i = self.bps - 2
		while i < len(mft_entry):
			x = unpack("<H", mft_entry[i:i+2])
			if x != sig_value:
				print("Integrity of MFT entry compromised.")
				sys.exit()
				break
			i = i + self.bps

		""" This code replaces the last two values in each sector with the values in the 
			fixup array. The bytes are converted to a bytearray and a while loop goes to
			the last two bytes of each sector and replaces them with the corresponding 
			values in the fixup array. The bytes of the changes data structure are returned."""	
		mft_entry = bytearray(mft_entry)
		i = self.bps - 2
		j = 2
		while i < len(mft_entry):
			mft_entry[i:i+2] = fixup_array[j:j+2]
			i = i + self.bps
			j = j + 2
		return(bytes(mft_entry))


""" This function takes bytes, finds the most significant bit. If its a 1 then its negative
	and the number is padded then unpacked to get the negative number returned. If its a 0
	then its positive and it is also padded, unpacked and returned."""
def getSigned(bArray):
	length = len(bArray)
	sigByte = bArray[-1]
	sign = sigByte >> 7
	if (sign == 0):
		pad = (8-length)*b'\x00'
		return(unpack('<q', bArray + pad)[0])
	elif (sign == 1):
		pad = (8-length)*b'\xFF'
		return(unpack('<q', bArray + pad)[0])


"""Usage method"""
def usage():
	print("Use this format:\n{} filename [MFT entry number]".format(sys.argv[0]))

def main():
	if len(sys.argv) != 3:
		usage()
	else:
		n = NTFS(int(sys.argv[2]))
		n.open_file(sys.argv[1])

if __name__ == '__main__':
    main()