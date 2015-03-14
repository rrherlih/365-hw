#!/usr/bin/env python3

import sys
from struct import unpack

class FATanalysis:

	def __init__(self, image):
		self.image = image

	def offset_check(self):
		self.fd.seek(510)
		if hex(unpack("<H", self.fd.read(2))[0]) == "0xaa55":
			self.offset = 0
		else:
			self.offset = 1
			self.fd.seek(self.fd.tell()-1)
			while hex(unpack("<H", self.fd.read(2))[0]) != "0xaa55":
				self.fd.seek(self.fd.tell()-1)
				self.offset += 1

	def run_analysis(self):
		self.open_image()
		self.offset_check()
		self.content_info()
		self.fs_info_first()
		self.fs_layout()
		print("FILE SYSTEM INFORMATION")
		print("-" * 40)
		self.fs_info_print()
		print("\nFile System Layout (in sectors)")
		self.layout_print()
		print("\nCONTENT INFORMATION")
		print("-" * 40)
		self.content_print()
		self.fd.close()

	def open_image(self):
		try:
			self.fd = open(self.image, 'rb')
		except FileNotFoundError:
			print("Unable to locate this file.")
			sys.exit()
		except:
			print("Error opening the file.")
			sys.exit()


	def content_info(self):
		self.fd.seek(11 + self.offset)	
		self.sector_size = unpack("<H", self.fd.read(2))[0]
		self.cluster_size = unpack("<B", self.fd.read(1))[0] * self.sector_size	

	def fs_layout(self):
		self.fd.seek(14 + self.offset)
		b = unpack("<HBH", self.fd.read(5))
		self.reserved_area_clusters = b[0]
		self.num_of_fats = b[1]
		self.max_rd_files = b[2]

		self.fd.seek(19 + self.offset)	
		num = unpack("<H", self.fd.read(2))[0]
		if num == 0:
			self.fd.seek(32 + self.offset)
			self.num_sec_in_fs = unpack("<L", self.fd.read(4))[0]
		else:
			self.num_sec_in_fs = num
		
		self.fd.seek(22 + self.offset)
		size = unpack("<H", self.fd.read(2))[0]
		s = self.reserved_area_clusters
		self.FATs = ""
		for i in range(0, self.num_of_fats):
			if i == (self.num_of_fats - 1):
				self.FATs += "FAT {}: {} - {}".format(i, s, s + size - 1)
			else:
				self.FATs += "FAT {}: {} - {}\n".format(i, s, s + size - 1)
			s = s + size
		self.data_start = s

		self.rd_range = (self.max_rd_files * 32) / self.sector_size
		self.rd_end = int(self.data_start + self.rd_range) - 1
		
		spc = self.cluster_size / self.sector_size
		self.total_clusters = (self.num_sec_in_fs - self.rd_end - 1)/spc
		self.cluster_end = int(int(self.total_clusters) * spc + self.rd_end)

	def fs_info_first(self):
		self.fd.seek(3 + self.offset)		
		self.oem_name = bytes.decode(self.fd.read(8))
		self.fd.seek(39 + self.offset)	
		self.volume_id = "{0:#x}".format(unpack("<L", self.fd.read(4))[0])
		self.vol_label = bytes.decode(self.fd.read(11))
		self.fs_type_label = bytes.decode(self.fd.read(5))


	def fs_info_print(self):
		if self.total_clusters < 4085:
			print("File System Type: FAT12\n")
		elif self.total_clusters >= 65525:
			print("File System Type: FAT32\n")
		else:
			print("File System Type: FAT16\n")
		print("OEM Name:", self.oem_name)
		print("Volume ID:", self.volume_id)
		print("Volume Label (Boot Sector):", self.vol_label)
		print("File System Type Label:", self.fs_type_label)

	def layout_print(self):
		print("Total Range: 0 -", self.num_sec_in_fs - 1)
		print("Total Range in Image: 0 -", self.cluster_end)
		print("Reserved: 0 -", self.reserved_area_clusters - 1)
		print("Boot Sector: 0")
		print(self.FATs)
		print("Data Area: {} - {}".format(self.data_start, self.num_sec_in_fs - 1))
		print("Root Directory: {} - {}".format(self.data_start, self.rd_end))
		print("Cluster Area: {} - {}".format(self.rd_end + 1, self.cluster_end))
		print("Non-Clustered: {} - {}".format(self.cluster_end + 1, self.num_sec_in_fs - 1))

	def content_print(self):
		print("Sector Size:", self.sector_size)
		print("Cluster Size:", self.cluster_size)
		print("Total Cluster Range: 2 - {}".format(int(self.total_clusters + 1)))


def usage():
	print("Use this format:\n{} filename".format(sys.argv[0]))

def main():
	if len(sys.argv) != 2:
		usage()
	else:
		f = FATanalysis(sys.argv[1])
		f.run_analysis()

if __name__ == '__main__':
    main()