class ByteStream:
    def __init__(self, bytes):
        self.bytes = bytes
    def __len__(self):
        return len(self.bytes)
    def __str__(self):
        if len(self) > 10:
            return(f"a stream of {len(self)} bytes beginning with {self.bytes[0:10]}")
        else:
            return(f"a stream of {len(self)} bytes beginning with {self.bytes}")
    # make the class iterable with __iter__() and __next__() 
    def __iter__(self):
        self.byteIndex = 0
        self.byteIter = self.bytes[0]
        return self
    def __next__(self):
        if (self.byteIndex == len(self) - 1):
            raise StopIteration
        else:
            curr = self.byteIter
            self.byteIndex += 1
            self.byteIter = self.bytes[self.byteIndex]
            return curr
    # make the class subscriptable with __getitem__()
    def __getitem__(self, key):
        return self.bytes[key]
        

class File(ByteStream):
    filetype = "file"
    def __init__(self, filename):
        with open(filename, "rb") as f:
            self.bytes = f.read()


class Text(File):
    filetype = "ASCII text"
    def __init__(self, filename):
        super().__init__(filename)

# https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
class Elf(File):
    def __init__(self, filename):
        super().__init__(filename)
        # must make ByteStream subscriptable before doing next line
        self.e_ident = ByteStream(self.bytes[0:17])

        # parse bitness from the header
        if (self.e_ident[4] == 1):
            self.EI_CLASS = "ELFCLASS32"
        elif (self.e_ident[4] == 2):
            self.EI_CLASS = "ELFCLASS64"
        else:
            self.EI_CLASS = "ELFCLASSNONE"
        # parse endianness from the header
        if (self.e_ident[5] == 1):
            self.EI_DATA = "ELFDATA2LSB"
        elif (self.e_ident[5] == 2):
            self.EI_DATA = "ELFDATA2MSB"
        else:
            self.EI_DATA = "ELFDATANONE"
        # parse version from the header
        if (self.e_ident[6] == 1):
            self.EI_VERSION = "EV_CURRENT"
        else:
            self.EI_VERSION = "EV_NONE"
        # parse the ABI
        if (self.e_ident[7] == 0):      self.EI_OSABI = "ELFOSABI_NONE"
        elif (self.e_ident[7] == 1):    self.EI_OSABI = "ELFOSABI_HPUX"
        elif (self.e_ident[7] == 2):    self.EI_OSABI = "ELFOSABI_NETBSD"
        elif (self.e_ident[7] == 3):    self.EI_OSABI = "ELFOSABI_LINUX"
        # 4, 5 not implemented
        elif (self.e_ident[7] == 6):    self.EI_OSABI = "ELFOSABI_SOLARIS"
        elif (self.e_ident[7] == 7):    self.EI_OSABI = "ELFOSABI_AIX"
        elif (self.e_ident[7] == 8):    self.EI_OSABI = "ELFOSABI_IRIX"
        elif (self.e_ident[7] == 9):    self.EI_OSABI = "ELFOSABI_FREEBSD"
        elif (self.e_ident[7] == 10):   self.EI_OSABI = "ELFOSABI_TRU64"
        elif (self.e_ident[7] == 11):   self.EI_OSABI = "ELFOSABI_MODESTO"
        elif (self.e_ident[7] == 12):   self.EI_OSABI = "ELFOSABI_OPENBSD"
        elif (self.e_ident[7] == 13):   self.EI_OSABI = "ELFOSABI_OPENVMS"
        elif (self.e_ident[7] == 14):   self.EI_OSABI = "ELFOSABI_NSK"
        else:                           self.EI_OSABI = "ELFOSABI_NONE"
        # ABI-specific field
        self.EI_ABIVERSION = self.e_ident[8]
        # once header has parsed, getStructure and its child functions will work
        self.filetype = self.getStructure()

    def getBitness(self):
        if (self.EI_CLASS == "ELFCLASSNONE"):
            return None
        else:
            bitnessAsInt = int(self.EI_CLASS[8:10])
            return bitnessAsInt
    
    def getEndianness(self):
        if self.EI_DATA == "ELFDATANONE":
            return None
        else:
            return self.EI_DATA[8:11]
    
    def getStructure(self):
        if (self.isValidElf()):
            return(f"ELF {self.getBitness()}-bit {self.getEndianness()} executable")
        else:
            return "Malformed ELF file"
    
    def isValidElf(self):
        padding = int.from_bytes(self.e_ident[9:16])
        if (self.e_ident[0] != 0x7f):       return False
        elif (self.e_ident[1] != ord("E")): return False
        elif (self.e_ident[2] != ord("L")): return False
        elif (self.e_ident[3] != ord("F")): return False
        elif (self.EI_CLASS == 0):          return False
        elif (self.EI_DATA == 0):           return False
        elif (padding != 0):                return False
        else:                               return True

# Sourced from - https://0xrick.github.io/categories/#win-internals
class Win32(File):
    def __init__(self, filename):
        super().__init__(filename)
        self.filetype = "PE32"
        # TODO: convert individual headers to classes
        self.IMAGE_DOS_HEADER = self.bytes[0:0x40]
        self.parse_dos_header(self.IMAGE_DOS_HEADER)
        self.IMAGE_DOS_STUB = self.bytes[0x40:0x80]
        if (self.e_lfanew > 0x80):
            self.IMAGE_RICH_HEADER = self.bytes[0x80:self.e_lfanew]
        else:
            self.IMAGE_RICH_HEADER = None
        self.IMAGE_NT_HEADERS = self.bytes[self.e_lfanew:self.e_lfanew+100]
        self.parse_nt_headers()
        self.filetype = self.getStructure()
    
    def isValidPE(self):
        if self.e_magic != b'MZ':               return False
        elif self.Signature != b'PE\x00\x00':   return False
        elif    ((self.Magic != b'\x0b\x01') and
                (self.Magic != b'\x0b\x02') and 
                (self.Magic != b'\x07\x01')):   return False
        else:                                   return True

    def getStructure():
        return

    def parse_dos_header(self, IMAGE_DOS_HEADER):
        self.e_magic = IMAGE_DOS_HEADER[0:2]            # Magic number
        self.e_cblp = IMAGE_DOS_HEADER[2:4]             # Bytes on last page of file
        self.e_cp = IMAGE_DOS_HEADER[4:6]               # Pages in file
        self.e_crlc = IMAGE_DOS_HEADER[6:8]             # Relocations
        self.e_cparhdr = IMAGE_DOS_HEADER[8:0xa]        # Size of header in paragraphs
        self.e_minalloc = IMAGE_DOS_HEADER[0xa:0xc]     # Minimum extra paragraphs needed
        self.e_maxalloc = IMAGE_DOS_HEADER[0xc:0xe]     # Maximum extra paragraphs needed
        self.e_ss = IMAGE_DOS_HEADER[0xe:0x10]          # Initial (relative) SS value
        self.e_sp = IMAGE_DOS_HEADER[0x10:0x12]         # Initial SP value
        self.e_csum = IMAGE_DOS_HEADER[0x12:0x14]       # Checksum
        self.e_ip = IMAGE_DOS_HEADER[0x14:0x16]         # Initial IP value
        self.e_cs = IMAGE_DOS_HEADER[0x16:0x18]         # Initial (relative) CS value
        self.e_lfarlc = IMAGE_DOS_HEADER[0x18:0x1a]     # File address of relocation table
        self.e_ovno = IMAGE_DOS_HEADER[0x1a:0x1c]       # Overlay number
        self.e_res = IMAGE_DOS_HEADER[0x1c:0x24]        # Reserved words
        self.e_oemid = IMAGE_DOS_HEADER[0x24:0x26]      # OEM identifier (for e_oeminfo)
        self.e_oeminfo = IMAGE_DOS_HEADER[0x26:0x28]    # OEM information = IMAGE_DOS_HEADER[] # e_oemid specific
        self.e_res2 = IMAGE_DOS_HEADER[0x28:0x3c]       # Reserved words
        self.e_lfanew = IMAGE_DOS_HEADER[0x3c:0x40]     # File address of new exe header
        self.e_lfanew = int.from_bytes(self.e_lfanew, byteorder='little')
    
    def parse_rich_header(self):
        return
    
    def parse_nt_headers(self):
        self.Signature = self.IMAGE_NT_HEADERS[0:4]
        self.FileHeader = self.IMAGE_NT_HEADERS[4:0x18]
        self.parse_coff_header(self.FileHeader)
        # TODO: pull sizeOfOH from COFF Header
        self.OptionalHeader = self.IMAGE_NT_HEADERS[0x18:0x18+self.SizeOfOptionalHeader]
        self.parse_optional_header(self.OptionalHeader)

    def parse_coff_header(self, header):
        # TODO: go through MS docs and get actual values for each
        # byte representation of Machine
        self.Machine =                  header[0x00:0x02]
        self.NumberOfSections =         header[0x02:0x04]
        # TODO: convert to actual timestamp
        self.TimeDateStamp =            header[0x04:0x08]
        self.PointerToSymbolTable =     header[0x08:0x0c]
        self.NumberOfSymbols =          header[0x0c:0x10]
        sizeOfOptionalHeader =          header[0x10:0x12]
        self.SizeOfOptionalHeader =     int.from_bytes(sizeOfOptionalHeader, byteorder='little')
        # TODO: go through MS docs and get actual values for each
        # byte representation of Characteristics
        self.Characteristics =          header[0x12:0x14]

    def parse_optional_header(self, header):
        self.Magic = header[0x00:0x02]
        self.MajorLinkerVersion = header[0x02:0x03]
        self.MinorLinkerVersion = header[0x03:0x04]
        self.SizeOfCode = header[0x04:0x08]
        self.SizeOfInitializedData = header[0x08:0x0c]
        self.SizeOfUninitializedData = header[0xc:0x10]
        self.AddressOfEntryPoint = header[0x10:0x14]
        self.BaseOfCode = header[0x14:0x18]
        self.BaseOfData = header[0x18:0x1c]
        # TODO: add additional/optional fields
        return


# TODO: Create unified PE class that Win32 and Win64 can inherit from
class PE(File):
    def __init__(self, filename):
        super().__init__(filename)
        self.filetype = "PE"
        # TODO: convert individual headers to classes
        self.IMAGE_DOS_HEADER = self.bytes[0:0x40]
        self.parse_dos_header(self.IMAGE_DOS_HEADER)
        self.IMAGE_DOS_STUB = self.bytes[0x40:0x80]
        if (self.e_lfanew > 0x80):
            self.IMAGE_RICH_HEADER = self.bytes[0x80:self.e_lfanew]
        else:
            self.IMAGE_RICH_HEADER = None
        self.IMAGE_NT_HEADERS = self.bytes[self.e_lfanew:self.e_lfanew+100]
        self.parse_nt_headers()
        self.filetype = self.getStructure()
    
    def isValidPE(self):
        if self.e_magic != b'MZ':               return False
        elif self.Signature != b'PE\x00\x00':   return False
        elif    ((self.Magic != b'\x0b\x01') and
                (self.Magic != b'\x0b\x02') and 
                (self.Magic != b'\x07\x01')):   return False
        else:                                   return True

    def getStructure():
        return

    # DOS header - same across 32-bit and 64-bit arch
    # https://0xrick.github.io/win-internals/pe3/
    def parse_dos_header(self, IMAGE_DOS_HEADER):
        self.e_magic = IMAGE_DOS_HEADER[0:2]            # Magic number
        self.e_cblp = IMAGE_DOS_HEADER[2:4]             # Bytes on last page of file
        self.e_cp = IMAGE_DOS_HEADER[4:6]               # Pages in file
        self.e_crlc = IMAGE_DOS_HEADER[6:8]             # Relocations
        self.e_cparhdr = IMAGE_DOS_HEADER[8:0xa]        # Size of header in paragraphs
        self.e_minalloc = IMAGE_DOS_HEADER[0xa:0xc]     # Minimum extra paragraphs needed
        self.e_maxalloc = IMAGE_DOS_HEADER[0xc:0xe]     # Maximum extra paragraphs needed
        self.e_ss = IMAGE_DOS_HEADER[0xe:0x10]          # Initial (relative) SS value
        self.e_sp = IMAGE_DOS_HEADER[0x10:0x12]         # Initial SP value
        self.e_csum = IMAGE_DOS_HEADER[0x12:0x14]       # Checksum
        self.e_ip = IMAGE_DOS_HEADER[0x14:0x16]         # Initial IP value
        self.e_cs = IMAGE_DOS_HEADER[0x16:0x18]         # Initial (relative) CS value
        self.e_lfarlc = IMAGE_DOS_HEADER[0x18:0x1a]     # File address of relocation table
        self.e_ovno = IMAGE_DOS_HEADER[0x1a:0x1c]       # Overlay number
        self.e_res = IMAGE_DOS_HEADER[0x1c:0x24]        # Reserved words
        self.e_oemid = IMAGE_DOS_HEADER[0x24:0x26]      # OEM identifier (for e_oeminfo)
        self.e_oeminfo = IMAGE_DOS_HEADER[0x26:0x28]    # OEM information = IMAGE_DOS_HEADER[] # e_oemid specific
        self.e_res2 = IMAGE_DOS_HEADER[0x28:0x3c]       # Reserved words
        self.e_lfanew = IMAGE_DOS_HEADER[0x3c:0x40]     # File address of new exe header
        self.e_lfanew = int.from_bytes(self.e_lfanew, byteorder='little')
    
    # not yet implemented
    def parse_rich_header(self):
        return
    
    # NT Headers - structure is the same except for optional header
    # https://0xrick.github.io/win-internals/pe4/#nt-headers-image_nt_headers
    def parse_nt_headers(self):
        self.Signature = self.IMAGE_NT_HEADERS[0:4]
        self.FileHeader = self.IMAGE_NT_HEADERS[4:0x18]
        self.parse_coff_header(self.FileHeader)
        # TODO: pull sizeOfOH from COFF Header
        self.OptionalHeader = self.IMAGE_NT_HEADERS[0x18:0x18+self.SizeOfOptionalHeader]
        # TODO: make inherited function parse the opt header
        # self.parse_optional_header(self.OptionalHeader)

    # File header/COFF header - same across PE32 and PE32+
    # https://0xrick.github.io/win-internals/pe4/#file-header-image_file_header
    def parse_coff_header(self, header):
        # TODO: go through MS docs and get actual values for each
        # byte representation of Machine
        self.Machine =                  header[0x00:0x02]
        self.NumberOfSections =         header[0x02:0x04]
        # TODO: convert to actual timestamp
        self.TimeDateStamp =            header[0x04:0x08]
        self.PointerToSymbolTable =     header[0x08:0x0c]
        self.NumberOfSymbols =          header[0x0c:0x10]
        sizeOfOptionalHeader =          header[0x10:0x12]
        self.SizeOfOptionalHeader =     int.from_bytes(sizeOfOptionalHeader, byteorder='little')
        # TODO: go through MS docs and get actual values for each
        # byte representation of Characteristics
        self.Characteristics =          header[0x12:0x14]


        

def main():
    test1 = ByteStream("MZ1234\xff")
    for b in test1:
        print(b, end=" ")
    print()
    print("======================================")
    
    testelf2 = Elf("./samples/test-elf")
    print(testelf2)
    print(testelf2.filetype)
    print("======================================")
    
    atm = Elf("./samples/atm")
    print(atm)
    print(atm.filetype)
    print("======================================")

    exe1 = Win32("./samples/pe32.exe")
    print(exe1)
    print(exe1.isValidPE())
    print(exe1.Signature)
    print(exe1.Magic)
    print(exe1.IMAGE_DOS_HEADER)
    print(exe1.IMAGE_DOS_STUB)
    print(exe1.IMAGE_RICH_HEADER)
    print(exe1.IMAGE_NT_HEADERS)
    print("======================================")
    
    exe2 = Win32("./samples/pe64.exe")
    print(exe2)
    print(exe2.filetype)
    print("======================================")

if __name__ == "__main__":
    main()