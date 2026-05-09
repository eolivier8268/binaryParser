import textwrap
import prodids

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
    def __init__(self, filename, bytes):
        self.filename = filename
        self.bytes = bytes

    @classmethod
    def read_bytes(cls, filename):
        rawBytes = b''
        with open(filename, "rb") as f:
            rawBytes = f.read()
        return cls(filename, rawBytes)


class Text(File):
    filetype = "ASCII text"
    def __init__(self, filename):
        super().__init__(filename)


class ElfIdentificationHeader(ByteStream):
    def __init__(self, bytes, EI_CLASS, EI_DATA, EI_VERSION, EI_OSABI, EI_ABIVERSION):
        self.bytes = bytes
        self.EI_CLASS = EI_CLASS
        self.EI_DATA = EI_DATA
        self.EI_VERSION = EI_VERSION
        self.EI_OSABI = EI_OSABI
        self.EI_ABIVERSION = EI_ABIVERSION

    @classmethod
    def parse_bytes(cls, bytes):
        if (bytes[4] == 1):
            EI_CLASS = "ELFCLASS32"
        elif (bytes[4] == 2):
            EI_CLASS = "ELFCLASS64"
        else:
            EI_CLASS = "ELFCLASSNONE"
        # parse endianness from the header
        if (bytes[5] == 1):
            EI_DATA = "ELFDATA2LSB"
        elif (bytes[5] == 2):
            EI_DATA = "ELFDATA2MSB"
        else:
            EI_DATA = "ELFDATANONE"
        # parse version from the header
        if (bytes[6] == 1):
            EI_VERSION = "EV_CURRENT"
        else:
            EI_VERSION = "EV_NONE"
        # parse the ABI
        if (bytes[7] == 0):      EI_OSABI = "ELFOSABI_NONE"
        elif (bytes[7] == 1):    EI_OSABI = "ELFOSABI_HPUX"
        elif (bytes[7] == 2):    EI_OSABI = "ELFOSABI_NETBSD"
        elif (bytes[7] == 3):    EI_OSABI = "ELFOSABI_LINUX"
        # 4, 5 not implemented
        elif (bytes[7] == 6):    EI_OSABI = "ELFOSABI_SOLARIS"
        elif (bytes[7] == 7):    EI_OSABI = "ELFOSABI_AIX"
        elif (bytes[7] == 8):    EI_OSABI = "ELFOSABI_IRIX"
        elif (bytes[7] == 9):    EI_OSABI = "ELFOSABI_FREEBSD"
        elif (bytes[7] == 10):   EI_OSABI = "ELFOSABI_TRU64"
        elif (bytes[7] == 11):   EI_OSABI = "ELFOSABI_MODESTO"
        elif (bytes[7] == 12):   EI_OSABI = "ELFOSABI_OPENBSD"
        elif (bytes[7] == 13):   EI_OSABI = "ELFOSABI_OPENVMS"
        elif (bytes[7] == 14):   EI_OSABI = "ELFOSABI_NSK"
        else:                    EI_OSABI = "ELFOSABI_NONE"
        # ABI-specific field
        EI_ABIVERSION = bytes[8]

        return cls(bytes, EI_CLASS, EI_DATA, EI_VERSION, EI_OSABI, EI_ABIVERSION)

    def __getitem__(self, key):
        return self.bytes[key]


# https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
class Elf(File):
    def __init__(self, filename, bytes, header):
        self.filename = filename
        self.bytes = bytes
        self.header = header

    @classmethod
    def from_file(cls, filename):
        rawBytes = cls.read_bytes(filename)
        header = ElfIdentificationHeader.parse_bytes(rawBytes[0:17])
        return cls(filename, rawBytes, header)

    @staticmethod
    def read_bytes(filename):
        rawBytes = b''
        with open(filename, "rb") as f:
            rawBytes = f.read()
        return rawBytes

    def get_bitness(self):
        if (self.header.EI_CLASS == "ELFCLASSNONE"):
            return None
        else:
            bitnessAsInt = int(self.header.EI_CLASS[8:10])
            return bitnessAsInt
    
    def get_endianness(self):
        if self.header.EI_DATA == "ELFDATANONE":
            return None
        else:
            return self.header.EI_DATA[8:11]
    
    @property
    def structure(self):
        if (self.is_valid_elf()):
            return(f"ELF {self.get_bitness()}-bit {self.get_endianness()} executable")
        else:
            return "Malformed ELF file"
    
    def is_valid_elf(self):
        padding = int.from_bytes(self.header[9:16])
        if (self.header[0] != 0x7f):       return False
        elif (self.header[1] != ord("E")): return False
        elif (self.header[2] != ord("L")): return False
        elif (self.header[3] != ord("F")): return False
        elif (self.header.EI_CLASS == 0):          return False
        elif (self.header.EI_DATA == 0):           return False
        elif (padding != 0):                return False
        else:                               return True


# DOS header - same across 32-bit and 64-bit arch
class IMAGE_DOS_HEADER(ByteStream):
    def __init__(self, rawBytes):
        self.bytes = rawBytes
        # https://0xrick.github.io/win-internals/pe3/
        self.e_magic = rawBytes[0:2]            # Magic number
        self.e_cblp = rawBytes[2:4]             # Bytes on last page of file
        self.e_cp = rawBytes[4:6]               # Pages in file
        self.e_crlc = rawBytes[6:8]             # Relocations
        self.e_cparhdr = rawBytes[8:0xa]        # Size of header in paragraphs
        self.e_minalloc = rawBytes[0xa:0xc]     # Minimum extra paragraphs needed
        self.e_maxalloc = rawBytes[0xc:0xe]     # Maximum extra paragraphs needed
        self.e_ss = rawBytes[0xe:0x10]          # Initial (relative) SS value
        self.e_sp = rawBytes[0x10:0x12]         # Initial SP value
        self.e_csum = rawBytes[0x12:0x14]       # Checksum
        self.e_ip = rawBytes[0x14:0x16]         # Initial IP value
        self.e_cs = rawBytes[0x16:0x18]         # Initial (relative) CS value
        self.e_lfarlc = rawBytes[0x18:0x1a]     # File address of relocation table
        self.e_ovno = rawBytes[0x1a:0x1c]       # Overlay number
        self.e_res = rawBytes[0x1c:0x24]        # Reserved words
        self.e_oemid = rawBytes[0x24:0x26]      # OEM identifier (for e_oeminfo)
        self.e_oeminfo = rawBytes[0x26:0x28]    # OEM information = rawBytes[] # e_oemid specific
        self.e_res2 = rawBytes[0x28:0x3c]       # Reserved words
        self.e_lfanew = rawBytes[0x3c:0x40]     # File address of new exe header
        self.e_lfanew = int.from_bytes(self.e_lfanew, byteorder='little')

    def __getitem__(self, key):
        return self.bytes[key]


# https://0xrick.github.io/win-internals/pe3/#dos-stub
class IMAGE_DOS_STUB(ByteStream):
    def __init__(self, rawBytes):
        self.bytes = rawBytes
        self.message = str(rawBytes[0x0e:0x38])
    
    def __getitem__(self, key):
        return self.bytes[key]
    

class RichHeaderId():
    def __init__(self, rawIds):
        self.buildId = int(rawIds[0][4:],16)
        self.count = int(rawIds[1],16)
        productIdNumeric = int(rawIds[0][0:4], 16)
        try: 
            self.productID = prodids.int_names[productIdNumeric]
        except KeyError:
            self.productID = "prodidUnknown"
        self.vsVersion = prodids.vs_version(productIdNumeric)
        return
    def __str__(self):
        return f"Compiled with {self.productID} in {self.vsVersion[0]} {self.vsVersion[1]}"
        # alternative way of printing numbers pre-translation - useful for debugging
        # return f"{str(int(self.rawIds[0][4:],16))}.{str(int(self.rawIds[0][0:4],16))}.{str(int(self.rawIds[1],16))}"
        

# https://0xrick.github.io/win-internals/pe3/#rich-header
class IMAGE_RICH_HEADER(ByteStream):
    def __init__(self, rawBytes):
        self.bytes = rawBytes
        data = rawBytes
        key  = rawBytes[0x04:0x08]
        rch_hdr = (IMAGE_RICH_HEADER.xor(data,key)).hex()
        rch_hdr = textwrap.wrap(rch_hdr, 16)

        self.signatures = []
        for i in range(2,len(rch_hdr)):
            tmp = textwrap.wrap(rch_hdr[i], 8)
            f1 = IMAGE_RICH_HEADER.rev_endiannes(tmp[0])
            f2 = IMAGE_RICH_HEADER.rev_endiannes(tmp[1])
            self.signatures.append(RichHeaderId((f1, f2)))


    def xor(data, key):
        return bytearray( ((data[i] ^ key[i % len(key)]) for i in range(0, len(data))) )

    def rev_endiannes(data):
        tmp = [data[i:i+8] for i in range(0, len(data), 8)]
        
        for i in range(len(tmp)):
            tmp[i] = "".join(reversed([tmp[i][x:x+2] for x in range(0, len(tmp[i]), 2)]))
        
        return "".join(tmp)
    
    def __getitem__(self, key):
        return super().__getitem__(key)
    
    def __str__(self):
        output = "RICH HEADER SIGNATURES EXTRACTED:\n"
        for sig in self.signatures:
            output += f"\t\_ {sig}\n"
        # remove trailing newline
        return output[:-1]


# NT Headers - structure is the same except for optional header
# https://0xrick.github.io/win-internals/pe4/#nt-headers-image_nt_headers
class IMAGE_NT_HEADERS(ByteStream):
    def __init__(self, rawBytes):
        self.bytes = rawBytes
        self.Signature = rawBytes[0:4]
        self.coffHeader = COFF_HEADER(rawBytes[4:0x18])
        # self.parse_coff_header(self.FileHeader)
        # TODO: pull sizeOfOH from COFF Header
        optionalHeaderBytes = rawBytes[0x18:0x18+self.coffHeader.SizeOfOptionalHeader]
        self.OptionalHeader = IMAGE_OPTIONAL_HEADER(optionalHeaderBytes)


# File header/COFF header - same across PE32 and PE32+
# https://0xrick.github.io/win-internals/pe4/#file-header-image_file_header
class COFF_HEADER(ByteStream):
    def __init__(self, rawBytes):
        self.bytes = rawBytes
        # TODO: go through MS docs and get actual values for each
        # byte representation of Machine
        self.Machine =                  rawBytes[0x00:0x02]
        self.NumberOfSections =         rawBytes[0x02:0x04]
        # TODO: convert to actual timestamp
        self.TimeDateStamp =            rawBytes[0x04:0x08]
        self.PointerToSymbolTable =     rawBytes[0x08:0x0c]
        self.NumberOfSymbols =          rawBytes[0x0c:0x10]
        sizeOfOptionalHeader =          rawBytes[0x10:0x12]
        self.SizeOfOptionalHeader =     int.from_bytes(sizeOfOptionalHeader, byteorder='little')
        # TODO: go through MS docs and get actual values for each
        # byte representation of Characteristics
        self.Characteristics =          rawBytes[0x12:0x14]


# Optional header - need to separate 32-bit and 64-bit versions
# https://0xrick.github.io/win-internals/pe4/#optional-header-image_optional_header
class IMAGE_OPTIONAL_HEADER(ByteStream):
    def __init__(self, rawBytes):
        self.bytes = rawBytes
        self.Magic = rawBytes[0x00:0x02]
        self.MajorLinkerVersion = rawBytes[0x02:0x03]
        self.MinorLinkerVersion = rawBytes[0x03:0x04]
        self.SizeOfCode = rawBytes[0x04:0x08]
        self.SizeOfInitializedData = rawBytes[0x08:0x0c]
        self.SizeOfUninitializedData = rawBytes[0xc:0x10]
        self.AddressOfEntryPoint = rawBytes[0x10:0x14]
        self.BaseOfCode = rawBytes[0x14:0x18]
        self.BaseOfData = rawBytes[0x18:0x1c]
        # TODO: add additional/optional fields
        return
    
    def __getitem__(self, key):
        return self.bytes[key]

# TODO: Create unified PE class that Win32 and Win64 can inherit from
class PE(File):
    def __init__(self, filename, bytes, dosHeader, dosStub, richHeader, ntHeaders, coffHeader, optionalHeader):
        self.filename = filename
        self.bytes = bytes
        self.dosHeader = dosHeader
        self.dosStub = dosStub
        self.richHeader = richHeader
        self.ntHeaders = ntHeaders
        self.coffHeader = coffHeader
        self.optionalHeader = optionalHeader
    
    @staticmethod
    def read_bytes(filename):
        rawBytes = b''
        with open(filename, "rb") as f:
            rawBytes = f.read()
        return rawBytes
    
    @classmethod
    def from_file(cls, filename):
        rawBytes = cls.read_bytes(filename)
        dosHeader = IMAGE_DOS_HEADER(rawBytes[0:0x40])
        dosStub = IMAGE_DOS_STUB(rawBytes[0x40:0x80])
        if (dosHeader.e_lfanew > 0x80):
            richHeader = IMAGE_RICH_HEADER(rawBytes[0x80:dosHeader.e_lfanew])
        else:
            richHeader = None
        ntHeaders = IMAGE_NT_HEADERS(rawBytes[dosHeader.e_lfanew:dosHeader.e_lfanew+100])

        return cls(filename, rawBytes, dosHeader, dosStub, richHeader, ntHeaders, ntHeaders.coffHeader, ntHeaders.OptionalHeader)

    def is_valid_PE(self):
        if self.dosHeader.e_magic != b'MZ':               return False
        elif self.ntHeaders.Signature != b'PE\x00\x00':   return False
        elif    ((self.optionalHeader.Magic != b'\x0b\x01') and
                (self.optionalHeader.Magic != b'\x0b\x02') and 
                (self.optionalHeader.Magic != b'\x07\x01')):   return False
        else:                                   return True

    @property
    def structure(self):
        return None
        

def main():
    test1 = ByteStream("MZ1234\xff")
    for b in test1:
        print(b, end=" ")
    print()
    print("======================================")
    
    testelf2 = Elf.from_file("./samples/test-elf")
    print(testelf2)
    print(testelf2.filetype)
    print(testelf2.structure)
    print("======================================")
    
    atm = Elf.from_file("./samples/atm")
    print(atm)
    print(atm.filetype)
    print(atm.structure)
    print("======================================")

    exe1 = PE.from_file("./samples/pe32.exe")
    print(exe1)
    print(exe1.dosStub.message)
    print(exe1.is_valid_PE())
    print(exe1.ntHeaders.Signature)
    print(exe1.optionalHeader.Magic)
    print(exe1.dosHeader)
    print(exe1.dosStub)
    print(exe1.richHeader)
    print(exe1.ntHeaders)
    print("======================================")
    
    # exe2 = PE("./samples/selenium-manager.exe")
    # print(exe2)
    # print(exe2.dosStub.message)
    # print(exe2.richHeader)
    # print(exe2.isValidPE())
    # print(exe2.filetype)
    # print("======================================")

if __name__ == "__main__":
    main()