import textwrap
import prodids


class ByteStream:
    def __init__(self, bytes):
        self.bytes = bytes

    def __len__(self):
        return len(self.bytes)

    def __str__(self):
        if len(self) > 10:
            return f"a stream of {len(self)} bytes beginning with {self.bytes[0:10]}"
        else:
            return f"a stream of {len(self)} bytes beginning with {self.bytes}"

    # make the class iterable with __iter__() and __next__()
    def __iter__(self):
        self.byteIndex = 0
        self.byteIter = self.bytes[0]
        return self

    def __next__(self):
        if self.byteIndex == len(self) - 1:
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
        rawBytes = b""
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
        if bytes[4] == 1:
            EI_CLASS = "ELFCLASS32"
        elif bytes[4] == 2:
            EI_CLASS = "ELFCLASS64"
        else:
            EI_CLASS = "ELFCLASSNONE"
        # parse endianness from the header
        if bytes[5] == 1:
            EI_DATA = "ELFDATA2LSB"
        elif bytes[5] == 2:
            EI_DATA = "ELFDATA2MSB"
        else:
            EI_DATA = "ELFDATANONE"
        # parse version from the header
        if bytes[6] == 1:
            EI_VERSION = "EV_CURRENT"
        else:
            EI_VERSION = "EV_NONE"
        # parse the ABI
        if bytes[7] == 0:
            EI_OSABI = "ELFOSABI_NONE"
        elif bytes[7] == 1:
            EI_OSABI = "ELFOSABI_HPUX"
        elif bytes[7] == 2:
            EI_OSABI = "ELFOSABI_NETBSD"
        elif bytes[7] == 3:
            EI_OSABI = "ELFOSABI_LINUX"
        # 4, 5 not implemented
        elif bytes[7] == 6:
            EI_OSABI = "ELFOSABI_SOLARIS"
        elif bytes[7] == 7:
            EI_OSABI = "ELFOSABI_AIX"
        elif bytes[7] == 8:
            EI_OSABI = "ELFOSABI_IRIX"
        elif bytes[7] == 9:
            EI_OSABI = "ELFOSABI_FREEBSD"
        elif bytes[7] == 10:
            EI_OSABI = "ELFOSABI_TRU64"
        elif bytes[7] == 11:
            EI_OSABI = "ELFOSABI_MODESTO"
        elif bytes[7] == 12:
            EI_OSABI = "ELFOSABI_OPENBSD"
        elif bytes[7] == 13:
            EI_OSABI = "ELFOSABI_OPENVMS"
        elif bytes[7] == 14:
            EI_OSABI = "ELFOSABI_NSK"
        else:
            EI_OSABI = "ELFOSABI_NONE"
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
        rawBytes = b""
        with open(filename, "rb") as f:
            rawBytes = f.read()
        return rawBytes

    def get_bitness(self):
        if self.header.EI_CLASS == "ELFCLASSNONE":
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
        if self.is_valid_elf():
            return f"ELF {self.get_bitness()}-bit {self.get_endianness()} executable"
        else:
            return "Malformed ELF file"

    def is_valid_elf(self):
        padding = int.from_bytes(self.header[9:16])
        if self.header[0] != 0x7F:
            return False
        elif self.header[1] != ord("E"):
            return False
        elif self.header[2] != ord("L"):
            return False
        elif self.header[3] != ord("F"):
            return False
        elif self.header.EI_CLASS == 0:
            return False
        elif self.header.EI_DATA == 0:
            return False
        elif padding != 0:
            return False
        else:
            return True


# DOS header - same across 32-bit and 64-bit arch
class IMAGE_DOS_HEADER(ByteStream):
    def __init__(self, rawBytes, e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno, e_res, e_oemid, e_oeminfo, e_res2, e_lfanew):
        self.bytes = rawBytes
        self.e_magic = e_magic
        self.e_cblp = e_cblp
        self.e_cp = e_cp
        self.e_crlc = e_crlc
        self.e_cparhdr = e_cparhdr
        self.e_minalloc = e_minalloc
        self.e_maxalloc = e_maxalloc
        self.e_ss = e_ss
        self.e_sp = e_sp
        self.e_csum = e_csum
        self.e_ip = e_ip
        self.e_cs = e_cs
        self.e_lfarlc = e_lfarlc
        self.e_ovno = e_ovno
        self.e_res = e_res
        self.e_oemid = e_oemid
        self.e_oeminfo = e_oeminfo
        self.e_res2 = e_res2
        self.e_lfanew = e_lfanew

    @classmethod
    def from_bytes(cls, rawBytes):
        # https://0xrick.github.io/win-internals/pe3/
        e_magic = rawBytes[0:2]  # Magic number
        e_cblp = rawBytes[2:4]  # Bytes on last page of file
        e_cp = rawBytes[4:6]  # Pages in file
        e_crlc = rawBytes[6:8]  # Relocations
        e_cparhdr = rawBytes[8:0xA]  # Size of header in paragraphs
        e_minalloc = rawBytes[0xA:0xC]  # Minimum extra paragraphs needed
        e_maxalloc = rawBytes[0xC:0xE]  # Maximum extra paragraphs needed
        e_ss = rawBytes[0xE:0x10]  # Initial (relative) SS value
        e_sp = rawBytes[0x10:0x12]  # Initial SP value
        e_csum = rawBytes[0x12:0x14]  # Checksum
        e_ip = rawBytes[0x14:0x16]  # Initial IP value
        e_cs = rawBytes[0x16:0x18]  # Initial (relative) CS value
        e_lfarlc = rawBytes[0x18:0x1A]  # File address of relocation table
        e_ovno = rawBytes[0x1A:0x1C]  # Overlay number
        e_res = rawBytes[0x1C:0x24]  # Reserved words
        e_oemid = rawBytes[0x24:0x26]  # OEM identifier (for e_oeminfo)
        e_oeminfo = rawBytes[0x26:0x28]  # OEM information = rawBytes[] # e_oemid specific
        e_res2 = rawBytes[0x28:0x3C]  # Reserved words
        e_lfanew = rawBytes[0x3C:0x40]  # File address of new exe header
        e_lfanew = int.from_bytes(e_lfanew, byteorder="little")
        return cls(rawBytes, e_magic, e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc, e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno, e_res, e_oemid, e_oeminfo, e_res2, e_lfanew)

    def __getitem__(self, key):
        return self.bytes[key]


# https://0xrick.github.io/win-internals/pe3/#dos-stub
class IMAGE_DOS_STUB(ByteStream):
    def __init__(self, rawBytes, message):
        self.bytes = rawBytes
        self.message = message

    @classmethod
    def from_bytes(cls, rawBytes):
        return cls(rawBytes, str(rawBytes[0x0E:0x38]))

    def __getitem__(self, key):
        return self.bytes[key]


# an entry in the IMAGE_RICH_HEADER class, containing build info
class RichHeaderId:
    def __init__(self, buildId, count, productID, vsVersion):
        self.buildId = buildId
        self.count = count
        self.productID = productID
        self.vsVersion = vsVersion

    @classmethod
    def from_fields(cls, f1, f2):
        buildId = int(f1[4:], 16)
        count = int(f2, 16)
        productIdNumeric = int(f1[0:4], 16)
        try:
            productID = prodids.int_names[productIdNumeric]
        except KeyError:
            productID = "prodidUnknown"
        vsVersion = prodids.vs_version(productIdNumeric)
        return cls(buildId, count, productID, vsVersion)


    def __str__(self):
        return (
            f"Compiled with {self.productID} in {self.vsVersion[0]} {self.vsVersion[1]}"
        )
        # alternative way of printing numbers pre-translation - useful for debugging
        # return f"{str(int(self.rawIds[0][4:],16))}.{str(int(self.rawIds[0][0:4],16))}.{str(int(self.rawIds[1],16))}"


# https://0xrick.github.io/win-internals/pe3/#rich-header
class IMAGE_RICH_HEADER(ByteStream):
    def __init__(self, rawBytes, signatures):
        self.bytes = rawBytes
        self.signatures = signatures

    @classmethod
    def from_bytes(cls, rawBytes):
        key = rawBytes[0x04:0x08]
        rch_hdr = (IMAGE_RICH_HEADER._xor(rawBytes, key)).hex()
        rch_hdr = textwrap.wrap(rch_hdr, 16)

        signatures = []
        for i in range(2, len(rch_hdr)):
            tmp = textwrap.wrap(rch_hdr[i], 8)
            f1 = IMAGE_RICH_HEADER._rev_endiannes(tmp[0])
            f2 = IMAGE_RICH_HEADER._rev_endiannes(tmp[1])
            signatures.append(RichHeaderId.from_fields(f1, f2))
        
        return cls(rawBytes, signatures)

    def _xor(data, key):
        return bytearray(((data[i] ^ key[i % len(key)]) for i in range(0, len(data))))

    def _rev_endiannes(data):
        tmp = [data[i : i + 8] for i in range(0, len(data), 8)]

        for i in range(len(tmp)):
            tmp[i] = "".join(
                reversed([tmp[i][x : x + 2] for x in range(0, len(tmp[i]), 2)])
            )

        return "".join(tmp)

    def __getitem__(self, key):
        return super().__getitem__(key)

    def __str__(self):
        output = "RICH HEADER SIGNATURES EXTRACTED:\n"
        for sig in self.signatures:
            output += f"\t\\_ {sig}\n"
        # remove trailing newline
        return output[:-1]


# NT Headers - structure is the same except for optional header
# https://0xrick.github.io/win-internals/pe4/#nt-headers-image_nt_headers
class IMAGE_NT_HEADERS(ByteStream):
    def __init__(self, rawBytes, signature, coffHeader, optionalHeader):
        self.bytes = rawBytes
        self.signature = signature
        self.coffHeader = coffHeader
        self.OptionalHeader = optionalHeader

    @classmethod
    def from_bytes(cls, rawBytes):
        signature = rawBytes[0:4]
        coffHeader = COFF_HEADER.from_bytes(rawBytes[4:0x18])
        optionalHeaderBytes = rawBytes[
            0x18 : 0x18 + coffHeader.SizeOfOptionalHeader
        ]
        optionalHeader = IMAGE_OPTIONAL_HEADER.from_bytes(optionalHeaderBytes)
        return cls(rawBytes, signature, coffHeader, optionalHeader)


# File header/COFF header - same across PE32 and PE32+
# https://0xrick.github.io/win-internals/pe4/#file-header-image_file_header
class COFF_HEADER(ByteStream):
    def __init__(
        self,
        bytes,
        machine,
        numberOfSections,
        timeDateStamp,
        pointerToSymbolTable,
        numberOfSymbols,
        sizeOfOptionalHeader,
        characteristics,
    ):
        self.bytes = bytes
        self.Machine = machine
        self.NumberOfSections = numberOfSections
        self.TimeDateStamp = timeDateStamp
        self.PointerToSymbolTable = pointerToSymbolTable
        self.NumberOfSymbols = numberOfSymbols
        self.SizeOfOptionalHeader = sizeOfOptionalHeader
        self.Characteristics = characteristics

    @classmethod
    def from_bytes(cls, rawBytes):
        bytes = rawBytes
        # TODO: go through MS docs and get actual values for each
        # byte representation of Machine
        machine = rawBytes[0x00:0x02]
        numberOfSections = rawBytes[0x02:0x04]
        # TODO: convert to actual timestamp
        timeDateStamp = rawBytes[0x04:0x08]
        pointerToSymbolTable = rawBytes[0x08:0x0C]
        numberOfSymbols = rawBytes[0x0C:0x10]
        sizeOfOptionalHeader = rawBytes[0x10:0x12]
        sizeOfOptionalHeader = int.from_bytes(sizeOfOptionalHeader, byteorder="little")
        # TODO: go through MS docs and get actual values for each
        # byte representation of Characteristics
        characteristics = rawBytes[0x12:0x14]
        return cls(
            bytes,
            machine,
            numberOfSections,
            timeDateStamp,
            pointerToSymbolTable,
            numberOfSymbols,
            sizeOfOptionalHeader,
            characteristics,
        )


# https://0xrick.github.io/win-internals/pe4/#optional-header-image_optional_header
class IMAGE_OPTIONAL_HEADER(ByteStream):
    def __init__(
        self,
        bytes,
        magic,
        majorLinkerVersion,
        minorLinkerVersion,
        sizeOfCode,
        sizeOfInitializedData,
        sizeOfUninitializedData,
        addressOfEntryPoint,
        baseOfCode,
    ):
        self.bytes = bytes
        self.Magic = magic
        self.MajorLinkerVersion = majorLinkerVersion
        self.MinorLinkerVersion = minorLinkerVersion
        self.SizeOfCode = sizeOfCode
        self.SizeOfInitializedData = sizeOfInitializedData
        self.SizeOfUninitializedData = sizeOfUninitializedData
        self.AddressOfEntryPoint = addressOfEntryPoint
        self.BaseOfCode = baseOfCode

    @classmethod
    def dispatcher(cls, magic, sharedFields, optionalRawBytes, rawBytes):
        if magic == b"\x0b\x01":
            return IMAGE_OPTIONAL_HEADER32.factory(
                sharedFields, optionalRawBytes, rawBytes
            )
        elif magic == b"\x0b\x02":
            return IMAGE_OPTIONAL_HEADER64.factory(
                sharedFields, optionalRawBytes, rawBytes
            )
        else:
            return None

    @staticmethod
    def _parse_shared_fields(rawBytes):
        return {
            "magic": rawBytes[0x00:0x02],
            "majorLinkerVersion": rawBytes[0x02:0x03],
            "minorLinkerVersion": rawBytes[0x03:0x04],
            "sizeOfCode": rawBytes[0x04:0x08],
            "sizeOfInitializedData": rawBytes[0x08:0x0C],
            "sizeOfUninitializedData": rawBytes[0xC:0x10],
            "addressOfEntryPoint": rawBytes[0x10:0x14],
            "baseOfCode": rawBytes[0x14:0x18],
        }

    @classmethod
    def from_bytes(cls, rawBytes):
        magic = rawBytes[0x00:0x02]
        sharedFields = cls._parse_shared_fields(rawBytes[0x00:0x18])
        return cls.dispatcher(magic, sharedFields, rawBytes[0x18:], rawBytes)

    def __getitem__(self, key):
        return self.bytes[key]


# Optional header for 32-bit PE
class IMAGE_OPTIONAL_HEADER32(IMAGE_OPTIONAL_HEADER):
    def __init__(
        self,
        rawBytes,
        magic,
        majorLinkerVersion,
        minorLinkerVersion,
        sizeOfCode,
        sizeOfInitializedData,
        sizeOfUninitializedData,
        addressOfEntryPoint,
        baseOfCode,
        baseOfData,
        imageBase,
        sectionAlignment,
        fileAlignment,
        majorOperatingSystemVersion,
        minorOperatingSystemVersion,
        majorImageVersion,
        minorImageVersion,
        majorSubsystemVersion,
        minorSubsystemVersion,
        win32VersionValue,
        sizeOfImage,
        sizeOfHeaders,
        checkSum,
        subsystem,
        dllCharacteristics,
        sizeOfStackReserve,
        sizeOfStackCommit,
        sizeOfHeapReserve,
        sizeOfHeapCommit,
        loaderFlags,
        numberOfRvaAndSizes,
        dataDirectory,
    ):
        super().__init__(
            rawBytes,
            magic,
            majorLinkerVersion,
            minorLinkerVersion,
            sizeOfCode,
            sizeOfInitializedData,
            sizeOfUninitializedData,
            addressOfEntryPoint,
            baseOfCode
        )
        self.BaseOfData = baseOfData
        self.ImageBase = imageBase
        self.SectionAlignment = sectionAlignment
        self.fileAlignment = fileAlignment
        self.majorOperatingSystemVersion = majorOperatingSystemVersion
        self.minorOperatingSystemVersion = minorOperatingSystemVersion
        self.majorImageVersion = majorImageVersion
        self.minorImageVersion = minorImageVersion
        self.majorSubsystemVersion = majorSubsystemVersion
        self.minorSubsystemVersion = minorSubsystemVersion
        self.win32VersionValue = win32VersionValue
        self.sizeOfImage = sizeOfImage
        self.sizeOfHeaders = sizeOfHeaders
        self.checkSum = checkSum
        self.subsystem = subsystem
        self.dllCharacteristics = dllCharacteristics
        self.sizeOfStackReserve = sizeOfStackReserve
        self.sizeOfStackCommit = sizeOfStackCommit
        self.sizeOfHeapReserve = sizeOfHeapReserve
        self.sizeOfHeapCommit = sizeOfHeapCommit
        self.loaderFlags = loaderFlags
        self.numberOfRvaAndSizes = numberOfRvaAndSizes
        self.dataDirectory = dataDirectory
        return

    @classmethod
    def factory(cls, sharedObjects, additionalFieldBytes, rawBytes):
        baseOfData = additionalFieldBytes[0x00:0x04]
        imageBase = additionalFieldBytes[0x04:0x08]
        sectionAlignment = additionalFieldBytes[0x08:0x0C]
        fileAlignment = additionalFieldBytes[0x0C:0x10]
        majorOperatingSystemVersion = additionalFieldBytes[0x10:0x12]
        minorOperatingSystemVersion = additionalFieldBytes[0x12:0x14]
        majorImageVersion = additionalFieldBytes[0x14:0x16]
        minorImageVersion = additionalFieldBytes[0x16:0x18]
        majorSubsystemVersion = additionalFieldBytes[0x18:0x1C]
        minorSubsystemVersion = additionalFieldBytes[0x1C:0x1E]
        win32VersionValue = additionalFieldBytes[0x1E:0x22]
        sizeOfImage = additionalFieldBytes[0x22:0x26]
        sizeOfHeaders = additionalFieldBytes[0x26:0x2A]
        checkSum = additionalFieldBytes[0x2A:0x2E]
        subsystem = additionalFieldBytes[0x2E:0x32]
        dllCharacteristics = additionalFieldBytes[0x32:0x34]
        sizeOfStackReserve = additionalFieldBytes[0x34:0x38]
        sizeOfStackCommit = additionalFieldBytes[0x38:0x3C]
        sizeOfHeapReserve = additionalFieldBytes[0x3C:0x40]
        sizeOfHeapCommit = additionalFieldBytes[0x40:0x44]
        loaderFlags = additionalFieldBytes[0x44:0x48]
        numberOfRvaAndSizes = additionalFieldBytes[0x48:0x4C]
        dataDirectory = additionalFieldBytes[0x4C:]
        return cls(
            rawBytes,
            sharedObjects["magic"],
            sharedObjects["majorLinkerVersion"],
            sharedObjects["minorLinkerVersion"],
            sharedObjects["sizeOfCode"],
            sharedObjects["sizeOfInitializedData"],
            sharedObjects["sizeOfUninitializedData"],
            sharedObjects["addressOfEntryPoint"],
            sharedObjects["baseOfCode"],
            baseOfData,
            imageBase,
            sectionAlignment,
            fileAlignment,
            majorOperatingSystemVersion,
            minorOperatingSystemVersion,
            majorImageVersion,
            minorImageVersion,
            majorSubsystemVersion,
            minorSubsystemVersion,
            win32VersionValue,
            sizeOfImage,
            sizeOfHeaders,
            checkSum,
            subsystem,
            dllCharacteristics,
            sizeOfStackReserve,
            sizeOfStackCommit,
            sizeOfHeapReserve,
            sizeOfHeapCommit,
            loaderFlags,
            numberOfRvaAndSizes,
            dataDirectory,
        )

    @classmethod
    def from_bytes(cls, rawBytes):
        return super().from_bytes(rawBytes)


# Optional header for 64-bit PE
class IMAGE_OPTIONAL_HEADER64(IMAGE_OPTIONAL_HEADER):
    def __init__(
        self,
        rawBytes,
        magic,
        majorLinkerVersion,
        minorLinkerVersion,
        sizeOfCode,
        sizeOfInitializedData,
        sizeOfUninitializedData,
        addressOfEntryPoint,
        baseOfCode,
        imageBase,
        sectionAlignment,
        fileAlignment,
        majorOperatingSystemVersion,
        minorOperatingSystemVersion,
        majorImageVersion,
        minorImageVersion,
        majorSubsystemVersion,
        minorSubsystemVersion,
        win32VersionValue,
        sizeOfImage,
        sizeOfHeaders,
        checkSum,
        subsystem,
        dllCharacteristics,
        sizeOfStackReserve,
        sizeOfStackCommit,
        sizeOfHeapReserve,
        sizeOfHeapCommit,
        loaderFlags,
        numberOfRvaAndSizes,
        dataDirectory,
    ):
        super().__init__(
            rawBytes,
            magic,
            majorLinkerVersion,
            minorLinkerVersion,
            sizeOfCode,
            sizeOfInitializedData,
            sizeOfUninitializedData,
            addressOfEntryPoint,
            baseOfCode
        )
        self.ImageBase = imageBase
        self.SectionAlignment = sectionAlignment
        self.fileAlignment = fileAlignment
        self.majorOperatingSystemVersion = majorOperatingSystemVersion
        self.minorOperatingSystemVersion = minorOperatingSystemVersion
        self.majorImageVersion = majorImageVersion
        self.minorImageVersion = minorImageVersion
        self.majorSubsystemVersion = majorSubsystemVersion
        self.minorSubsystemVersion = minorSubsystemVersion
        self.win32VersionValue = win32VersionValue
        self.sizeOfImage = sizeOfImage
        self.sizeOfHeaders = sizeOfHeaders
        self.checkSum = checkSum
        self.subsystem = subsystem
        self.dllCharacteristics = dllCharacteristics
        self.sizeOfStackReserve = sizeOfStackReserve
        self.sizeOfStackCommit = sizeOfStackCommit
        self.sizeOfHeapReserve = sizeOfHeapReserve
        self.sizeOfHeapCommit = sizeOfHeapCommit
        self.loaderFlags = loaderFlags
        self.numberOfRvaAndSizes = numberOfRvaAndSizes
        self.dataDirectory = dataDirectory
        return

    @classmethod
    def factory(cls, sharedObjects, additionalFieldBytes, rawBytes):
        imageBase = additionalFieldBytes[0x00:0x08]
        sectionAlignment = additionalFieldBytes[0x08:0x0C]
        fileAlignment = additionalFieldBytes[0x0C:0x10]
        majorOperatingSystemVersion = additionalFieldBytes[0x10:0x12]
        minorOperatingSystemVersion = additionalFieldBytes[0x12:0x14]
        majorImageVersion = additionalFieldBytes[0x14:0x16]
        minorImageVersion = additionalFieldBytes[0x16:0x18]
        majorSubsystemVersion = additionalFieldBytes[0x18:0x1A]
        minorSubsystemVersion = additionalFieldBytes[0x1A:0x1C]
        win32VersionValue = additionalFieldBytes[0x1C:0x20]
        sizeOfImage = additionalFieldBytes[0x20:0x24]
        sizeOfHeaders = additionalFieldBytes[0x24:0x28]
        checkSum = additionalFieldBytes[0x28:0x2C]
        subsystem = additionalFieldBytes[0x2C:0x2E]
        dllCharacteristics = additionalFieldBytes[0x2E:0x30]
        sizeOfStackReserve = additionalFieldBytes[0x30:0x38]
        sizeOfStackCommit = additionalFieldBytes[0x38:0x40]
        sizeOfHeapReserve = additionalFieldBytes[0x40:0x48]
        sizeOfHeapCommit = additionalFieldBytes[0x48:0x50]
        loaderFlags = additionalFieldBytes[0x50:0x54]
        numberOfRvaAndSizes = additionalFieldBytes[0x54:0x58]
        dataDirectory = additionalFieldBytes[0x58:]
        return cls(
            rawBytes,
            sharedObjects["magic"],
            sharedObjects["majorLinkerVersion"],
            sharedObjects["minorLinkerVersion"],
            sharedObjects["sizeOfCode"],
            sharedObjects["sizeOfInitializedData"],
            sharedObjects["sizeOfUninitializedData"],
            sharedObjects["addressOfEntryPoint"],
            sharedObjects["baseOfCode"],
            imageBase,
            sectionAlignment,
            fileAlignment,
            majorOperatingSystemVersion,
            minorOperatingSystemVersion,
            majorImageVersion,
            minorImageVersion,
            majorSubsystemVersion,
            minorSubsystemVersion,
            win32VersionValue,
            sizeOfImage,
            sizeOfHeaders,
            checkSum,
            subsystem,
            dllCharacteristics,
            sizeOfStackReserve,
            sizeOfStackCommit,
            sizeOfHeapReserve,
            sizeOfHeapCommit,
            loaderFlags,
            numberOfRvaAndSizes,
            dataDirectory,
        )

    @classmethod
    def from_bytes(cls, rawBytes):
        return super().from_bytes(rawBytes)


# TODO: Create unified PE class that Win32 and Win64 can inherit from
class PE(File):
    def __init__(
        self,
        filename,
        bytes,
        dosHeader,
        dosStub,
        richHeader,
        ntHeaders,
        coffHeader,
        optionalHeader,
    ):
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
        rawBytes = b""
        with open(filename, "rb") as f:
            rawBytes = f.read()
        return rawBytes

    @classmethod
    def from_file(cls, filename):
        rawBytes = cls.read_bytes(filename)
        dosHeader = IMAGE_DOS_HEADER.from_bytes(rawBytes[0:0x40])
        dosStub = IMAGE_DOS_STUB.from_bytes(rawBytes[0x40:0x80])
        if dosHeader.e_lfanew > 0x80:
            richHeader = IMAGE_RICH_HEADER.from_bytes(rawBytes[0x80 : dosHeader.e_lfanew])
        else:
            richHeader = None
        ntHeaders = IMAGE_NT_HEADERS.from_bytes(
            rawBytes[dosHeader.e_lfanew : dosHeader.e_lfanew + 100]
        )

        return cls(
            filename,
            rawBytes,
            dosHeader,
            dosStub,
            richHeader,
            ntHeaders,
            ntHeaders.coffHeader,
            ntHeaders.OptionalHeader,
        )

    def is_valid_PE(self):
        if self.dosHeader.e_magic != b"MZ":
            return False
        elif self.ntHeaders.signature != b"PE\x00\x00":
            return False
        elif (
            (self.optionalHeader.Magic != b"\x0b\x01")
            and (self.optionalHeader.Magic != b"\x0b\x02")
            and (self.optionalHeader.Magic != b"\x07\x01")
        ):
            return False
        else:
            return True

    @property
    def bitness(self):
        if self.optionalHeader.Magic == b"\x0b\x01":
            return "32-bit"
        elif self.optionalHeader.Magic == b"\x0b\x02":
            return "64-bit"
        elif self.optionalHeader.Magic == b"\x07\x01":
            return "ROM Image"
        else:
            return "unknown"

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
    print(exe1.coffHeader.SizeOfOptionalHeader)
    print(exe1.dosStub.message)
    print(exe1.is_valid_PE())
    print(exe1.ntHeaders.signature)
    print(exe1.optionalHeader.Magic)
    print(exe1.bitness)
    print(exe1.dosHeader)
    print(exe1.dosStub)
    print(exe1.richHeader)
    print(exe1.ntHeaders)
    print("======================================")

    exe2 = PE.from_file("./samples/selenium-manager.exe")
    print(exe2)
    print(exe2.coffHeader.SizeOfOptionalHeader)
    print(exe2.optionalHeader)
    print(exe2.bitness)
    print(exe2.dosStub.message)
    print(exe2.richHeader)
    print(exe2.is_valid_PE())
    print(exe2.filetype)
    print("======================================")

    exe64 = PE.from_file("./samples/notepad.exe")
    print(exe64)
    print(exe64.coffHeader.SizeOfOptionalHeader)
    print(exe64.optionalHeader)
    print(exe64.bitness)
    print(exe64.dosStub.message)
    print(exe64.richHeader)
    print(exe64.is_valid_PE())
    print(exe64.filetype)
    print("======================================")


if __name__ == "__main__":
    main()
