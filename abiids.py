#!/usr/bin/python3

ELF_ABIs = {
    0: "ELFOSABI_NONE",
    1: "ELFOSABI_HPUX",
    2: "ELFOSABI_NETBSD",
    3: "ELFOSABI_LINUX",
    # 4, 5 not implemented
    6: "ELFOSABI_SOLARIS",
    7: "ELFOSABI_AIX",
    8: "ELFOSABI_IRIX",
    9: "ELFOSABI_FREEBSD",
    10: "ELFOSABI_TRU64",
    11: "ELFOSABI_MODESTO",
    12: "ELFOSABI_OPENBSD",
    13: "ELFOSABI_OPENVMS",
    14: "ELFOSABI_NSK",
    # all others set to "ELFOSABI_NONE"
}
