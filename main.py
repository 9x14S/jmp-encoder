import enum
import argparse
import sys
import logging
from os.path import abspath

import capstone as cs


logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)


class Error(enum.IntEnum):
    """Error codes."""
    SUCCESS = 0
    NO_FILE_ERROR = 1
    FILE_NOT_FOUND = 2
    UNENCODABLE = 3
    CANCELED = 4
    IS_DIR = 5
    NO_PERMS = 6


class Disasm(enum.IntEnum):
    """Index names for Capstone's lite disassembler."""
    address = 0
    size = 1
    mnemonic = 2
    op_str = 3


def get_shellcode() -> bytes:
    """Opens the provided file and reads the shellcode there."""
    if arguments.filename is not None:
        try:
            with open(arguments.filename, "rb") as f:
                return f.read()
        except FileNotFoundError:
            logging.error("File '%s' not found.", arguments.filename)
            sys.exit(Error.FILE_NOT_FOUND)
    else:
        # Read from stdin
        return sys.stdin.buffer.read()



def check_and_get_sizes(shellcode: bytes) -> list[int]:
    """Checks that the shellcode is actually encodable, and returns a list
    of offsets that'll be used for encoding it."""

    inst_sizes: list[int] = []

    # TODO: Add checks for the architecture 
    parsed_shellcode = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    for ins in parsed_shellcode.disasm_lite(shellcode, 0x0):
        if ins[Disasm.size] > 4:
            logging.error(" Cannot encode instruction '%s %s' at address %x.\n"
                          "\tSize of instruction '%s' plus operand(s) (%i bytes) "
                          "exceeds max encodable size (4 bytes).",
                          ins[Disasm.mnemonic], ins[Disasm.op_str], ins[Disasm.address], 
                          ins[Disasm.mnemonic], ins[Disasm.size],
                          )
            sys.exit(Error.UNENCODABLE)
        else:
            inst_sizes.append(ins[Disasm.size])

    return inst_sizes


def encode(inst_sizes: list, shellcode: bytes) -> bytes:
    """Encodes the instructions passed as `jmp` instructions. Joins adjacent
    instructions whose sum of their size adds up to 4 or less, and pads with `nop`."""

    jmp_over = b'\xeb\x00'
    nop = b'\x90'
    encoded = b''

    start = 0
    for size in inst_sizes:
        # TODO: For extra efficiency, check if two or more instructions can be encoded
        # as a single instruction
        encoded += jmp_over + (shellcode[start:start+size].ljust(4, nop))
        start += size
        
    return encoded


def main():
    """Receives and encodes the shellcode, then writes it to stdout or to a file."""

    shellcode = get_shellcode()
    inst_list = check_and_get_sizes(shellcode)
    encoded_shellcode = encode(inst_list, shellcode)

    if arguments.outfile is not None:
        if arguments.filename is not None and abspath(arguments.filename) == abspath(arguments.outfile):
            logging.warning("Source and destination files are the same. ")
            answer = input("Proceed? [y/N]: ").strip().upper()
            if answer != 'Y':
                sys.exit(Error.CANCELED)

        try:
            with open(arguments.outfile, "wb") as f:
                f.write(encoded_shellcode)
        except PermissionError:
            logging.error("Can't access file '%s', permission error.", arguments.outfile)
            sys.exit(Error.NO_PERMS)
        except IsADirectoryError:
            logging.error("'%s' is a directory.", arguments.outfile)
            sys.exit(Error.IS_DIR)

    else:
        sys.stdout.buffer.write(encoded_shellcode)
    sys.exit(Error.SUCCESS)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="x86/64 Shellcode encoder as `jmp` instructions.")
    parser.add_argument("filename", 
                        action="store",
                        nargs='?',
                        default=None,
                        help="source shellcode file. If not provided, read from stdin.")

    parser.add_argument("-o", "--out", 
                        action="store", 
                        dest="outfile",
                        required=False,
                        help="the encoded shellcode output file. If not provided, print to stdout.")

    arguments = parser.parse_args()
    main()
