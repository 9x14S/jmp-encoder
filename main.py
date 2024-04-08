import enum
import argparse
import sys
import logging
import capstone as cs

logging.basicConfig(format="%(levelname)s: %(message)s", level=logging.INFO)


class Error(enum.IntEnum):
    """Error codes."""
    SUCCESS = 0
    NO_FILE_ERROR = 1
    FILE_NOT_FOUND = 2
    UNENCODABLE = 3


class Disasm(enum.IntEnum):
    """Index names for Capstone's lite disassembler."""
    address = 0
    size = 1
    mnemonic = 2
    op_str = 3


def get_shellcode() -> bytes:
    """Opens the provided file and reads the shellcode there."""
    if len(sys.argv) >= 2:
        try:
            with open(arguments.filename, "rb") as f:
                return f.read()
        except FileNotFoundError:
            logging.error( "File '%s' not found. Exiting.", sys.argv[1])
            sys.exit(Error.FILE_NOT_FOUND)
    else:
        parser.print_usage()
        sys.exit(Error.NO_FILE_ERROR)


def check_and_get_sizes(shellcode: bytes) -> list[int]:
    """Checks that the shellcode is actually encodable, and returns a list
    of offsets that'll be used for encoding it."""

    inst_list: list[int] = []

    # TODO: Add checks for the architecture 
    parsed_shellcode = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
    for i in parsed_shellcode.disasm_lite(shellcode, 0x0):
        if i[Disasm.size] > 4:
            logging.error( " Cannot encode instruction '%s %s' at address %x.\n"
                            "\tSize of instruction '%s' plus operand(s) (%i bytes) "
                            "exceeds max encodable size (4 bytes).",
                            i[Disasm.mnemonic], i[Disasm.op_str], i[Disasm.address], i[Disasm.mnemonic], i[Disasm.size],
                            )
            sys.exit(Error.UNENCODABLE)
        else:
            inst_list.append(i[Disasm.size])

    return inst_list


def encode(inst_list: list, shellcode: bytes) -> bytes:
    """Encodes the instructions passed as `jmp` instructions. Joins adjacent
    instructions whose sum of their size adds up to 4 or less, and pads with `nop`."""

    jmp_over = b'\xeb\x00'
    nop = b'\x90'
    encoded = b''

    start = 0
    for size in inst_list:
        # TODO: For extra efficiency, check if two or more instructions can be encoded
        # as a single instruction
        encoded += jmp_over + (shellcode[start:start+size].ljust(4, nop))
        start += size
        
    return encoded


def main():
    """Main function. Gets and encodes the shellcode, then writes it to stdout or to a file."""
    shellcode = get_shellcode()
    inst_list = check_and_get_sizes(shellcode)
    encoded_shellcode = encode(inst_list, shellcode)
    if arguments.outfile is not None:
        with open(arguments.outfile, "wb") as f:
            f.write(encoded_shellcode)
    else:
        sys.stdout.buffer.write(encoded_shellcode)
    sys.exit(Error.SUCCESS)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="x86/64 Shellcode encoder as `jmp` instructions.")
    parser.add_argument("filename", 
                        action="store",
                        help="your source shellcode file")

    parser.add_argument("-o", "--out", 
                        action="store", 
                        dest="outfile",
                        required=False,
                        help="the encoded shellcode output file")

    arguments = parser.parse_args()
    main()
