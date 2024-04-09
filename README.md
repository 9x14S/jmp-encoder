# jmp-encoder
A `x86/64` Shellcode Encoder using `jmp` instructions

## Why?
Because I participated in TAMUCTF 2024 and found a [challenge](https://github.com/tamuctf/tamuctf-2024/tree/master/pwn/janky) there that required shellcode like this. This encoder just automates that.

## Usage

Make sure you have `capstone` installed. If not, run `pip install capstone`. 

Then, run the `main.py` script and pass the shellcode file path as an argument or pipe into the script like
`cat shellcode.bin | python3 main.py`. 
Optionally, you can use `-o <outfile>` to save it into a file or just redirect into a 
file like `python3 main.py shellcode.bin > encoded`.

## Todo

[ ] - Add some efficiency by joining short instructions into a single `jmp` instruction.

[ ] - If possible, add checks that check if the inputted shellcode is `x86/64`.

[ ] - Test and debug. Also check if it works for `x86` (only tested with `x64`) shellcode.

