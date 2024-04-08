# For quick testing
all:
	python3 main.py shellcode.bin -o encoded.bin
# Tester shellcode, you can also use any other type of shellcode
shellcode: shellcode.asm 
	as -o shellcode.o shellcode.asm
	ld -o shellcode.elf shellcode.o
	objcopy -O binary -j .text shellcode.elf shellcode.bin
	rm -f shellcode.elf shellcode.o

# For testing the shellcode
tester: tester.asm
	as -o tester.o tester.asm
	ld -o tester tester.o -z execstack
	rm -f tester.o

