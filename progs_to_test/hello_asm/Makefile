OUTDIR=../bin
OUTFILE=$(OUTDIR)/hello_asm

build:
	mkdir -p $(OUTDIR)
	nasm -f elf64 hello.asm
	ld -s -o $(OUTFILE) hello.o

clean:
	rm $(OUTFILE)
