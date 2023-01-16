
#DEBUG=-D DEBUG
CFLAGS=-g -Wall $(DEBUG)
CFLAGS_=-D USE_OLD_SECTION -D USING_SAFE_FUNC $(DEBUG)
LLVM-STRIP=llvm-strip-13

all: bpf.o bpf_l.o

clean:
	rm *.li *.o

bpf.li: 
	clang -O2 $(CFLAGS) -emit-llvm -c bpf.c -o bpf.li

bpf.o: bpf.li
	llc -march=bpf -filetype=obj -o bpf.o bpf.li
	$(LLVM-STRIP) -g bpf.o

bpf_l.li:
	clang -O2 $(CFLAGS_) -emit-llvm -c bpf.c -o bpf_l.li

bpf_l.o: bpf_l.li
	llc -march=bpf -filetype=obj -o bpf_l.o bpf_l.li


