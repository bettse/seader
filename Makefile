

all: asn1 build

asn1:
	asn1c -D ./lib/asn1 -no-gen-example -no-gen-OER -no-gen-PER -pdu=all seader.asn1


build:
	ufbt

launch:
	ufbt launch

format:
	ufbt format

clean:
	rm -rf dist
