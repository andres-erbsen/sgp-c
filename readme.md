# Dependencies

	sudo pacman -S protobuf libsodium
	wget https://raw.github.com/maandree/sha3sum/master/c/sha3.h
	wget https://raw.github.com/maandree/sha3sum/master/c/sha3.c
	wget http://nanopb.googlecode.com/files/nanopb-0.2.1.tar.gz
	tar xfa nanopb-0.2.1.tar.gz

# Compile

	protoc -o box.pb box.proto
	protoc -o publickey.pb publickey.proto
	python2 nanopb/generator/nanopb_generator.py -f sgp.options box.pb
	python2 nanopb/generator/nanopb_generator.py -f sgp.options publickey.pb

	gcc --std=gnu99 -o sgp-keygen      -I ./nanopb/ nanopb/*.c -lsodium sgp-keygen.c publickey.pb.c
	gcc --std=gnu99 -o sgp-fingerprint -I ./nanopb/ nanopb/*.c -lsodium sgp-fingerprint.c publickey.pb.c sha3.c
	gcc --std=gnu99 -o sgp-seal        -I ./nanopb/ nanopb/*.c -lsodium sgp-seal.c box.pb.c publickey.pb.c -DPB_FIELD_16BIT
	gcc --std=gnu99 -o sgp-open        -I ./nanopb/ nanopb/*.c -lsodium sgp-open.c box.pb.c publickey.pb.c -DPB_FIELD_16BIT

# Use

	./sgp-keygen 1>pk1 2>sk1
	./sgp-fingerprint -h < pk1
	./sgp-keygen 1>pk2 2>sk2
	./sgp-fingerprint -h < pk2
	echo kala | ./sgp-seal pk2 pk1 sk1 | ./sgp-open sk2 2>/dev/null # => "kala\n"
	echo kala | ./sgp-seal pk2 pk1 sk1 | ./sgp-open sk2 2>&1 >/dev/null | ./sgp-fingerprint -h

# License

GPLv3+, but not religious about it. If you'd like to use this code in an open source project, contact me.
