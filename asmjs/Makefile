
run: all
	./lighttpd -m lighttpd_libs/ -f config/lighttpd.conf -D

all: release

release: themis-raw.js
	

themis-raw.js:
	emcc -O2 -Iinclude -s ASSERTIONS=2 -s EXPORTED_FUNCTIONS=@exported_functions key_gen.c ssession_client.c base64.c libs/libthemis.a libs/libsoter.a libs/libcrypto.a -o themis-raw.js

debug:
	emcc -Iinclude -s ASSERTIONS=2 -s EXPORTED_FUNCTIONS=@exported_functions key_gen.c ssession_client.c base64.c libs/libthemis.a libs/libsoter.a libs/libcrypto.a -o themis-raw.js

clean:
	rm themis-raw.js
	rm themis-raw.js.mem