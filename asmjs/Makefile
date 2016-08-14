
run: release
	./server.py -v

all: release

release: static/themis-raw.js
	

static/themis-raw.js:
	emcc -O3  --memory-init-file 0 -Iinclude -s EXPORTED_FUNCTIONS=@exported_functions key_gen.c ssession_client.c base64.c libs/libthemis.a libs/libsoter.a libs/libcrypto.a -o static/themis-raw.js

debug:
	emcc -g -Iinclude -s SAFE_HEAP=1 -s ASSERTIONS=2 -s EXPORTED_FUNCTIONS=@exported_functions key_gen.c ssession_client.c base64.c libs/libthemis.a libs/libsoter.a libs/libcrypto.a -o static/themis-raw.js

clean:
	rm static/themis-raw.js
	rm static/themis-raw.js.mem