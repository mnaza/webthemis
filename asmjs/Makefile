#
# Copyright (c) 2015 Cossack Labs Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

SRC_PATH = src
BUILD_PATH = static
LIBS_PATH = libs

all: release

release: static/themis-raw.js
	
debug: static/themis-raw-debug.js

static/themis-raw.js:
	emcc -O3  --memory-init-file 0 -Iinclude -s EXPORTED_FUNCTIONS=@exported_functions $(SRC_PATH)/key_gen.c $(SRC_PATH)/ssession_client.c $(SRC_PATH)/base64.c $(LIBS_PATH)/libthemis.a $(LIBS_PATH)/libsoter.a $(LIBS_PATH)/libcrypto.a -o $(BUILD_PATH)/themis-raw.js

static/themis-raw-debug.js:
	emcc -g -Iinclude -s SAFE_HEAP=1 -s ASSERTIONS=2 -s EXPORTED_FUNCTIONS=@exported_functions $(SRC_PATH)/key_gen.c $(SRC_PATH)/ssession_client.c $(SRC_PATH)/base64.c $(LIBS_PATH)/libthemis.a $(LIBS_PATH)/libsoter.a $(LIBS_PATH)/libcrypto.a -o $(BUILD_PATH)/themis-raw-debug.js

clean:
	rm -rf static/themis-raw.js
	rm -rf static/themis-raw-debug.js

run: release
	./server.py -v

