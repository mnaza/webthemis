/*
* Copyright (c) 2015 Cossack Labs Limited
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

function secure_session_client(url, client_id, base64_client_private_key, server_id, base64_server_piublic_key){
    var secure_session_create = Module.cwrap('secure_session_client_create','pointer',['string', 'string', 'string', 'string']);
    this.session_destroy = Module.cwrap('secure_session_client_destroy','number',['number']);
    this.arr2C = function(arr){
	var ret = Runtime.stackAlloc(arr.byteLength);
	var dataHeap = new Uint8Array(Module.HEAPU8.buffer, ret, arr.byteLength);
	dataHeap.set(new Uint8Array(arr));
	return ret;
    }
    
    this.session = secure_session_create(client_id, base64_client_private_key, server_id, base64_server_piublic_key);
    if(!(this.session))
	return false;
    this.socket = new WebSocket(url);
    this.socket.binaryType = "arraybuffer";
    this.socket.onopen=function(){
	var error;
	var stack = Runtime.stackSave();
	var plength = Runtime.stackAlloc(4);
	if(plength && (-4 == _secure_session_client_connect_request(this.session, 0, plength))){
	    var pdata = Runtime.stackAlloc(getValue(plength, "i32", true));
	    if(pdata && (0 == _secure_session_client_connect_request(this.session, pdata, plength))){
		this.socket.send(HEAPU8.subarray(pdata, pdata+getValue(plength, "i32", true)));
	    }else{
		error = "secure session connection request";
	    }
	}else{
	    error = "secure session connection request length determination error";
	}
	if(error)
	    this.onError(error);
	Runtime.stackRestore(stack);
    }.bind(this);

    this.socket.onclose = function(event){
	this.onClose(event);
    }.bind(this);

    this.socket.onmessage = function(event){
	var stack = Runtime.stackSave();
	var error;
	if (event.data instanceof ArrayBuffer){
	    var arr = this.arr2C(event.data);
	    var plength = Runtime.stackAlloc(4);
	    if (plength){
		var r = _secure_session_client_unwrap(this.session, arr, event.data.byteLength, 0, plength);
		if(0 == r && 0 == getValue(plength, "i32", true)){
		    this.onOpen();
		} else if (-4 == r){
		    var pdata = Runtime.stackAlloc(getValue(plength, "i32", true));
		    if(pdata ){
			r = _secure_session_client_unwrap(this.session, arr, event.data.byteLength, pdata, plength);
			if(1 == r)
			    this.socket.send(HEAPU8.subarray(pdata, pdata+getValue(plength, "i32", true)));
			else if (0 == r)
			    this.onMessage(AsciiToString(pdata));
			else
			    error = "secure session unwrap error: " + r;
		    } else 
			error = "stack allocation error: "+getValue(plength, "i32", true) + " bytes";
		} else
		    error = "secure session unwrap error (unwrapped message length determination): "+r;
	    } else
		error = "stack allocation error: "+ 4 + " bytes";
	} else
	    error = "only binary message allow";
	if(error)
	    this.onError(error);
	Runtime.stackRestore(stack);
    }.bind(this);

    this.socket.onerror = function(error){
	this.onError(error);
    }.bind(this);
}

secure_session_client.prototype.close = function(){
    if(this.session)
	this.session_destroy(this.session);
    if(this.socket)
	this.socket.close();
}

secure_session_client.prototype.send = function(msg){
    var error; 
    var stack = Runtime.stackSave();
    if(this.session && this.socket){
	if(typeof msg === "string"){
            var pmsg=Runtime.stackAlloc(msg.length+1);
	    if(pmsg){
		stringToAscii(msg, pmsg);
		setValue(pmsg+msg.length, 0, "i8", true);
	    	var plength = Runtime.stackAlloc(4);
		if(plength && -4 == _secure_session_client_wrap(this.session, pmsg, msg.length+1, 0, plength)){
		    var pdata = Runtime.stackAlloc(getValue(plength, "i32", true));
		    if(pdata && 0 == _secure_session_client_wrap(this.session, pmsg, msg.length+1, pdata, plength)){
			this.socket.send(HEAPU8.subarray(pdata, pdata+getValue(plength, "i32", true)));
		    }else
			error = "secure session wrap error";		    
		}else
		    error = "secure session wrap error (wrapped message length determination)";		    
	    }else
		error = "stack allocation error: "+ msg.length+1 + " bytes";
	}else
	    error = "secure session client allow to send only strings";
    }else
	error = "secure session client object not initialise";
    if(error)
	this.onError(error);
    Runtime.stackRestore(stack);
}


secure_session_client.prototype.onOpen = function(){}
secure_session_client.prototype.onClose = function(event){}
secure_session_client.prototype.onMessage = function(msg){}
secure_session_client.prototype.onError = function(error){}
