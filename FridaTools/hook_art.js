// hook functions in libart.so
var is_libart_hooked = false;

var FindClassAddr = null;
var GetMethodIDAddr = null;
var RegisterNativesAddr = null;
var NewStringUTFAddr = null;
var GetStringUTFCharsAddr = null;
var CallObjectMethodAddr = null;

function hook_libart() {
    if (is_libart_hooked === true) {
        return true;
    }
    var symbols = Module.enumerateSymbolsSync("libart.so");

    // get function address
    for(var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        if(symbol.name == "_ZN3art3JNI9FindClassEP7_JNIEnvPKc") {
            FindClassAddr = symbol.address;
            send("FindClass : symbol = " + symbol.name + ", address = " + symbol.address);
        } else if(symbol.name == "_ZN3art3JNI11GetMethodIDEP7_JNIEnvP7_jclassPKcS6_") {
            GetMethodIDAddr = symbol.address;
            send("GetMethodID : symbol = " + symbol.name + ", address = " + symbol.address);
        } else if(symbol.name == "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi") {
            RegisterNativesAddr = symbol.address;
            send("RegisterNatives : symbol = " + symbol.name + ", address = " + symbol.address);
        } else if(symbol.name == "_ZN3art3JNI12NewStringUTFEP7_JNIEnvPKc") {
            NewStringUTFAddr = symbol.address;
            send("NewStringUTF : symbol = " + symbol.name + ", address = " + symbol.address);
        } else if(symbol.name == "_ZN3art3JNI17GetStringUTFCharsEP7_JNIEnvP8_jstringPh") {
            GetStringUTFCharsAddr = symbol.address;
            send("GetStringUTFChars : symbol = " + symbol.name + ", address = " + symbol.address);
        } else if(symbol.name.indexOf("_ZN3art3JNI16CallObjectMethodEP7_JNIEnvP8_jobjectP10_jmethodIDz") >= 0) {
            CallObjectMethodAddr = symbol.address;
            send("CallObjectMethod : symbol = " + symbol.name + ", address = " + symbol.address);
        }
    }

    is_libart_hooked = true;
    return is_libart_hooked;
}

/*
// hook native function demos
Interceptor.attach(addr, {
    onEnter: function(args) {},
    onLeave: function(retval) {}
});
*/

function hookFindClass() {
    // art::JNI::FindClass(_JNIEnv *, char const*)
    if (FindClassAddr != null) {
        Interceptor.attach(FindClassAddr, {
            onEnter: function(args) {
                if (args[1] != null) {
                    send("FindClass = " + Memory.readCString(args[1]));
                }
            },
            onLeave: function(retval) {}
        });
    }
}

function hookGetMethodID() {
    // art::JNI::GetMethodID(_JNIEnv *, _jclass *, char const*, char const*)
    if (GetMethodIDAddr != null) {
        Interceptor.attach(GetMethodIDAddr, {
            onEnter: function(args) {
                if (args[2] != null) {
                    send("GetMethodID name = " + Memory.readCString(args[2]));
                    if (args[3] != null) {
                        send("GetMethodID sig = " + Memory.readCString(args[3]));
                    }
                }
            },
            onLeave: function(retval) {}
        });
    }
}

function hookRegisterNatives() {
    Java.perform(function(){
        // art::JNI::RegisterNatives(_JNIEnv *, _jclass *, JNINativeMethod const*, int)
        if (RegisterNativesAddr != null) {
            Interceptor.attach(RegisterNativesAddr, {
                onEnter: function(args) {
                    var count = parseInt(args[3]);
                    send("RegisterNativeMethod Count = " + count);
                    // jni method array declares Java method name pointer, sig pointer, native method pointer
                    var class_name = Java.vm.getEnv().getClassName(args[1]);
                    var methods = ptr(args[2]);
                    var module = Process.findModuleByAddress(Memory.readPointer(methods));
                    send("RegisterNativeMethod class = " + class_name + ", module = " + module.name + ", base = " + module.base);
                    // get registered native method info
                    var offset = Process.pointerSize;
                    for(var i = 0; i < count; i++) {
                        var name = Memory.readCString(Memory.readPointer(methods.add(offset * 3 * i)));
                        var sig = Memory.readCString(Memory.readPointer(methods.add(offset * (3 * i + 1))));
                        var addr = Memory.readPointer(methods.add(offset * (3 * i + 2)));
                        send("RegisterNativeMethod name = " + name + ", sig = " + sig + ", addr = " + addr + ", offset = " + ptr(addr).sub(module.base));
                    }
                },
                onLeave: function(retval) {}
            });
        }
    });
}

function hookNewStringUTF() {
    // art::JNI::NewStringUTF(_JNIEnv *, char const*)
    if (NewStringUTFAddr != null) {
        Interceptor.attach(NewStringUTFAddr, {
            onEnter: function(args) {
                if (args[1] != null) {
                    send("NewStringUTF = " + Memory.readCString(args[1]));
                }
            },
            onLeave: function(retval) {}
        });
    }
}

function hookGetStringUTFChars() {
    // art::JNI::GetStringUTFChars(_JNIEnv *, _jstring *, unsigned char *)
    if (GetStringUTFCharsAddr != null) {
        Interceptor.attach(GetStringUTFCharsAddr, {
            onEnter: function(args) {},
            onLeave: function(retval) {
                if (retval != null) {
                    send("GetStringUTFChars = " + Memory.readCString(retval));
                }
            }
        });
    }
}


// run test
if (hook_libart()) {
    hookRegisterNatives();
//    hookGetStringUTFChars();
}
