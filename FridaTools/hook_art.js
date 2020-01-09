// hook functions in libart.so
var is_libart_hooked = false;

var FindClassAddr = null;
var GetMethodIDAddr = null;
var GetStaticMethodIDAddr = null;
var GetFieldIDAddr = null;
var GetStaticFieldIDAddr = null;
var RegisterNativesAddr = null;
var NewStringUTFAddr = null;
var GetStringUTFCharsAddr = null;
var ReleaseStringUTFCharsAddr = null;
var AllocObjectAddr = null;
var GetObjectClassAddr = null;
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
        } else if(symbol.name == "_ZN3art3JNI17GetStaticMethodIDEP7_JNIEnvP7_jclassPKcS6_") {
            GetStaticMethodIDAddr = symbol.address;
            send("GetStaticMethodID : symbol = " + symbol.name + ", address = " + symbol.address);
        } else if(symbol.name == "_ZN3art3JNI10GetFieldIDEP7_JNIEnvP7_jclassPKcS6_") {
            GetFieldIDAddr = symbol.address;
            send("GetFieldID : symbol = " + symbol.name + ", address = " + symbol.address);
        } else if(symbol.name == "_ZN3art3JNI16GetStaticFieldIDEP7_JNIEnvP7_jclassPKcS6_") {
            GetStaticFieldIDAddr = symbol.address;
            send("GetStaticFieldID : symbol = " + symbol.name + ", address = " + symbol.address);
        } else if(symbol.name == "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi") {
            RegisterNativesAddr = symbol.address;
            send("RegisterNatives : symbol = " + symbol.name + ", address = " + symbol.address);
        } else if(symbol.name == "_ZN3art3JNI12NewStringUTFEP7_JNIEnvPKc") {
            NewStringUTFAddr = symbol.address;
            send("NewStringUTF : symbol = " + symbol.name + ", address = " + symbol.address);
        } else if(symbol.name == "_ZN3art3JNI17GetStringUTFCharsEP7_JNIEnvP8_jstringPh") {
            GetStringUTFCharsAddr = symbol.address;
            send("GetStringUTFChars : symbol = " + symbol.name + ", address = " + symbol.address);
        } else if(symbol.name.indexOf("_ZN3art3JNI21ReleaseStringUTFCharsEP7_JNIEnvP8_jstringPKc") >= 0) {
            ReleaseStringUTFCharsAddr = symbol.address;
            send("ReleaseStringUTFChars : symbol = " + symbol.name + ", address = " + symbol.address);
        } else if(symbol.name.indexOf("_ZN3art3JNI11AllocObjectEP7_JNIEnvP7_jclass") >= 0) {
            AllocObjectAddr = symbol.address;
            send("AllocObject : symbol = " + symbol.name + ", address = " + symbol.address);
        } else if(symbol.name.indexOf("_ZN3art3JNI14GetObjectClassEP7_JNIEnvP8_jobject") >= 0) {
            GetObjectClassAddr = symbol.address;
            send("GetObjectClass : symbol = " + symbol.name + ", address = " + symbol.address);
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
//                    send("GetMethodID name = " + Memory.readCString(args[2]));
                    if (args[3] != null) {
//                        send("GetMethodID sig = " + Memory.readCString(args[3]));
                    }
                }
            },
            onLeave: function(retval) {}
        });
    }
}

function hookGetStaticMethodID() {
    // art::JNI::GetStaticMethodID(_JNIEnv *, _jclass *, char const*, char const*)
    if (GetStaticMethodIDAddr != null) {
        Interceptor.attach(GetStaticMethodIDAddr, {
            onEnter: function(args) {
                if (args[2] != null) {
                    send("GetStaticMethodID name = " + Memory.readCString(args[2]));
                    if (args[3] != null) {
                        send("GetStaticMethodID sig = " + Memory.readCString(args[3]));
                    }
                }
            },
            onLeave: function(retval) {}
        });
    }
}

function hookGetFieldID() {
    // art::JNI::GetFieldID(_JNIEnv *, _jclass *, char const*, char const*)
    if (GetFieldIDAddr != null) {
        Interceptor.attach(GetFieldIDAddr, {
            onEnter: function(args) {
                if (args[2] != null) {
                    send("GetFieldID name = " + Memory.readCString(args[2]));
                    if (args[3] != null) {
                        send("GetFieldID sig = " + Memory.readCString(args[3]));
                    }
                }
            },
            onLeave: function(retval) {}
        });
    }
}

function hookGetStaticFieldID() {
    // art::JNI::GetStaticFieldID(_JNIEnv *, _jclass *, char const*, char const*)
    if (GetStaticFieldIDAddr != null) {
        Interceptor.attach(GetStaticFieldIDAddr, {
            onEnter: function(args) {
                if (args[2] != null) {
                    send("GetStaticFieldID name = " + Memory.readCString(args[2]));
                    if (args[3] != null) {
                        send("GetStaticFieldID sig = " + Memory.readCString(args[3]));
                    }
                }
            },
            onLeave: function(retval) {}
        });
    }
}

function hookRegisterNatives() {
    // art::JNI::RegisterNatives(_JNIEnv *, _jclass *, JNINativeMethod const*, int)
    if (RegisterNativesAddr != null) {
        Interceptor.attach(RegisterNativesAddr, {
            onEnter: function(args) {
                var env = args[0];
                var className = args[1];    // string pointer of Java class name who registers native methods
                var methods = ptr(args[2]);     // jni method array declares Java method name pointer, sig pointer, native method pointer
                var count = parseInt(args[3]);      // jni method count
                send("RegisterNativeMethod Count = " + count);
                // get native functions
                var GetMethodIDFunc = new NativeFunction(GetMethodIDAddr, "pointer", ["pointer", "pointer", "pointer", "pointer"]);
                var AllocObjectFunc = new NativeFunction(AllocObjectAddr, "pointer", ["pointer", "pointer"]);
                var GetObjectClassFunc = new NativeFunction(GetObjectClassAddr, "pointer", ["pointer", "pointer"]);
                var CallObjectMethodFunc = new NativeFunction(CallObjectMethodAddr, "pointer", ["pointer", "pointer", "pointer"]);
                var GetStringUTFCharsFunc = new NativeFunction(GetStringUTFCharsAddr, "pointer", ["pointer", "pointer", "pointer"]);
                var ReleaseStringUTFCharsFunc = new NativeFunction(ReleaseStringUTFCharsAddr, "pointer", ["pointer", "pointer", "pointer"]);
                // call 'getClass()', returns an object of 'Ljava/lang/Class;'
                var classNameObject = AllocObjectFunc(env, className);
                var getClassMethodID = GetMethodIDFunc(env, className, Memory.allocUtf8String("getClass"), Memory.allocUtf8String("()Ljava/lang/Class;"));
                var clazz = CallObjectMethodFunc(env, classNameObject, getClassMethodID);
                // call 'getName()', returns the name of the class in string format
                var clazzClass = GetObjectClassFunc(env, clazz);
                var getNameMethodID = GetMethodIDFunc(env, clazzClass, Memory.allocUtf8String("getName"), Memory.allocUtf8String("()Ljava/lang/String;"));
                var name_jstring = CallObjectMethodFunc(env, clazz, getNameMethodID);
                // convert string in java to native, in 'const char*' format
                var name_pchar = GetStringUTFCharsFunc(env, name_jstring, ptr(0));
                var class_name = ptr(name_pchar).readCString();
                ReleaseStringUTFCharsFunc(env, name_jstring, name_pchar);
                // get module by address
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
}

function hookNewStringUTF() {
    // art::JNI::NewStringUTF(_JNIEnv *, char const*)
    if (NewStringUTFAddr != null) {
        Interceptor.attach(NewStringUTFAddr, {
            onEnter: function(args) {
                if (args[1] != null) {
//                    send("NewStringUTF = " + Memory.readCString(args[1]));
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
