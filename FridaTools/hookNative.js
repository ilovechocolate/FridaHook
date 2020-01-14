
function getLoadedModules() {
    send("enumerating all loaded modules ...");
    Process.enumerateModules({
        onMatch: function(module) {
            send(module.name + " : " +  module.base + "\t" + module.size + "\t" + module.path);
        },
        onComplete: function() {
            send("enumerating completed !!!");
        }
    });
}

function getExportSymbols(moduleName) {
    var symbols = Module.enumerateExportsSync(moduleName);
    symbols.forEach(function(symbol){
        send(symbol.name + " address = " + symbol.address);
    });
    return symbols;
}

function getModuleAddr(moduleName) {
    var address = Module.findBaseAddress(moduleName);
    if (address != null) {
        send("get module '" + moduleName + "' address = " + address);
    }
    return address;
}

function getExportSymbolAddr(moduleName, symbol_sig) {
    var address = Module.findExportByName(moduleName, symbol_sig);
    if (address != null) {
        send("get symbol '" + symbol_sig + "' address = " + address);
    }
    return address;
}

function getSymbolAddr(moduleName, symbol_sig) {
    var symbols = Module.enumerateSymbolsSync(moduleName);
    var address = null;
    for(var i = 0; i < symbols.length; i++) {
        var symbol = symbols[i];
        if(symbol.name == symbol_sig){
            address = symbol.address;
        }
    }
    if (address != null) {
        send("get symbol '" + symbol_sig + "' address = " + address);
    }
    return address;
}

function getRegisterInfo() {
    var RegisterNativesAddr = getSymbolAddr("libart.so", "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi");
    if(RegisterNativesAddr != null){
        send("find symbol 'RegisterNatives' in libart.so, address = " + RegisterNativesAddr);
        Interceptor.attach(RegisterNativesAddr, {
            onEnter: function(args) {
                var class_name = Java.vm.getEnv().getClassName(args[1]);
                var methods_ptr = ptr(args[2]);
                var module = Process.findModuleByAddress(Memory.readPointer(methods_ptr));
                send("RegisterNativeMethod class = " + class_name + ", module = " + module.name + ", base = " + module.base);
                var method_count = parseInt(args[3]);
                send("registered methods count = " + method_count);
                // get registered native method info
                var offset = Process.pointerSize;
                for (var i = 0; i < method_count; i++) {
                    var name = Memory.readCString(Memory.readPointer(methods_ptr.add(offset*3*i)));
                    var sig = Memory.readCString(Memory.readPointer(methods_ptr.add(offset*3*i+offset)));
                    var address = Memory.readPointer(methods_ptr.add(offset*(3*i+2)));
                    send("methods name = " + name + ", sig = " + sig + ", address = " + ptr(address) + ", offset = " + ptr(address).sub(module.base));
                }
            },
            onLeave: function() {}
        });
    }
}

send("start frida hook ~~~ ");
// getLoadedModules();
// getExportSymbols("libnative-lib.so");
var base = getModuleAddr("libnative-lib.so");
var testAddAddr = getExportSymbolAddr("libnative-lib.so", "_Z7testAddii");
getRegisterInfo();
// getRegisterInfo output:
// find symbol 'RegisterNatives' in libart.so, address = 0x6f5260f740
// RegisterNativeMethod class = com.demo.fridahook.HookClass, module = libnative-lib.so, base = 0x6f32a63000
// registered methods count = 5
// methods name = helloFromNative, sig = ()Ljava/lang/String;, address = 0x6f32a6cc80, offset = 0x9c80
// methods name = testNativeInt, sig = (I)I, address = 0x6f32a6ce38, offset = 0x9e38
// methods name = testNativeBoolean, sig = (Z)Z, address = 0x6f32a6cef8, offset = 0x9ef8
// methods name = testNativeString, sig = (Ljava/lang/String;)Ljava/lang/String;, address = 0x6f32a6cf68, offset = 0x9f68
// methods name = testNativeArray, sig = ([Lcom/demo/fridahook/NormalClass;)[Lcom/demo/fridahook/NormalClass;, address = 0x6f32a6d098, offset = 0xa098

var helloFromNativeOff = 0x9c80;
var testNativeIntOff = 0x9e38;
var testNativeBooleanOff = 0x9ef8;
var testNativeStringOff = 0x9f68;
var testNativeArrayOff = 0xa098;
var testAddOff = 0x99fc;    //testAddAddr.sub(base)


if (base != null) {
    Java.perform(function(){
        // get native function and invoke
        var testAddFunc = new NativeFunction(testAddAddr, "int", ["int", "int"]);
        send("testAdd(111, 222) = " + testAddFunc(111, 222));
        // hook native function testAdd
        Interceptor.attach(testAddAddr, {
            onEnter: function(args) {
                send("before hook : testAdd(" + parseInt(args[0]) + ", " + parseInt(args[1]) + ")");
                args[0] = ptr(333);
                args[1] = ptr(444);
                send("after hook : testAdd(" + parseInt(args[0]) + ", " + parseInt(args[1]) + ")");
            },
            onLeave: function(retval) {
                send("before hook : testAdd = " + parseInt(retval));
                retval.replace(789);
                send("after hook : testAdd = " + parseInt(retval));
            }
        });

        var str = Java.use("java.lang.String");
        // hook native function sayHello
        Interceptor.attach(new NativePointer(base).add(helloFromNativeOff), {
            onEnter: function(args) {},
            onLeave: function(retval) {
                send("before hook : sayHello = " + Java.cast(retval, str));
                var test = Java.vm.getEnv().newStringUtf("SayHello by Frida!");
                retval.replace(ptr(test));
                send("after hook : sayHello = " + Java.cast(test, str));
            }
        });

        // hook native function testInt
        Interceptor.attach(new NativePointer(base).add(testNativeIntOff), {
            onEnter: function(args) {
                send("before hook : testInt(" + parseInt(args[2]) + ")");
                args[2] = ptr(999);
                send("after hook : testInt(" + parseInt(args[2]) + ")");
            },
            onLeave: function(retval) {}
        });

        // hook native function testBoolean
        Interceptor.attach(new NativePointer(base).add(testNativeBooleanOff), {
            onEnter: function(args) {
                send("before hook : testBoolean(" + args[2] + ")");
            },
            onLeave: function(retval) {
                retval.replace(ptr(0x1))
                send("after hook : testBoolean = " + retval);
            }
        });

        // hook native function testSting
        Interceptor.attach(new NativePointer(base).add(testNativeStringOff), {
            onEnter: function(args) {
                send("before hook : testSting(" + Java.cast(ptr(args[2]), str) + ")");
                var test = Java.vm.getEnv().newStringUtf("Hello from Frida!");
                args[2] = ptr(test);
                send("after hook : testSting(" + Java.cast(ptr(args[2]), str) + ")");
            },
            onLeave: function(retval) {
                send("before hook : testSting = " + Java.cast(retval, str));
                var test = Java.vm.getEnv().newStringUtf("Bye from Frida!");
                retval.replace(ptr(test));
                send("before hook : testSting = " + Java.cast(retval, str));
            }
        });

        // hook native function testArray
        Interceptor.attach(new NativePointer(base).add(testNativeArrayOff), {
            onEnter: function(args) {
                this.args2 = args[2];
            },
            onLeave: function(retval) {
                var env = Java.vm.getEnv();
                // get the java class and method id by reflection
                var clazz = env.findClass("com/demo/fridahook/NormalClass");
                var initId = env.getMethodId(clazz, "<init>", "(Ljava/lang/String;)V");
                var getId = env.getMethodId(clazz, "getContent", "()Ljava/lang/String;");
                // get the Java class object by args and call the getContent method
                var getContent = env.nonvirtualVaMethod('pointer', ['void']);
                for (var i = 0; i < 3; i++) {
                    var object = env.getObjectArrayElement(this.args2, i);
                    var content = getContent(env, object, clazz, getId);
                    send("testArray : NormalClass[" + i + "] args = " + Java.cast(content, str));
                }
                for (var i = 0; i < 3; i++) {
                    var object = env.getObjectArrayElement(retval, i);
                    var content = getContent(env, object, clazz, getId);
                    send("before hook : NormalClass[" + i + "] return = " + Java.cast(content, str));
                }
                // call the init method to new Java object array
                var init = env.nonvirtualVaMethod('void', ['pointer']);
                var object1 = env.allocObject(clazz);
                var object2 = env.allocObject(clazz);
                var object3 = env.allocObject(clazz);
                var content1 = env.newStringUtf("Frida NormalClass1");
                var content2 = env.newStringUtf("Frida NormalClass2");
                var content3 = env.newStringUtf("Frida NormalClass3");
                init(env, object1, clazz, initId, content1);
                init(env, object2, clazz, initId, content2);
                init(env, object3, clazz, initId, content3);
                var newArray = env.newObjectArray(3, clazz, ptr(0));
                env.setObjectArrayElement(newArray, 0, object1);
                env.setObjectArrayElement(newArray, 1, object2);
                env.setObjectArrayElement(newArray, 2, object3);
                retval.replace(newArray);
                for (var i = 0; i < 3; i++) {
                    var object = env.getObjectArrayElement(retval, i);
                    var content = getContent(env, object, clazz, getId);
                    send("after hook : NormalClass[" + i + "] return = " + Java.cast(content, str));
                }
            }
        });
    });
}