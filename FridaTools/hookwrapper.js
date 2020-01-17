// this is a frida hook wrapper

function log(message){
    console.log("*****[frida hook]***** : " + message);
}

log("this is a frida hook wrapper");

// enumerating all loaded classes
function getLoadedClass(){
    log("enumerating all loaded classes ...");
    Java.enumerateLoadedClasses({
        onMatch:function(_className){
            log("found instance of '" + _className + "'");
        },
        onComplete: function(){
            log("enumerating completed !!!");
        }
    });
}

// check specific class loaded
function isClassLoaded(className){
    Java.enumerateLoadedClasses({
        onMatch:function(_className){
            if(_className == className){
                log("class '" + className + "' is loaded");
            }
        },
        onComplete:function(){
            log("onComplete");
        }
    });
}

// locating the specific class to check instance
function getClassInstance(className){
    Java.choose(className, {
        onMatch:function(instance){
            log("find class '" + className + "' instance = " + instance);
        },
        onComplete:function(){
            log("choose complete!!!")
        }
    });
}

// enumerating all methods of the specific class by name
function getAllMethods(className){
    var clazz = Java.use(className);
    var methods = clazz.class.getDeclaredMethods();
    clazz.$dispose;
    if(methods.length > 0){
        log("getDeclaredMethods of class '" + className + "':");
        methods.forEach(function(method){
            log(method);
        });
    }
}

// enumerating all methods of the specific class by object
function getAllMethodsByObject(classObject){
    var clazz = Java.cast(classObject.getClass(), Java.use('java.lang.Class'));
    var methods = clazz.getDeclaredMethods();
    clazz.$dispose;
    if(methods.length > 0){
        log("getDeclaredMethods of class '" + classObject.getClass() + "':");
        methods.forEach(function(method){
            log(method);
        });
    }
}

// enumerating all fields of the specific class by name
function getAllFields(className){
    var clazz = Java.use(className);
    var fields = clazz.class.getDeclaredFields();
    clazz.$dispose;
    if(fields.length > 0){
        log("getDeclaredFields of class '" + className + "':");
        fields.forEach(function(field){
            log(field);
        });
    }
}

// enumerating all fields of the specific class by object
function getAllFieldsByObject(classObject){
    var clazz = Java.cast(classObject.getClass(), Java.use('java.lang.Class'));
    var fields = clazz.getDeclaredFields();
    clazz.$dispose;
    if(fields.length > 0){
        log("getDeclaredFields of class '" + classObject.getClass() + "':");
        fields.forEach(function(field){
            field.setAccessible(true);
            log(field + " = " + field.get(classObject));
            field.setAccessible(false);
        });
    }
}

function throwException(message){
    log("throw Exception(" + message + ")");
    throw Java.use("java.lang.Exception").$new(message);
}

/* locating the specific class and hook the method
 * className : hooked class name
 * methodName : hooked method name
 * argumentTypes : method arguments type array
 * callback : override method implementation
 */
function hookMethod(className, methodName, callback){
    var clazz = Java.use(className);
    clazz[methodName].implementation = callback;
    clazz.$dispose;
}

/* locating the specific class and hook the override method
 * className : hooked class name
 * methodName : hooked method name
 * argumentTypes : method arguments type array
 * callback : override method implementation
 */
function hookOverloadMethod(className, methodName, argumentTypes, callback){
    var clazz = Java.use(className);
    clazz[methodName].overload.apply(this, argumentTypes).implementation = callback;
    clazz.$dispose;
}

// get the StackTrace
function getStackTrace(){
    var stack = Java.use("java.lang.Thread").$new().currentThread().getStackTrace();
    for(var i = 2; i < stack.length; i++){
        log("getStackTrace[" + (i-2) + "] : " + stack[i].toString());
    }
    stack.$dispose;
}

// enumerating all loaded modules
function getLoadedModules() {
    log("enumerating all loaded modules ...");
    Process.enumerateModules({
        onMatch: function(module) {
            log(module.name + " : " +  module.base + "\t" + module.size + "\t" + module.path);
        },
        onComplete: function() {
            log("enumerating completed !!!");
        }
    });
}

// enumerating all threads
function getThreads() {
    log("enumerating all threads ...");
    Process.enumerateThreads({
        onMatch: function(thread) {
            log("Thread[" + thread.id + "](" + thread.state + ") : " +  JSON.stringify(thread.context));
        },
        onComplete: function() {
            log("enumerating completed !!!");
        }
    });
}

// enumerating all exported symbols of the module
function getExportSymbols(moduleName) {
    var symbols = Module.enumerateExportsSync(moduleName);
    symbols.forEach(function(symbol){
        log(symbol.name + " address = " + symbol.address);
    });
    return symbols;
}

// get module address when loaded to memory
function getModuleAddr(moduleName) {
    var address = Module.findBaseAddress(moduleName);
    if (address != null) {
        log("get module '" + moduleName + "' address = " + address);
    }
    return address;
}

// get exported symbol address of module when loaded to memory
function getExportSymbolAddr(moduleName, symbol_sig) {
    var address = Module.findExportByName(moduleName, symbol_sig);
    if (address != null) {
        log("get symbol '" + symbol_sig + "' address = " + address);
    }
    return address;
}

// get symbol address of module when loaded to memory
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
        log("get symbol '" + symbol_sig + "' address = " + address);
    }
    return address;
}

// get info of registered native methods
function getRegisterInfo() {
    var RegisterNativesAddr = getSymbolAddr("libart.so", "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi");
    if(RegisterNativesAddr != null){
        log("find symbol 'RegisterNatives' in libart.so, address = " + RegisterNativesAddr);
        Interceptor.attach(RegisterNativesAddr, {
            onEnter: function(args) {
                var class_name = Java.vm.getEnv().getClassName(args[1]);
                var methods_ptr = ptr(args[2]);
                var module = Process.findModuleByAddress(Memory.readPointer(methods_ptr));
                log("RegisterNativeMethod class = " + class_name + ", module = " + module.name + ", base = " + module.base);
                var method_count = parseInt(args[3]);
                log("registered methods count = " + method_count);
                // get registered native method info
                var offset = Process.pointerSize;
                for (var i = 0; i < method_count; i++) {
                    var name = Memory.readCString(Memory.readPointer(methods_ptr.add(offset*3*i)));
                    var sig = Memory.readCString(Memory.readPointer(methods_ptr.add(offset*3*i+offset)));
                    var address = Memory.readPointer(methods_ptr.add(offset*(3*i+2)));
                    log("methods name = " + name + ", sig = " + sig + ", address = " + ptr(address) + ", offset = " + ptr(address).sub(module.base));
                }
            },
            onLeave: function() {}
        });
    }
}

// hook native method by symbol
function hookNativeMethod(moduleName, symbol_sig, onEnterCallbk, onLeaveCallbk){
    var addr = getSymbolAddr(moduleName, symbol_sig);
    if(addr == null){
        log("cannot found symbol '" + symbol_sig + "' in module '" + moduleName + "'");
    } else {
        log("find symbol 'RegisterNatives' in libart.so, address = " + addr);
        Interceptor.attach(addr, {
            onEnter:function(args){
                onEnterCallbk(args);
            },
            onLeave:function(retval){
                onLeaveCallbk(retval);
            }
        });
    }
}

// hook native method by address
function hookNativeMethodByAddress(address, onEnterCallbk, onLeaveCallbk){
    Interceptor.attach(address, {
        onEnter:function(args){
            onEnterCallbk(args);
        },
        onLeave:function(retval){
            onLeaveCallbk(retval);
        }
    });
}

// hook native method by static address(offset)
function hookNativeMethodByOffset(moduleName, offset, onEnterCallbk, onLeaveCallbk){
    var base = getModuleAddr(moduleName);
    if(base == null){
        log("cannot found module '" + moduleName + "'");
    } else {
        Interceptor.attach(base.add(offset), {
            onEnter:function(args){
                onEnterCallbk(args);
            },
            onLeave:function(retval){
                onLeaveCallbk(retval);
            }
        });
    }
}

function byteArray2String(byteArray) {
    var bytes = new Uint8Array(byteArray);
    var res = "";
    for(var i = 0; i < bytes.length; i++) {
        res += String.fromCharCode(bytes[i]);
    }
    log("byteArray2String = " + res);
    return res;
}

function dumpMemory(address, size){
    log(hexdump(address, {
        offset: 0,
        length: size,
        header: true,
        ansi: true
    }));
    return new NativePointer(address).readByteArray(size);
}

function dumpDex(){
    var dexHeader = "64 65 78 0a 30 33 35 00";      // dex.035
    var res = [];
    Process.enumerateRanges("r--").forEach(function(range){
        try {
            // 从 range.base 开始搜索 range.size 大小的内存，寻找匹配 dexHeader 的数据
            Memory.scanSync(range.base, range.size, dexHeader).forEach(function(dex){
                var memory = Process.findRangeByAddress(dex.address);
                log(memory.file.path);
                log("memory base = " + memory.base + ", size = " + memory.size);
                log("dex address = " + dex.address + ", size = " + dex.address.add("0x20").readInt());
            });
        } catch(exception) {
            log("deumpDex error! catch excpetion = " + exception);
        }
    });
    return res;
}

function getApplication(){
    return Java.use("android.app.ActivityThread").currentApplication();
}

function getPkgName(){
    log("current package name = " + getApplication().getPackageName());
    return getApplication().getPackageName();
}

function toast(message){
    var curApplication = getApplication();
    if (curApplication != null) {
        var context = curApplication.getApplicationContext();
        var pkgName = curApplication.getPackageName();
        var pkgMgr = curApplication.getPackageManager();
        curApplication.$dispose;
        var activity = pkgMgr.getLaunchIntentForPackage(pkgName).resolveActivityInfo(pkgMgr, 0);
        var Runnable = Java.use("java.lang.Runnable");
        var Toast = Java.use("android.widget.Toast");
        var CharSequence = Java.use("java.lang.CharSequence");
        var String = Java.use("java.lang.String");
        var ToastRunnable = Java.registerClass({
            name: "ToastRunnable",
            implements: [Runnable, ],
            fields: {
                TAG: "java.lang.String",
                content: "java.lang.String"
            },
            methods: {
                $init: function() {
                    this.TAG.value = String.$new("ToastRunnable");
                    log("[" + this.TAG.value + "] run in init");
                },
                setContent: [{
                    returnType: "void",
                    argumentTypes: ["java.lang.String"],
                    implementation: function(test){
                        log("[" + this.TAG.value + "] run in setContent1");
                        this.content.value = String.$new(test);
                    }
                }, {
                    returnType: "void",
                    argumentTypes: ["java.lang.String", "java.lang.String"],
                    implementation: function(test1, test2){
                        log("[" + this.TAG.value + "] run in setContent2");
                        this.content.value = String.$new(test1 + test2);
                    }
                }],
                run: function(){
                    log("[" + this.TAG.value + "] maketoast");
                    Toast.makeText(context, Java.cast(String.$new(this.content.value), CharSequence), 0).show();
                }
            }
        });
        Runnable.$dispose;
        Toast.$dispose;
        CharSequence.$dispose;
        String.$dispose;
        Java.choose(activity.name.value, {
            onMatch: function(instance) {
                var toast = ToastRunnable.$new();
                toast.setContent(message);
                instance.runOnUiThread(toast);
                toast.setContent(message, "!");
                instance.runOnUiThread(toast);
            },
            onComplete: function() {}
        });
    }
}

function printArgsInfo(args) {
    log("argument count = " + args.length);
    for(var i = 0; i < args.length; i++) {
        log("arguments[" + i + "] = " + arguments[i]);
    }
}
