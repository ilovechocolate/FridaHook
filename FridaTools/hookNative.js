
function getModules() {
    Process.enumerateModules({
        onMatch: function(module) {
            send(module.name + " : " +  module.base + "\t" + module.size + "\t" + module.path);
        },
        onComplete: function() {
            send("enumerateModules completed!");
        }
    });
}

function getExportSymbols(module) {
    var symbols = Module.enumerateExportsSync(module);
    for(var i = 0; i < symbols.length; i++) {
        send(symbols[i].name + " : " + symbols[i].address);
    }
    return symbols;
}

function getModuleAddr(module) {
    send("module address = " + Module.findBaseAddress(module));
    return Module.findBaseAddress(module);
}

function getSymbolAddr(module, symbol_sig) {
    var address = Module.findExportByName(module, symbol_sig);
    send("findExportByName address = " + address);
    if (address != null) {
        Interceptor.attach(address, {
            onEnter: function(args) {
//                send("open(" + Memory.readCString(args[0]) + "," + args[1] + ")");
    //            //获取函数名
    //            var method_name=args[2].add(0x10).readPointer().readUtf8String();
    //            //获取函数地址
    //            var method_insns=args[2].add(0x20).readPointer();
    //            //判断是否是所要查找函数
    //            if(method_name=='doCommandNative'){
    //                //创建模块快照
    //                var mod_map=new ModuleMap();
    //                var mod=mod_map.find(method_insns);
    //                var offset=method_insns.sub(mod.base);
    //                ("module_name: "+mod.name+"       "+"offset: "+offset.toString());
    //            }
            },
            onLeave: function() {}
        });
    }
    return address;
}

function getRegisterInfo(module) {
    var RegisterNativesAddr = null;
    var symbols = Module.enumerateSymbolsSync("libart.so");
    for (var i = 0; i < symbols.length; i++) {
        if (symbols[i].name == "_ZN3art3JNI15RegisterNativesEP7_JNIEnvP7_jclassPK15JNINativeMethodi") {
            RegisterNativesAddr = symbols[i].address;
            send("find symbol 'RegisterNatives' in libart.so");
            break;
        }
    }

    if (RegisterNativesAddr != null) {
        Interceptor.attach(RegisterNativesAddr, {
            onEnter: function(args) {
                var methods_ptr = ptr(args[2]);
                var method_count = parseInt(args[3]);
                send("methods count = " + method_count);
                var module_base = Process.findModuleByAddress(Memory.readPointer(methods_ptr)).base;
                var offset = Process.pointerSize;
                for (var i = 0; i < method_count; i++) {
                    var name = Memory.readCString(Memory.readPointer(methods_ptr.add(offset*3*i)));
                    var sig = Memory.readCString(Memory.readPointer(methods_ptr.add(offset*3*i+offset)));
                    var address = Memory.readPointer(methods_ptr.add(offset*(3*i+2)));
                    send("methods name = " + name + ", sig = " + sig + ", address = " + ptr(address) + ", offset = " + ptr(address).sub(module_base));
                }
            },
            onLeave: function() {}
        });
    }
}


send("start frida hook ~~~ ");
//getModules();
//getExportSymbols("libnative-lib.so");
getRegisterInfo("libnative-lib.so");
// getRegisterInfo output:
// methods count = 5
// methods name = helloFromNative, sig = ()Ljava/lang/String;, address = 0x70640d9c80, offset = 0x9c80
// methods name = testNativeInt, sig = (I)I, address = 0x70640d9e38, offset = 0x9e38
// methods name = testNativeBoolean, sig = (Z)Z, address = 0x70640d9ef8, offset = 0x9ef8
// methods name = testNativeString, sig = (Ljava/lang/String;)Ljava/lang/String;, address = 0x70640d9f68, offset = 0x9f68
// methods name = testNativeArray, sig = ([Lcom/demo/fridahook/NormalClass;)[Lcom/demo/fridahook/NormalClass;, address = 0x70640da098, offset = 0xa098
var base = getModuleAddr("libnative-lib.so");
var testAddAddr = getSymbolAddr("libnative-lib.so", "_Z7testAddii");

var helloFromNativeOff = 0x9c80;
var testNativeIntOff = 0x9e38;
var testNativeBooleanOff = 0x9ef8;
var testNativeStringOff = 0x9f68;
var testNativeArrayOff = 0xa098;
var testAddOff = 0x99fc;

// get native function and invoke
var testAddFunc = new NativeFunction(new NativePointer(testAddAddr), "int", ["int", "int"]);
send("testAdd(111, 222) = " + testAddFunc(111, 222));
// hook native function testAdd
Interceptor.attach(testAddAddr, {
    onEnter: function(args) {
        send("before hook : testAddr(" + parseInt(args[0]) + ", " + parseInt(args[1]) + ")");
        args[0] = ptr(333);
        args[1] = ptr(444);
        send("before hook : testAddr(" + parseInt(args[0]) + ", " + parseInt(args[1]) + ")");
    },
    onLeave: function(retval) {
        retval.replace(789);
    }
});

Interceptor.attach(new NativePointer(base).add(helloFromNativeOff), {
    onEnter: function(args) {},
    onLeave: function(retval) {

    }
});

//        send("hooked helloFromNative retval = " + );
//        retval.replace("Hello, Frida!");
//        var s = Java.cast(retval, str);
//        send("say() 原返回值：" + s);
//        //调用env下的方法，构造jstring类型
//        var env = Java.vm.getEnv();
//        var jstring = env.newStringUtf("frida hook native");
//        retval.replace(ptr(jstring));
//        send("修改say()返回值:" + Java.cast(jstring, str));
//
//
//        var feditptr = new NativePointer(soAddr).add(fedit);
//        Interceptor.attach(feditptr, {
//            onEnter: function (args) {
//                send("onEnter edit()");
//                send("edit() env：" + args[0] + "  jobject：" + args[1] + " jint:" + args[2].toInt32());
//                //参数修改使用new NativePointer(s)  简写ptr(s)
//                args[2] = ptr(4);
//                send("hook edit() 修改后的参数jint：" + args[2]);
//            },
//            onLeave: function (retval) {
//                send("onLeave edit()");
//            }
//        });
//
//        var fmystrptr = new NativePointer(soAddr).add(fmystr);
//        send("fmystrptr:" + fmystrptr);
//        Interceptor.attach(fmystrptr, {
//            onEnter: function (args) {
//                send("onEnter mystr()");
//                send("mystr() env：" + args[0] + "  jobject：" + args[1] + " jstring:" + args[2]);
//                var s = Java.cast(args[2], str);
//                send("mystr() jstring参数：" + s);
//
//                //send("mystr："+Memory.readUtf16String(args[2],7));
//                //send("mystr："+Memory.readUtf8String(args[2],7));
//            },
//            onLeave: function (retval) {
//                send("onLeave mystr()");
//                var env = Java.vm.getEnv();
//                var jstring = env.newStringUtf("frida hook native");
//                send("修改返回值jstring:" + jstring);
//                retval.replace(ptr(jstring));
//            }
//        });
//        // Java.choose("com.example.goal.DiyClass",{
//        //     onMatch:function(instance){
//        //         send("DiyClass instance:"+instance);
//        //     },
//        //     onComplete:function(){
//        //
//        //     }
//        //
//        // });
//        var fmyarrayptr = ptr(soAddr).add(fmyarray);
//        //var fmyarrayptr = new NativePointer(soAddr).add(fmyarray);
//        send("fmyarrayptr:" + fmyarrayptr);
//        //var argptr;
//        Interceptor.attach(fmyarrayptr, {
//            onEnter: function (args) {
//                send("onEnter myarray()");
//                send("mystr() env：" + args[0] + "  jobject：" + args[1] + " jobjectArray:" + args[2]);
//                send("jobjectArray参数：" + args[2].toString());
//                //可以在onEnter中通过this.xxx保存变量 在onLeave中通过this.xxx读取
//                this.argptr = args[2]
//
//                //jstring 不同于wchar_t* (jchar*) 与 char*
//                //send("mystr："+Memory.readUtf16String(args[2],7));
//                //send("mystr："+Memory.readUtf8String(args[2],7));
//            },
//            onLeave: function (retval) {
//                send("onLeave myarray()");
//                send("argptr:" + this.argptr);
//
//                var env = Java.vm.getEnv();
//                var cla = env.findClass("com/example/goal/DiyClass");
//                send("clazz:" + cla);
//                var initid = env.getMethodId(cla, "<init>", "(I)V");
//                send("initid:" + initid);
//                var setid = env.getMethodId(cla, "setData", "(I)V");
//                send("setid:" + setid);
//                var getid = env.getMethodId(cla, "getData", "()I");
//                send("getid:" + getid);
//                //frida 中env 方法参考frida-java/lib/env.js  本人能力有限，有些方法确实搞不懂
//                //调用env中的allocObject()方法创建对象，未初始化，
//                var obj1 = env.allocObject(cla);
//                send("obj1:" + obj1);
//
//                var obj2 = env.allocObject(cla);
//                send("obj2:" + obj2);
//
//                var rtarray = env.newObjectArray(2, cla, ptr(0));
//                send("env.newObjectArray:" + rtarray);
//
//                //获取DiyClass类中public void setData(int data)方法
//                var nvmethod = env.nonvirtualVaMethod("void", ["int"]);
//                //NativeType CallNonvirtual<type>Method(JNIEnv *env, jobject obj,jclass clazz, jmethodID methodID, ...);
//                //设置obj1中data值
//                nvmethod(env, obj1, cla, setid, 11);
//                //设置obj2中data值
//                nvmethod(env, obj2, cla, setid, 22);
//                send("env.nonvirtualVaMethod(JNIEnv,jobject,jclass,jmethodid,args):" + nvmethod);
//                //设置数组中的元素
//                env.setObjectArrayElement(rtarray, 0, obj1);
//                env.setObjectArrayElement(rtarray, 1, obj2);
//                send("env.newObjectArray:" + rtarray);
//
//                send("原retval:" + retval);
//                retval.replace(ptr(rtarray));
//                send("修改后retval:" + retval);
//
//                // //堆中分配空间
//                // var memo=Memory.alloc(4);
//                // //写入数据
//                // Memory.writeInt(memo,0x40302010);
//                // // 读取数据
//                // console.log(hexdump(memo, {
//                //         offset: 0,
//                //         length: 64,
//                //         header: true,
//                //         ansi: true
//                // }));
//            }
//        });
//
//    });
//});