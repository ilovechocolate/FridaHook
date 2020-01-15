
log("start frida hook ~~~ ");
var base = getModuleAddr("libnative-lib.so");
// getExportSymbols("libnative-lib.so");
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
        log("testAdd(111, 222) = " + testAddFunc(111, 222));
        // hook native function testAdd
        hookNativeMethodByAddress(testAddAddr, function(args){
            log("before hook : testAdd(" + parseInt(args[0]) + ", " + parseInt(args[1]) + ")");
            args[0] = ptr(333);
            args[1] = ptr(444);
            log("after hook : testAdd(" + parseInt(args[0]) + ", " + parseInt(args[1]) + ")");
        }, function(retval){
            log("before hook : testAdd = " + parseInt(retval));
            retval.replace(789);
            log("after hook : testAdd = " + parseInt(retval));
        });

        // hook native function sayHello
        var str = Java.use("java.lang.String");
        hookNativeMethodByOffset("libnative-lib.so", helloFromNativeOff, function(){}, function(retval){
            log("before hook : sayHello = " + Java.cast(retval, str));
            var test = Java.vm.getEnv().newStringUtf("SayHello by Frida!");
            retval.replace(ptr(test));
            log("after hook : sayHello = " + Java.cast(test, str));
        });

        // hook native function testInt
        hookNativeMethodByOffset("libnative-lib.so", testNativeIntOff, function(args){
            log("before hook : testInt(" + parseInt(args[2]) + ")");
            args[2] = ptr(999);
            log("after hook : testInt(" + parseInt(args[2]) + ")");
        }, function(){});

        // hook native function testBoolean
        hookNativeMethodByOffset("libnative-lib.so", testNativeBooleanOff, function(args){
            log("before hook : testBoolean(" + args[2] + ")");
        }, function(retval){
            retval.replace(ptr(0x1))
            log("after hook : testBoolean = " + retval);
        });

        // hook native function testSting
        hookNativeMethodByOffset("libnative-lib.so", testNativeStringOff, function(args){
            log("before hook : testSting(" + Java.cast(ptr(args[2]), str) + ")");
            var test = Java.vm.getEnv().newStringUtf("Hello from Frida!");
            args[2] = ptr(test);
            log("after hook : testSting(" + Java.cast(ptr(args[2]), str) + ")");
        }, function(retval) {
            log("before hook : testSting = " + Java.cast(retval, str));
            var test = Java.vm.getEnv().newStringUtf("Bye from Frida!");
            retval.replace(ptr(test));
            log("before hook : testSting = " + Java.cast(retval, str));
        });

        // hook native function testArray
        hookNativeMethodByOffset("libnative-lib.so", testNativeArrayOff, function(args){
            var env = Java.vm.getEnv();
            // get the java class and method id by reflection
            var clazz = env.findClass("com/demo/fridahook/NormalClass");
            var getId = env.getMethodId(clazz, "getContent", "()Ljava/lang/String;");
            // get the Java class object by args and call the getContent method
            var getContent = env.nonvirtualVaMethod('pointer', ['void']);
            for (var i = 0; i < 3; i++) {
                var object = env.getObjectArrayElement(args[2], i);
                var content = getContent(env, object, clazz, getId);
                log("testArray : NormalClass[" + i + "] args = " + Java.cast(content, str));
            }
        }, function(retval) {
            var env = Java.vm.getEnv();
            // get the java class and method id by reflection
            var clazz = env.findClass("com/demo/fridahook/NormalClass");
            var initId = env.getMethodId(clazz, "<init>", "(Ljava/lang/String;)V");
            var getId = env.getMethodId(clazz, "getContent", "()Ljava/lang/String;");
            // get the Java class object by args and call the getContent method
            var getContent = env.nonvirtualVaMethod('pointer', ['void']);
            for (var i = 0; i < 3; i++) {
                var object = env.getObjectArrayElement(retval, i);
                var content = getContent(env, object, clazz, getId);
                log("before hook : NormalClass[" + i + "] return = " + Java.cast(content, str));
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
                log("after hook : NormalClass[" + i + "] return = " + Java.cast(content, str));
            }
        });
        str.$dispose;
    });
}