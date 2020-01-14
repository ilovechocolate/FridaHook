setImmediate(function(){
    Java.perform(function(){
        log("start frida hook ~~~ ");

        // hook java function
        var hookClassName = "com.demo.fridahook.HookClass";
        var hookClass = Java.use(hookClassName);
        overloadMethod(hookClassName, "$init", ["int", "java.lang.String"], function(){
            log("HookClass(" + arguments[0] + ", " + arguments[1] + ")");
            return this.$init(200, "HookClass got hooked!");
        });

        // hook static variable TAG
        var clazz = Java.use("java.lang.Class");
        var tag = Java.cast(hookClass.class, clazz).getDeclaredField("TAG");
        tag.setAccessible(true);
        tag.set("java.lang.String", "FridaHooked");
        tag.setAccessible(false);
        log("change tag to 'FridaHooked'");

        // construct instance
        var ins = hookClass.$new(1111, "hook HookClass");
        log("hook HookClass instance = " + ins);
        var ins1 = hookClass.$new.overload("int", "java.lang.String").call(hookClass, 2222, "hook HookClass again");
        log("hook HookClass instance again = " + ins1);

        // list all decalred methods
        getAllMethods(hookClassName);

        // test invoke function by reflection
        log("test invoke 'testString' by reflection")
        var string = Java.use("java.lang.String");
        var func = hookClass.class.getDeclaredMethod("testString", Java.array("java.lang.Class", [string.class]));
        log("testString = " + func);
        // todo
//        func.invoke(this, Java.array("java.lang.Class",[string.$init("reflection hook").class]));
        log("call 'testString' by reflection");

        // test invoke normal class
        var normalClass = Java.use("com.demo.fridahook.NormalClass");
        var content = normalClass.$new("hook Normalclass").getContent();
        log("call normal class and return " + content);

        // hook static function testInt and overload
        hookMethod(hookClassName, "testInt", function(num){
            // modify field by reflection
            log("test modify field by reflection in testInt");
            var ins_number = Java.cast(ins.getClass(), clazz).getDeclaredField("number");
            ins_number.setAccessible(true);
            log("before hook : " + ins_number + " = " + ins_number.get(ins));
            ins_number.setInt(ins, 4444);
            ins_number.setAccessible(false);
            log("after hook : " + ins_number + " = " + ins_number.get(ins));
            // invoke function in hook
            log("call 'testString()' of instance")
            ins.testString("called in hook");

            log("hook HookClass.testInt(" + arguments[0] + ")");
            return this.testInt(3333);
        });

        // hook function testString
        hookMethod(hookClassName, "testString", function(test){
            log("hook HookClass.testString(" + arguments[0] + ") = " + this.testString(test));
            return this.testString("hahaha, got hooked!")
        });

        // hook function testArray
        hookMethod(hookClassName, "testArray", function(array){
            log("before hook : HookClass.testArray(" + array[0].getContent() + ")");
            var newArray = Java.array("com.demo.fridahook.NormalClass", [normalClass.$new("hook NormalClass1"), normalClass.$new("hook NormalClass2"), normalClass.$new("hook NormalClass3")]);
            log("after hook : HookClass.testArray(" + newArray[0].getContent() + ")");
            return this.testArray(newArray);
        });

        // hook abstract class
        overloadMethod("com.demo.fridahook.HookClass$1", "setAbs", ["java.lang.String"], function(test) {
            log("overload AbstractClass.setAbs(" + arguments[0] + ")");
            return this.setAbs("hook setAbs");
        });

        // overload inner class
        overloadMethod("com.demo.fridahook.HookClass$InnerClass", "$init", ["com.demo.fridahook.HookClass", "java.lang.String"], function(clazz, test){
            log("overload HookClass.InnerClass(" + test + ")");
            return this.$init(clazz, "hook InnerClass");
        });

        // hook inner class function
        hookMethod("com.demo.fridahook.HookClass$InnerClass", "testInner", function(test){
            log("get field by reflection in testInner");
            var innerCont = this.getClass().getDeclaredField("innerContent");
            innerCont.setAccessible(true);
            this.innerContent.value = "hook InnerClass by way 1";
            // todo
            // innerCont.set(innerClass, "hook InnerClass by way 2");
            innerCont.setAccessible(false);
            log("overload HookClass.InnerClass.testInner(" + test + ")");
            return this.testInner("hook testInner");
        });
    });
});