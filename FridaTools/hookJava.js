setImmediate(function(){
    Java.perform(function(){
        send("start frida hook ~~~ ");

        // hook java function
        var hookClass = Java.use("com.demo.fridahook.HookClass");
        hookClass.$init.overload("int", "java.lang.String").implementation = function(number, content){
            send("HookClass() : number = " + number);
            send("HookClass() : content = " + content);
            return this.$init(200, "HookClass got hooked!");
        };

        // hook static variable TAG
        var clazz = Java.use("java.lang.Class");
        var tag = Java.cast(hookClass.class, clazz).getDeclaredField("TAG");
        tag.setAccessible(true);
        tag.set("java.lang.String", "FridaHooked");
        tag.setAccessible(false);
        send("change tag to 'FridaHooked'");

        // construct instance
        var ins = hookClass.$new(1111, "hook HookClass");
        send("hook HookClass instance = " + ins);
        var ins1 = hookClass.$new.overload("int", "java.lang.String").call(hookClass, 2222, "hook HookClass again");
        send("hook HookClass instance again = " + ins1);

        // list all decalred methods
        send("list all decalred methods in 'HookClass'");
        var funcs = hookClass.class.getDeclaredMethods();
        for(var i = 0; i < funcs.length; i++){
            send("func[" + i + "] = " + funcs[i]);
        }

        // test invoke function by reflection
        send("test invoke 'testString' by reflection")
        var string = Java.use("java.lang.String");
        var func = hookClass.class.getDeclaredMethod("testString", Java.array("java.lang.Class", [string.class]));
        send("testString = " + func);
        // todo
        // func.invoke(this, Java.array("java.lang.Class",[string.$init("reflection hook").class]));
        send("call 'testString' by reflection");

        // test invoke normal class
        var normalClass = Java.use("com.demo.fridahook.NormalClass");
        var content = normalClass.$new("hook Normalclass").getContent();
        send("call normal class and return " + content);

        // hook static function testInt and overload
        hookClass.testInt.overload("int").implementation = function(num){
            // modify field by reflection
            send("test modify field by reflection in testInt");
            var ins_number = Java.cast(ins.getClass(), clazz).getDeclaredField("number");
            ins_number.setAccessible(true);
            send("before hook : " + ins_number + " = " + ins_number.get(ins));
            ins_number.setInt(ins, 4444);
            ins_number.setAccessible(false);
            send("after hook : " + ins_number + " = " + ins_number.get(ins));
            // invoke function in hook
            send("call 'testString()' of instance")
            ins.testString("called in hook");

            send("overload HookClass.testInt(" + arguments[0] + ")");
            return this.testInt(3333);
        }

        // hook function testString
        hookClass.testString.implementation = function(test){
            send("hook HookClass.testString(" + arguments[0] + ")");
            send("hook HookClass.testString(" + test + ")");
            return this.testString("hahaha, got hooked!")
        };

        // hook function testArray
        hookClass.testArray.implementation = function(array){
            send("before hook : HookClass.testArray(" + array[0].getContent() + ")");
            var newArray = Java.array("com.demo.fridahook.NormalClass", [normalClass.$new("hook NormalClass1"), normalClass.$new("hook NormalClass2"), normalClass.$new("hook NormalClass3")]);
            send("after hook : HookClass.testArray(" + newArray[0].getContent() + ")");
            return this.testArray(newArray);
        };

        // hook abstract class
        var absClass = Java.use("com.demo.fridahook.HookClass$1");
        absClass.setAbs.overload("java.lang.String").implementation = function(test) {
            send("overload AbstractClass.setAbs(" + arguments[0] + ")");
            return this.setAbs("hook setAbs");
        };

        // overload inner class
        var innerClass = Java.use("com.demo.fridahook.HookClass$InnerClass");
        innerClass.$init.overload("com.demo.fridahook.HookClass", "java.lang.String").implementation = function(clazz, test){
            send("overload HookClass.InnerClass(" + test + ")");
            return this.$init(clazz, "hook InnerClass");
        };

        // hook inner class function
        innerClass.testInner.implementation = function(test) {
            send("get field by reflection in testInner");
            var innerCont = innerClass.class.getDeclaredField("innerContent");
            innerCont.setAccessible(true);
            this.innerContent.value = "hook InnerClass by way 1";
            // todo
            // innerCont.set(innerClass, "hook InnerClass by way 2");
            innerCont.setAccessible(false);
            send("overload HookClass.InnerClass.testInner(" + test + ")");
            return this.testInner("hook testInner");
        };

    });
});
