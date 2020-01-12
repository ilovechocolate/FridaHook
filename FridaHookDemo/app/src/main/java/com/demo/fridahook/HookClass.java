package com.demo.fridahook;

import android.util.Log;

public class HookClass {

    public static String TAG = "FridaHook";

    private static int number;
    private String content;

    public HookClass(){}

    public HookClass(int number, String content){
        this.number = number;
        this.content = content;
        Log.d(TAG, "HookClass(" + number + ", " + content + ") is constructed!");
    }

    public static int testInt(int num) {
        Log.d(TAG, "testInt add(" + number + ", " + num + ")");
        return number + num;
    }

    public String testString(String test) {
        Log.d(TAG, "testString append(" + this.content + ", " + test + ")");
        return this.content + " " + test;
    }

    public void testArray(NormalClass[] classes) {
        for (int i = 0; i < classes.length; i++) {
            Log.d(TAG, "NormalClass[" + i + "].getContent = " + classes[i].getContent());
        }
    }

    public void testAbstract() {
        new AbstractClass() {
            @Override
            public void setAbs(String test) {
                Log.d(TAG, "AbstractClass(" + this.abs + ").setAbs(" + test + ")");
            }
        }.setAbs("testAbstract");
    }

    public class InnerClass {
        private String innerContent;

        public InnerClass(String innerContent) {
            this.innerContent = innerContent;
        }

        public void testInner(String innerContent) {
            Log.d(TAG, "InnerClass(" + this.innerContent + ").testInner(" + innerContent + ")");
        }
    }

    public native String helloFromNative();
    public native int testNativeInt(int test);
    public native boolean testNativeBoolean(boolean flag);
    public native String testNativeString(String test);
    public native NormalClass[] testNativeArray(NormalClass[] classes);

    public void display(){
        Log.d(TAG, "testInt result = " + testInt(666));
        Log.d(TAG, "testString result = " + testString("append a test string"));
        NormalClass[] normalClasses = {
                new NormalClass("NormalClass1"),
                new NormalClass("NormalClass2"),
                new NormalClass("NormalClass3")
        };
        testArray(normalClasses);
        testAbstract();
        HookClass.InnerClass innerClass = new HookClass().new InnerClass("InnerClass");
        innerClass.testInner("testInner");

        // test native
        Log.d(TAG, "helloFromNative = " + helloFromNative());
        Log.d(TAG, "testNativeInt number(666) = " + testNativeInt(888));
        Log.d(TAG, "testNativeBoolean flag(true) = " + testNativeBoolean(true));
        Log.d(TAG, "testNativeString string(Hello from Java!) = " + testNativeString("Hello from Java!"));
        NormalClass[] newNormalClass = testNativeArray(normalClasses);
        for (int i = 0; i < newNormalClass.length; i ++) {
            Log.d(TAG, "testNativeArray newNormalClass[" + i + "] = " + newNormalClass[i].getContent());
        }
    }
}
