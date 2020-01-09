#include <jni.h>
#include <string>
#include<android/log.h>

#define LOG_TAG "FridaHook-native"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

inline const char * const BoolToString(jboolean flag)
{
    return flag ? "true" : "false";
}

int testAdd(int x, int y) {
    return x + y;
}

static jstring sayHello(JNIEnv *env, jobject) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

static jint testInt(JNIEnv *env, jobject obj, jint num) {
    LOGD("testInt called! num = %d", num);

    jclass clazz = env->GetObjectClass(obj);
    jfieldID fieldId = env->GetStaticFieldID(clazz, "number", "I");
    jint number = env->GetStaticIntField(clazz, fieldId);
    LOGD("get class fields! number = %d", number);

    return testAdd(num, number);
}

static jboolean testBoolean(JNIEnv *env, jobject, jboolean flag) {
    LOGD("testBoolean called! flag = %s", BoolToString(flag));
    return !flag;
}

// Java 是 unicode 编码，native 则是 utf-8 编码
static jstring testSting(JNIEnv *env, jobject, jstring test) {
    // 将 Java 中的 String 转换为 native 中的 const char*，本地自己又申请了一片内存
    const char* nativeString = env->GetStringUTFChars(test, 0);
    LOGD("testSting called! GetStringUTFChars = %s", nativeString);
    env->ReleaseStringUTFChars(test, nativeString);

    // 也可以使用GetStringUTFRegion，调用前分配一块非 const 内存
    int length = env->GetStringLength(test);
    char buf[length + 1];
    env->GetStringUTFRegion(test, 0, length, buf);
    LOGD("testSting called! GetStringUTFRegion = %s", buf);

    // 返回 jstring
    return env->NewStringUTF("Hello, Java!");
}

static jobjectArray testArray(JNIEnv *env, jobject, jobjectArray array) {
    jclass clazz = env->FindClass("com/demo/fridahook/NormalClass");
    jmethodID initId = env->GetMethodID(clazz, "<init>", "(Ljava/lang/String;)V");
    jmethodID getId = env->GetMethodID(clazz, "getContent", "()Ljava/lang/String;");

    jobject object = env->GetObjectArrayElement(array, 0);
    jstring content = (jstring)env->CallObjectMethod(object, getId);
    const char *newContent = env->GetStringUTFChars(content, 0);
    LOGD("testArray called! getContent = %s", newContent);
    env->ReleaseStringUTFChars(content, newContent);

    jstring nativeContent1 = env->NewStringUTF("native NormalClass1");
    jstring nativeContent2 = env->NewStringUTF("native NormalClass2");
    jstring nativeContent3 = env->NewStringUTF("native NormalClass3");
    jobject nativeObject1 = env->NewObject(clazz, initId, nativeContent1);
    jobject nativeObject2 = env->NewObject(clazz, initId, nativeContent2);
    jobject nativeObject3 = env->NewObject(clazz, initId, nativeContent3);
    jobjectArray nativeArray = env->NewObjectArray(3, clazz, 0);
    env->SetObjectArrayElement(nativeArray, 0, nativeObject1);
    env->SetObjectArrayElement(nativeArray, 1, nativeObject2);
    env->SetObjectArrayElement(nativeArray, 2, nativeObject3);
    return nativeArray;
}

static const char *className = "com/demo/fridahook/HookClass";

static JNINativeMethod jniNativeMethod[] = {
        {"helloFromNative", "()Ljava/lang/String;", (void*)sayHello},
        {"testNativeInt", "(I)I", (void*)testInt},
        {"testNativeBoolean", "(Z)Z", (void*)testBoolean},
        {"testNativeString", "(Ljava/lang/String;)Ljava/lang/String;", (void*)testSting},
        {"testNativeArray", "([Lcom/demo/fridahook/NormalClass;)[Lcom/demo/fridahook/NormalClass;", (void*)testArray}
};

static int registerNativeMethods(JNIEnv* env, const char* className,
                                 const JNINativeMethod* gMethods, int numMethods) {
    jclass clazz;

    clazz = (env)->FindClass(className);
    if (clazz == NULL) {
        return -1;
    }

    int result = 0;
    if ((env)->RegisterNatives(clazz, jniNativeMethod, numMethods) < 0) {
        result = -1;
    }

    (env)->DeleteLocalRef(clazz);
    return result;
}

jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env = NULL;
    jint ret = -1;

    if (vm->GetEnv((void**)&env, JNI_VERSION_1_4) != JNI_OK) {
        return ret;
    }

    registerNativeMethods(env, className, jniNativeMethod, sizeof(jniNativeMethod) / sizeof(JNINativeMethod));
    return JNI_VERSION_1_4;
}