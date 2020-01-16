# -*- coding: utf-8 -*-
# @Time    : 2019/12/31 6:03 下午
# @Author  : nana
# @FileName: demo.py
# @Software: PyCharm


import frida
import sys
import subprocess


def exe(cmdline):
    """
    使用非阻塞式subprocess模块，返回管道，可以指定输出位置
    :param cmdline:
    :return:
    """
    output, errors = subprocess.Popen(cmdline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()


def get_frida_server():
    url = "https://github.com/frida/frida/releases/download/12.8.1/frida-server-12.8.1-android-arm64.xz"
    exe("curl -O " + url)


# 对应命令 frida-ls-devices
def get_device():
    local_device = frida.get_local_device()
    usb_device = frida.get_usb_device()
    remote_device = frida.get_remote_device()
    return remote_device


# 打印所有进程
def get_process(device):
    processes = device.enumerate_processes()
    for process in processes:
        # print(process)
        pass
    return processes


# 打印所有应用
def get_applications(device):
    applications = device.enumerate_applications()
    for application in applications:
        # print(application)
        pass
    return applications


# 获取并打印顶层应用进程
def get_front_application(device):
    front_app = device.get_frontmost_application()
    print(front_app)
    return front_app


def get_pkg_name(device):
    return get_front_application(device).identifier


def get_app_name(device):
    return get_front_application(device).name


def get_pid(device):
    return get_front_application(device).pid


def on_message(message, data):
    print(message)


src = """
function toast(message){
    var curApplication = Java.use("android.app.ActivityThread").currentApplication();
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
        methods: {
            run: function(){
                send("run in ToastRunnable");
                Toast.makeText(context, Java.cast(String.$new(message), CharSequence), 0).show();
            }
        }
    });
    Runnable.$dispose;
    Toast.$dispose;
    CharSequence.$dispose;
    String.$dispose;
    Java.choose(activity.name.value, {
        onMatch: function(instance) {
            instance.runOnUiThread(ToastRunnable.$new());
        },
        onComplete: function() {}
    });
}

Java.perform(function(){
    toast("lalala");
});
"""

device = get_device()
package_name = get_pkg_name(device)
session = device.attach(package_name)
script = session.create_script(src)
script.on('message', on_message)
script.load()
sys.stdin.read()
