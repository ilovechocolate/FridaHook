# -*- coding: utf-8 -*-
# @Time    : 2020/1/7 4:47 下午
# @Author  : nana
# @FileName: hook.py
# @Software: PyCharm

import frida
import sys


def on_message(message, data):
    if message['type'] == 'send':
        print("*****[frida hook]***** : {0}".format(message['payload']))
    else:
        print("*****[frida hook]***** : " + str(message))


def get_javascript(filepath):
    code = ''
    with open(filepath, 'r') as file:
        code = code + file.read()
    return code


package_name = "com.demo.fridahook"
javascript_file = "./hookNative.js"
device = frida.get_remote_device()
# pid = device.spawn([package_name])
session = device.attach(package_name)
# device.resume(pid)

# 1、可以通过命令行直接运行脚本
# frida -U/-R -f <package_name/pid> [--no-pause] -l <javascript_file>
# 2、也可以通过 python 脚本加载执行
# 2.1、直接写入代码
# javascript = """

# <javascript code>
# """
# 2.2、从文件中加载 javascript 脚本代码
javascript = get_javascript(javascript_file)
script = session.create_script(javascript)
script.on('message', on_message)
script.load()
sys.stdin.read()
