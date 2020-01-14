# FridaHook

provide frida hook demo and javascript of both Java and native hook

$ tree -L 1
.
├── FridaHookDemo	# this is a android studio project providing hook demo
├── FridaTools		# this is a python/javascript frida hook tool project
└── README.md


FridaTools
├── frida-server-12.8.1-android-arm64 	# frida-server
├── hook.py 			# python script to connect device, attach process and load scripts
├── hookJava.js 		# a Java hook javascript demo
├── hookNative.js 		# a Native hook javascript demo
├── hook_art.js 		# provide some function for handle libart.so
├── hookwrapper.js 		# a hook wrapper providing common functions
├── libart.so 			# the libart.so file
├── libnative-lib.so 	# the libnative-lib.so file from `FridaHookDemo`
├── testJava.js 		# a Java hook javascript demo based on hookwrapper.js
└── testNative.js 		# a Native hook javascript demo based on hookwrapper.js

You can run `hookJava.js` and `hookNative.js` by `hook.py`, or simple by commandline.
But you can only run `testJava.js` and `testNative.js` by `hook.py` and remember load `hookwrapper.js` forward.