
function log(message){
    console.log("*****[frida hook]***** : " + message);
}

log("this is a frida hook to check malware actions");

// check getting device info
function checkTelephonyManager(){
    var TelephonyManager = Java.use("android.telephony.TelephonyManager");
    // Device Info
    TelephonyManager.getDeviceSoftwareVersion.overload('int').implementation = function() {
        var ret = this.getDeviceSoftwareVersion(arguments[0]);
        log("TelephonyManager getDeviceSoftwareVersion() = " + ret);
        return ret;
    }
    TelephonyManager.getDeviceId.overload().implementation = function() {
        var ret = this.getDeviceId();
        log("TelephonyManager getDeviceId() = " + ret);
        return ret;
    }
    TelephonyManager.getDeviceId.overload('int').implementation = function() {
        var slotIndex = argument[0];
        var ret = this.getDeviceId(slotIndex);
        log("TelephonyManager getDeviceId(" + slotIndex + ") = " + ret);
        return ret;
    }
    TelephonyManager.getImei.overload('int').implementation = function() {
        var slotIndex = arguments[0];
        var ret = this.getImei(slotIndex);
        log("TelephonyManager getImei(" + slotIndex + ") = " + ret);
        return ret;
    }
    TelephonyManager.getMeid.overload('int').implementation = function() {
        var slotIndex = arguments[0];
        var ret = this.getMeid(slotIndex);
        log("TelephonyManager getMeid(" + slotIndex + ") = " + ret);
        return ret;
    }
    TelephonyManager.getNaiBySubscriberId.implementation = function() {
        var ret = this.getNaiBySubscriberId(arguments[0]);
        log("TelephonyManager getNaiBySubscriberId() = " + ret);
        return ret;
    }
    TelephonyManager.getCellLocation.implementation = function() {
        log("TelephonyManager getCellLocation()");
        return this.getCellLocation();
    }
    TelephonyManager.getNeighboringCellInfo.implementation = function() {
        log("TelephonyManager getNeighboringCellInfo()");
        return this.getNeighboringCellInfo();
    }
    TelephonyManager.getPhoneType.overload().implementation = function() {
        log("TelephonyManager getPhoneType()");
        return this.getPhoneType();
    }
    // Current Network
    TelephonyManager.getNetworkOperatorName.overload('int').implementation = function() {
        log("TelephonyManager getNetworkOperatorName()");
        return this.getNetworkOperatorName(arguments[0]);
    }
    TelephonyManager.getNetworkOperatorForPhone.implementation = function() {
        log("TelephonyManager getNetworkOperatorForPhone()");
        return this.getNetworkOperatorForPhone(arguments[0]);
    }
    TelephonyManager.getNetworkSpecifier.implementation = function() {
        log("TelephonyManager getNetworkSpecifier()");
        return this.getNetworkSpecifier();
    }
    TelephonyManager.getCarrierConfig.implementation = function() {
        log("TelephonyManager getCarrierConfig()");
        return this.getCarrierConfig();
    }
    TelephonyManager.isNetworkRoaming.overload('int').implementation = function() {
        log("TelephonyManager isNetworkRoaming()");
        return this.isNetworkRoaming(arguments[0]);
    }
    TelephonyManager.getNetworkCountryIsoForPhone.implementation = function() {
        log("TelephonyManager getNetworkCountryIsoForPhone()");
        return this.getNetworkCountryIsoForPhone(arguments[0]);
    }
    TelephonyManager.getNetworkType.overload().implementation = function() {
        var ret = this.getNetworkType();
        log("TelephonyManager getNetworkType() = " + ret);
        return ret;
    }
    TelephonyManager.getNetworkType.overload('int').implementation = function() {
        var ret = this.getNetworkType(arguments[0]);
        log("TelephonyManager getNetworkType() = " + ret);
        return ret;
    }
    TelephonyManager.getDataNetworkType.overload('int').implementation = function() {
        log("TelephonyManager getDataNetworkType()");
        return this.getDataNetworkType(arguments[0]);
    }
    TelephonyManager.getVoiceNetworkType.overload('int').implementation = function() {
        log("TelephonyManager getVoiceNetworkType()");
        return this.getVoiceNetworkType(arguments[0]);
    }
    // SIM Card
    TelephonyManager.hasIccCard.overload('int').implementation = function() {
        var ret = this.hasIccCard(arguments[0]);
        log("TelephonyManager hasIccCard() = " + ret);
        return ret;
    }
    TelephonyManager.getSimState.overload().implementation = function() {
        var ret = this.getSimState();
        log("TelephonyManager getSimState() = " + ret);
        return ret;
    }
    TelephonyManager.getSimState.overload('int').implementation = function() {
        var ret = this.getSimState(arguments[0]);
        log("TelephonyManager getSimState(" + arguments[0] + ") = " + ret);
        return ret;
    }
    TelephonyManager.getSimSerialNumber.overload().implementation = function() {
        var ret = this.getSimSerialNumber();
        log("TelephonyManager getSimSerialNumber() = " + ret);
        return ret;
    }
    // Subscriber Info
    TelephonyManager.getSubscriberId.overload('int').implementation = function() {
        var ret = this.getSubscriberId(arguments[0]);
        log("TelephonyManager getSubscriberId() = " + ret);
        return ret;
    }
    TelephonyManager.getLine1Number.overload().implementation = function() {
        var ret = this.getLine1Number();
        log("TelephonyManager getLine1Number() = " + ret);
        return ret;
    }
}

// check getting network info
function checkWifiManager(){
}

// check sending/getting sms
function checkSMSManager() {
    var SmsManager = Java.use("android.telephony.SmsManager");
    SmsManager.sendTextMessageInternal.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'android.app.PendingIntent', 'android.app.PendingIntent', 'boolean').implementation = function() {
        log("sent text message '" + arguments[2] + "' to '" + arguments[0] + "'");
        this.sendTextMessageInternal(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5]);
    }
    SmsManager.sendTextMessageInternal.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'android.app.PendingIntent', 'android.app.PendingIntent', 'boolean', 'int', 'boolean', 'int').implementation = function() {
        log("sent text message '" + arguments[2] + "' to '" + arguments[0] + "'");
        this.sendTextMessageInternal(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6], arguments[7], arguments[8]);
    }
    SmsManager.sendTextMessageWithSelfPermissions.implementation = function() {
        log("sent text message '" + arguments[2] + "' to '" + arguments[0] + "'");
        this.sendTextMessageWithSelfPermissions(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5]);
    }
    SmsManager.sendMultipartTextMessageInternal.overload('java.lang.String', 'java.lang.String', 'java.util.List', 'java.util.List', 'java.util.List', 'boolean').implementation = function() {
        log("sent text message '" + arguments[2].toString() + "' to '" + arguments[0] + "'");
        this.sendMultipartTextMessageInternal(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5]);
    }
    SmsManager.sendMultipartTextMessageInternal.overload('java.lang.String', 'java.lang.String', 'java.util.List', 'java.util.List', 'java.util.List', 'boolean', 'int', 'boolean', 'int').implementation = function() {
        log("sent text message '" + arguments[2].toString() + "' to '" + arguments[0] + "'");
        this.sendMultipartTextMessageInternal(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6], arguments[7], arguments[8]);
    }
    SmsManager.sendDataMessage.implementation = function() {
        log("sent text message '" + arguments[3].toString() + "' to '" + arguments[0] + "'");
        this.sendDataMessage(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5]);
    }
    SmsManager.sendDataMessageWithSelfPermissions.implementation = function() {
        log("sent text message '" + arguments[3].toString() + "' to '" + arguments[0] + "'");
        this.sendDataMessageWithSelfPermissions(arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5]);
    }
}

// check getting content provider data
function checkContentProvider() {
    var ContentResolver = Java.use("android.content.ContentResolver");
    // ContactsContract
    var ContactsContract = Java.use("android.provider.ContactsContract");
    var contact_authority = ContactsContract.class.getDeclaredField("AUTHORITY").get('java.lang.Object');
    // CalendarContract
    var CalendarContract = Java.use("android.provider.CalendarContract");
    var calendar_authority = CalendarContract.class.getDeclaredField("AUTHORITY").get('java.lang.Object');
    // BrowserContract
    var BrowserContract = Java.use("android.provider.BrowserContract");
    var browser_authority = BrowserContract.class.getDeclaredField("AUTHORITY").get('java.lang.Object');
    ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle', 'android.os.CancellationSignal').implementation = function() {
        log("ContentResolver.query() called! uri = " + arguments[0]);
        if (arguments[0].toString().indexOf(contact_authority) != -1) {
            log("Reading Contacts!");
        } else if (arguments[0].toString().indexOf(calendar_authority) != -1) {
            log("Reading Calendar!");
        } else if (arguments[0].toString().indexOf(browser_authority) != -1) {
            log("Reading Browser!");
        }
        return this.query(arguments[0], arguments[1], arguments[2], arguments[3]);
    }
}

Java.perform(function(){
    checkTelephonyManager();
    checkWifiManager();
    checkSMSManager();
    checkContentProvider();
});

log("test finished");

//    //ANDOID_ID hook
//    var Secure = Java.use("android.provider.Settings$Secure");
//    Secure.getString.implementation = function (p1,p2) {
//    	if(p2.indexOf("android_id")<0) return this.getString(p1,p2);
//    	console.log("[*]Called - get android_ID, param is:"+p2);
//    	var temp = this.getString(p1,p2);
//    	console.log("real Android_ID: "+temp);
//    	return "844de23bfcf93801";
//
//    }
//
//    //android的hidden API，需要通过反射调用
//    var SP = Java.use("android.os.SystemProperties");
//    SP.get.overload('java.lang.String').implementation = function (p1) {
//    	var tmp = this.get(p1);
//    	console.log("[*]"+p1+" : "+tmp);
//
//    	return tmp;
//    }
//    SP.get.overload('java.lang.String', 'java.lang.String').implementation = function (p1,p2) {
//    	var tmp = this.get(p1,p2)
//    	console.log("[*]"+p1+","+p2+" : "+tmp);
//    	return tmp;
//    }
//    // hook MAC
//    var wifi = Java.use("android.net.wifi.WifiInfo");
//    wifi.getMacAddress.implementation = function () {
//    	var tmp = this.getMacAddress();
//    	console.log("[*]real MAC: "+tmp);
//    	return tmp;
//    }