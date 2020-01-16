
function log(message){
    console.log("*****[frida hook]***** : " + message);
}

log("this is a frida hook to bypass SSL_Pinning");

function bypass_sslpinning(cert_path){
    log("Step 1. load our own certificate...");
    var FileInputStream = Java.use("java.io.FileInputStream");
    var BufferedInputStream = Java.use("java.io.BufferedInputStream");
    var bufferedInputStream = null;
    try {
        bufferedInputStream = BufferedInputStream.$new(FileInputStream.$new(cert_path));
    } catch (exception) {
        log("read '" + cert_path + "' error, catch exception = " + exception);
    }
    log("Step 2. generate the ca certificate...");
    var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
    var X509Certificate = Java.use("java.security.cert.X509Certificate");
    var certificate = CertificateFactory.getInstance("X.509").generateCertificate(bufferedInputStream);
    bufferedInputStream.close();
    log("Step 3. create keystore of the certificate...");
    var KeyStore = Java.use("java.security.KeyStore");
    var keystore = KeyStore.getInstance(KeyStore.getDefaultType());
    keystore.load(null, null);
    keystore.setCertificateEntry("ca", certificate);
    log("Step 4. create a TrustManager trusts the certificate...");
    var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
    var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(keystore);
    log("Step 5. hook the SSLContext init method...");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(){
        log("SSLContext init got hooked");
        this.init(arguments[0], tmf.getTrustManagers(), arguments[2]);
    }
}

Java.perform(function(){
    bypass_sslpinning("/data/local/tmp/JKS.pem");
});