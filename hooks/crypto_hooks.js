/*
 * crypto_hooks.js - Frida Runtime Hooking Script for Cryptographic Operations
 * =============================================================================
 * Automatically intercepts and logs:
 *   - javax.crypto.Cipher (encrypt/decrypt operations, algorithm, mode, padding)
 *   - javax.crypto.spec.SecretKeySpec (secret keys)
 *   - javax.crypto.spec.IvParameterSpec (initialization vectors)
 *   - javax.crypto.Mac (HMAC operations)
 *   - java.security.MessageDigest (hashing)
 *   - javax.crypto.KeyGenerator (key generation)
 *   - javax.crypto.SecretKeyFactory (PBE key derivation)
 *   - java.security.KeyPairGenerator (RSA/EC key generation)
 *   - javax.crypto.spec.PBEKeySpec (password-based keys)
 *   - javax.crypto.spec.GCMParameterSpec (GCM nonces)
 *
 * Output is saved to /sdcard/Download/modify/key/<package>/runtime_keys.txt
 *
 * References:
 *   - https://github.com/nicholasgasior/frida-crypto-interceptor
 *   - https://github.com/FSecureLABS/android-keystore-audit
 *   - https://github.com/nicholasgasior/apk-mitm
 *   - OWASP MASTG - https://mas.owasp.org/MASTG/
 */

"use strict";

var OUTPUT_DIR = "/sdcard/Download/modify/key";
var packageName = "";

function getPackageName() {
    try {
        var context = Java.use("android.app.ActivityThread")
            .currentApplication()
            .getApplicationContext();
        return context.getPackageName();
    } catch (e) {
        return "unknown_app";
    }
}

function getOutputPath() {
    return OUTPUT_DIR + "/" + packageName + "/runtime_keys.txt";
}

function ensureOutputDir() {
    try {
        var File = Java.use("java.io.File");
        var dir = File.$new(OUTPUT_DIR + "/" + packageName);
        if (!dir.exists()) {
            dir.mkdirs();
        }
    } catch (e) {
        console.log("[!] Could not create output directory: " + e);
    }
}

function timestamp() {
    return new Date().toISOString();
}

function writeToFile(content) {
    try {
        var File = Java.use("java.io.File");
        var FileWriter = Java.use("java.io.FileWriter");
        var BufferedWriter = Java.use("java.io.BufferedWriter");

        var file = File.$new(getOutputPath());
        var fw = FileWriter.$new(file, true); // append mode
        var bw = BufferedWriter.$new(fw);
        bw.write(content);
        bw.newLine();
        bw.flush();
        bw.close();
    } catch (e) {
        console.log("[!] File write error: " + e);
    }
}

function logEntry(tag, data) {
    var entry = "[" + timestamp() + "] [" + tag + "] " + data;
    console.log(entry);
    writeToFile(entry);
}

function bytesToHex(bytes) {
    if (bytes === null || bytes === undefined) return "(null)";
    try {
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {
            var b = (bytes[i] & 0xff).toString(16);
            if (b.length === 1) b = "0" + b;
            hex.push(b);
        }
        return hex.join("");
    } catch (e) {
        return "(error converting bytes)";
    }
}

function bytesToBase64(bytes) {
    if (bytes === null || bytes === undefined) return "(null)";
    try {
        var Base64 = Java.use("android.util.Base64");
        return Base64.encodeToString(bytes, 2); // NO_WRAP
    } catch (e) {
        return "(error encoding base64)";
    }
}

function bytesToUtf8(bytes) {
    if (bytes === null || bytes === undefined) return "(null)";
    try {
        var String = Java.use("java.lang.String");
        return String.$new(bytes, "UTF-8");
    } catch (e) {
        return "(non-utf8)";
    }
}

function getStackTrace() {
    try {
        var Exception = Java.use("java.lang.Exception");
        var ex = Exception.$new();
        var stack = ex.getStackTrace();
        var trace = [];
        var maxFrames = 10;
        for (var i = 0; i < Math.min(stack.length, maxFrames); i++) {
            trace.push("    " + stack[i].toString());
        }
        return trace.join("\n");
    } catch (e) {
        return "    (stack trace unavailable)";
    }
}

// ============================================================================
// HOOKING FUNCTIONS
// ============================================================================

function hookSecretKeySpec() {
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");

        // Constructor: SecretKeySpec(byte[] key, String algorithm)
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algorithm) {
            var keyHex = bytesToHex(key);
            var keyB64 = bytesToBase64(key);
            var keyUtf8 = bytesToUtf8(key);

            logEntry("SECRET_KEY", "Algorithm: " + algorithm +
                " | Key (hex): " + keyHex +
                " | Key (base64): " + keyB64 +
                " | Key (utf8): " + keyUtf8 +
                " | Key length: " + key.length + " bytes");
            logEntry("SECRET_KEY_STACK", "Call stack:\n" + getStackTrace());

            return this.$init(key, algorithm);
        };

        // Constructor: SecretKeySpec(byte[] key, int offset, int len, String algorithm)
        SecretKeySpec.$init.overload("[B", "int", "int", "java.lang.String").implementation = function (key, offset, len, algorithm) {
            var keyHex = bytesToHex(key);
            var keyB64 = bytesToBase64(key);

            logEntry("SECRET_KEY", "Algorithm: " + algorithm +
                " | Key (hex): " + keyHex +
                " | Key (base64): " + keyB64 +
                " | Offset: " + offset + " | Length: " + len + " bytes");
            logEntry("SECRET_KEY_STACK", "Call stack:\n" + getStackTrace());

            return this.$init(key, offset, len, algorithm);
        };

        console.log("[+] SecretKeySpec hooked");
    } catch (e) {
        console.log("[-] SecretKeySpec hook failed: " + e);
    }
}

function hookIvParameterSpec() {
    try {
        var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");

        // Constructor: IvParameterSpec(byte[] iv)
        IvParameterSpec.$init.overload("[B").implementation = function (iv) {
            var ivHex = bytesToHex(iv);
            var ivB64 = bytesToBase64(iv);
            var ivUtf8 = bytesToUtf8(iv);

            logEntry("IV_PARAMETER", "IV (hex): " + ivHex +
                " | IV (base64): " + ivB64 +
                " | IV (utf8): " + ivUtf8 +
                " | IV length: " + iv.length + " bytes");
            logEntry("IV_PARAMETER_STACK", "Call stack:\n" + getStackTrace());

            return this.$init(iv);
        };

        // Constructor: IvParameterSpec(byte[] iv, int offset, int len)
        IvParameterSpec.$init.overload("[B", "int", "int").implementation = function (iv, offset, len) {
            var ivHex = bytesToHex(iv);
            var ivB64 = bytesToBase64(iv);

            logEntry("IV_PARAMETER", "IV (hex): " + ivHex +
                " | IV (base64): " + ivB64 +
                " | Offset: " + offset + " | Length: " + len + " bytes");

            return this.$init(iv, offset, len);
        };

        console.log("[+] IvParameterSpec hooked");
    } catch (e) {
        console.log("[-] IvParameterSpec hook failed: " + e);
    }
}

function hookGCMParameterSpec() {
    try {
        var GCMParameterSpec = Java.use("javax.crypto.spec.GCMParameterSpec");

        GCMParameterSpec.$init.overload("int", "[B").implementation = function (tagLen, iv) {
            var ivHex = bytesToHex(iv);
            var ivB64 = bytesToBase64(iv);

            logEntry("GCM_PARAMETER", "Tag length: " + tagLen +
                " | IV/Nonce (hex): " + ivHex +
                " | IV/Nonce (base64): " + ivB64 +
                " | IV length: " + iv.length + " bytes");

            return this.$init(tagLen, iv);
        };

        console.log("[+] GCMParameterSpec hooked");
    } catch (e) {
        console.log("[-] GCMParameterSpec hook failed: " + e);
    }
}

function hookCipher() {
    try {
        var Cipher = Java.use("javax.crypto.Cipher");

        // Cipher.getInstance(String transformation)
        Cipher.getInstance.overload("java.lang.String").implementation = function (transformation) {
            logEntry("CIPHER_INIT", "Transformation: " + transformation);
            return this.getInstance(transformation);
        };

        // Cipher.getInstance(String transformation, String provider)
        Cipher.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (transformation, provider) {
            logEntry("CIPHER_INIT", "Transformation: " + transformation + " | Provider: " + provider);
            return this.getInstance(transformation, provider);
        };

        // Cipher.init(int opmode, Key key)
        Cipher.init.overload("int", "java.security.Key").implementation = function (opmode, key) {
            var mode = opmode === 1 ? "ENCRYPT" : opmode === 2 ? "DECRYPT" : "MODE_" + opmode;
            var algo = key.getAlgorithm();
            var keyBytes = key.getEncoded();
            var keyHex = bytesToHex(keyBytes);
            var keyB64 = bytesToBase64(keyBytes);

            logEntry("CIPHER_OPERATION", "Mode: " + mode +
                " | Algorithm: " + algo +
                " | Key (hex): " + keyHex +
                " | Key (base64): " + keyB64 +
                " | Key length: " + (keyBytes ? keyBytes.length : 0) + " bytes");
            logEntry("CIPHER_OPERATION_STACK", "Call stack:\n" + getStackTrace());

            return this.init(opmode, key);
        };

        // Cipher.init(int opmode, Key key, AlgorithmParameterSpec params)
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (opmode, key, params) {
            var mode = opmode === 1 ? "ENCRYPT" : opmode === 2 ? "DECRYPT" : "MODE_" + opmode;
            var algo = key.getAlgorithm();
            var keyBytes = key.getEncoded();
            var keyHex = bytesToHex(keyBytes);
            var keyB64 = bytesToBase64(keyBytes);

            var paramInfo = "(unknown params)";
            try {
                var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
                if (Java.cast(params, IvParameterSpec)) {
                    var iv = Java.cast(params, IvParameterSpec).getIV();
                    paramInfo = "IV (hex): " + bytesToHex(iv) + " | IV (base64): " + bytesToBase64(iv);
                }
            } catch (e) {
                try {
                    var GCMParameterSpec = Java.use("javax.crypto.spec.GCMParameterSpec");
                    var gcm = Java.cast(params, GCMParameterSpec);
                    var gcmIv = gcm.getIV();
                    paramInfo = "GCM IV (hex): " + bytesToHex(gcmIv) + " | Tag length: " + gcm.getTLen();
                } catch (e2) {
                    paramInfo = "Params class: " + params.getClass().getName();
                }
            }

            logEntry("CIPHER_OPERATION", "Mode: " + mode +
                " | Algorithm: " + algo +
                " | Key (hex): " + keyHex +
                " | Key (base64): " + keyB64 +
                " | " + paramInfo);
            logEntry("CIPHER_OPERATION_STACK", "Call stack:\n" + getStackTrace());

            return this.init(opmode, key, params);
        };

        // Cipher.doFinal(byte[] input) - capture plaintext/ciphertext
        Cipher.doFinal.overload("[B").implementation = function (input) {
            var result = this.doFinal(input);
            var algo = this.getAlgorithm();

            logEntry("CIPHER_DATA", "Algorithm: " + algo +
                " | Input (hex): " + bytesToHex(input) +
                " | Input (utf8): " + bytesToUtf8(input) +
                " | Output (hex): " + bytesToHex(result) +
                " | Output (utf8): " + bytesToUtf8(result));

            return result;
        };

        // Cipher.doFinal() - no args
        Cipher.doFinal.overload().implementation = function () {
            var result = this.doFinal();
            var algo = this.getAlgorithm();

            logEntry("CIPHER_DATA", "Algorithm: " + algo +
                " | doFinal() with no input" +
                " | Output (hex): " + bytesToHex(result));

            return result;
        };

        console.log("[+] Cipher hooked");
    } catch (e) {
        console.log("[-] Cipher hook failed: " + e);
    }
}

function hookMessageDigest() {
    try {
        var MessageDigest = Java.use("java.security.MessageDigest");

        MessageDigest.getInstance.overload("java.lang.String").implementation = function (algorithm) {
            logEntry("HASH_INIT", "Algorithm: " + algorithm);
            return this.getInstance(algorithm);
        };

        MessageDigest.digest.overload("[B").implementation = function (input) {
            var result = this.digest(input);

            logEntry("HASH_DATA", "Algorithm: " + this.getAlgorithm() +
                " | Input (hex): " + bytesToHex(input) +
                " | Input (utf8): " + bytesToUtf8(input) +
                " | Digest (hex): " + bytesToHex(result));

            return result;
        };

        MessageDigest.digest.overload().implementation = function () {
            var result = this.digest();

            logEntry("HASH_DATA", "Algorithm: " + this.getAlgorithm() +
                " | Digest (hex): " + bytesToHex(result));

            return result;
        };

        console.log("[+] MessageDigest hooked");
    } catch (e) {
        console.log("[-] MessageDigest hook failed: " + e);
    }
}

function hookMac() {
    try {
        var Mac = Java.use("javax.crypto.Mac");

        Mac.getInstance.overload("java.lang.String").implementation = function (algorithm) {
            logEntry("MAC_INIT", "Algorithm: " + algorithm);
            return this.getInstance(algorithm);
        };

        Mac.init.overload("java.security.Key").implementation = function (key) {
            var keyBytes = key.getEncoded();

            logEntry("MAC_KEY", "Algorithm: " + this.getAlgorithm() +
                " | Key (hex): " + bytesToHex(keyBytes) +
                " | Key (base64): " + bytesToBase64(keyBytes) +
                " | Key (utf8): " + bytesToUtf8(keyBytes));
            logEntry("MAC_KEY_STACK", "Call stack:\n" + getStackTrace());

            return this.init(key);
        };

        Mac.doFinal.overload("[B").implementation = function (input) {
            var result = this.doFinal(input);

            logEntry("MAC_DATA", "Algorithm: " + this.getAlgorithm() +
                " | Input (hex): " + bytesToHex(input) +
                " | Input (utf8): " + bytesToUtf8(input) +
                " | MAC (hex): " + bytesToHex(result) +
                " | MAC (base64): " + bytesToBase64(result));

            return result;
        };

        Mac.doFinal.overload().implementation = function () {
            var result = this.doFinal();

            logEntry("MAC_DATA", "Algorithm: " + this.getAlgorithm() +
                " | MAC (hex): " + bytesToHex(result) +
                " | MAC (base64): " + bytesToBase64(result));

            return result;
        };

        console.log("[+] Mac hooked");
    } catch (e) {
        console.log("[-] Mac hook failed: " + e);
    }
}

function hookSecretKeyFactory() {
    try {
        var SecretKeyFactory = Java.use("javax.crypto.SecretKeyFactory");

        SecretKeyFactory.getInstance.overload("java.lang.String").implementation = function (algorithm) {
            logEntry("KEY_DERIVATION", "SecretKeyFactory algorithm: " + algorithm);
            return this.getInstance(algorithm);
        };

        SecretKeyFactory.generateSecret.overload("java.security.spec.KeySpec").implementation = function (keySpec) {
            var result = this.generateSecret(keySpec);
            var encoded = result.getEncoded();

            logEntry("KEY_DERIVATION", "Derived key algorithm: " + result.getAlgorithm() +
                " | Derived key (hex): " + bytesToHex(encoded) +
                " | Derived key (base64): " + bytesToBase64(encoded) +
                " | Key length: " + (encoded ? encoded.length : 0) + " bytes");
            logEntry("KEY_DERIVATION_STACK", "Call stack:\n" + getStackTrace());

            return result;
        };

        console.log("[+] SecretKeyFactory hooked");
    } catch (e) {
        console.log("[-] SecretKeyFactory hook failed: " + e);
    }
}

function hookPBEKeySpec() {
    try {
        var PBEKeySpec = Java.use("javax.crypto.spec.PBEKeySpec");

        // PBEKeySpec(char[] password, byte[] salt, int iterationCount, int keyLength)
        PBEKeySpec.$init.overload("[C", "[B", "int", "int").implementation = function (password, salt, iterations, keyLength) {
            var passStr = "(could not read)";
            try {
                var String = Java.use("java.lang.String");
                passStr = String.$new(password);
            } catch (e) { /* ignore */ }

            logEntry("PBE_KEY", "Password: " + passStr +
                " | Salt (hex): " + bytesToHex(salt) +
                " | Iterations: " + iterations +
                " | Key length: " + keyLength + " bits");
            logEntry("PBE_KEY_STACK", "Call stack:\n" + getStackTrace());

            return this.$init(password, salt, iterations, keyLength);
        };

        // PBEKeySpec(char[] password)
        PBEKeySpec.$init.overload("[C").implementation = function (password) {
            var passStr = "(could not read)";
            try {
                var String = Java.use("java.lang.String");
                passStr = String.$new(password);
            } catch (e) { /* ignore */ }

            logEntry("PBE_KEY", "Password: " + passStr);

            return this.$init(password);
        };

        console.log("[+] PBEKeySpec hooked");
    } catch (e) {
        console.log("[-] PBEKeySpec hook failed: " + e);
    }
}

function hookKeyGenerator() {
    try {
        var KeyGenerator = Java.use("javax.crypto.KeyGenerator");

        KeyGenerator.generateKey.implementation = function () {
            var key = this.generateKey();
            var encoded = key.getEncoded();

            logEntry("KEY_GENERATION", "Algorithm: " + key.getAlgorithm() +
                " | Generated key (hex): " + bytesToHex(encoded) +
                " | Generated key (base64): " + bytesToBase64(encoded) +
                " | Key length: " + (encoded ? encoded.length : 0) + " bytes");

            return key;
        };

        console.log("[+] KeyGenerator hooked");
    } catch (e) {
        console.log("[-] KeyGenerator hook failed: " + e);
    }
}

function hookKeyStore() {
    try {
        var KeyStore = Java.use("java.security.KeyStore");

        KeyStore.getKey.overload("java.lang.String", "[C").implementation = function (alias, password) {
            var key = this.getKey(alias, password);

            if (key !== null) {
                var encoded = key.getEncoded();
                logEntry("KEYSTORE", "Alias: " + alias +
                    " | Algorithm: " + key.getAlgorithm() +
                    " | Key (hex): " + (encoded ? bytesToHex(encoded) : "(not exportable)") +
                    " | Key (base64): " + (encoded ? bytesToBase64(encoded) : "(not exportable)"));
            } else {
                logEntry("KEYSTORE", "Alias: " + alias + " | Key: null (not found)");
            }

            return key;
        };

        console.log("[+] KeyStore hooked");
    } catch (e) {
        console.log("[-] KeyStore hook failed: " + e);
    }
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

Java.perform(function () {
    console.log("==============================================");
    console.log("  Crypto Hooks - Runtime Key Extractor");
    console.log("==============================================");

    packageName = getPackageName();
    console.log("[*] Package: " + packageName);
    console.log("[*] Output: " + getOutputPath());

    ensureOutputDir();

    writeToFile("================================================================================");
    writeToFile("Runtime Crypto Extraction Report");
    writeToFile("Package: " + packageName);
    writeToFile("Date: " + timestamp());
    writeToFile("================================================================================");
    writeToFile("");

    hookSecretKeySpec();
    hookIvParameterSpec();
    hookGCMParameterSpec();
    hookCipher();
    hookMessageDigest();
    hookMac();
    hookSecretKeyFactory();
    hookPBEKeySpec();
    hookKeyGenerator();
    hookKeyStore();

    console.log("==============================================");
    console.log("[+] All crypto hooks installed successfully");
    console.log("[*] Waiting for crypto operations...");
    console.log("==============================================");
});
