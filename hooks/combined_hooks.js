/*
 * combined_hooks.js - Combined Crypto + Header Hooks for Frida Gadget
 * =============================================================================
 * This script is injected via frida-gadget and runs automatically when the
 * application starts. It combines all crypto and header interception.
 *
 * Output: /sdcard/Download/modify/key/<package>/
 *   - runtime_keys.txt    (secret keys, IVs, cipher operations)
 *   - runtime_headers.txt (HTTP headers, auth tokens, JWT)
 *
 * The app will pause on startup until the script is fully loaded.
 * =============================================================================
 */

"use strict";

var OUTPUT_DIR = "/sdcard/Download/modify/key";
var packageName = "";

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

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

function writeToFile(filePath, content) {
    try {
        var File = Java.use("java.io.File");
        var FileWriter = Java.use("java.io.FileWriter");
        var BufferedWriter = Java.use("java.io.BufferedWriter");

        var file = File.$new(filePath);
        var fw = FileWriter.$new(file, true);
        var bw = BufferedWriter.$new(fw);
        bw.write(content);
        bw.newLine();
        bw.flush();
        bw.close();
    } catch (e) {
        console.log("[!] File write error: " + e);
    }
}

function logCrypto(tag, data) {
    var entry = "[" + timestamp() + "] [" + tag + "] " + data;
    console.log(entry);
    writeToFile(OUTPUT_DIR + "/" + packageName + "/runtime_keys.txt", entry);
}

function logHeader(tag, data) {
    var entry = "[" + timestamp() + "] [" + tag + "] " + data;
    console.log(entry);
    writeToFile(OUTPUT_DIR + "/" + packageName + "/runtime_headers.txt", entry);
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
        return "(error)";
    }
}

function bytesToBase64(bytes) {
    if (bytes === null || bytes === undefined) return "(null)";
    try {
        var Base64 = Java.use("android.util.Base64");
        return Base64.encodeToString(bytes, 2);
    } catch (e) {
        return "(error)";
    }
}

function bytesToUtf8(bytes) {
    if (bytes === null || bytes === undefined) return "(null)";
    try {
        var Str = Java.use("java.lang.String");
        return Str.$new(bytes, "UTF-8");
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
        for (var i = 0; i < Math.min(stack.length, 10); i++) {
            trace.push("    " + stack[i].toString());
        }
        return trace.join("\n");
    } catch (e) {
        return "    (unavailable)";
    }
}

// ============================================================================
// CRYPTO HOOKS
// ============================================================================

function hookAllCrypto() {
    // SecretKeySpec
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algo) {
            logCrypto("SECRET_KEY", "Algorithm: " + algo +
                " | Key (hex): " + bytesToHex(key) +
                " | Key (base64): " + bytesToBase64(key) +
                " | Key (utf8): " + bytesToUtf8(key) +
                " | Length: " + key.length + "B");
            logCrypto("SECRET_KEY_STACK", "Call stack:\n" + getStackTrace());
            return this.$init(key, algo);
        };
        SecretKeySpec.$init.overload("[B", "int", "int", "java.lang.String").implementation = function (key, off, len, algo) {
            logCrypto("SECRET_KEY", "Algorithm: " + algo +
                " | Key (hex): " + bytesToHex(key) +
                " | Offset: " + off + " | Length: " + len + "B");
            return this.$init(key, off, len, algo);
        };
        console.log("[+] SecretKeySpec hooked");
    } catch (e) { console.log("[-] SecretKeySpec: " + e.message); }

    // IvParameterSpec
    try {
        var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
        IvParameterSpec.$init.overload("[B").implementation = function (iv) {
            logCrypto("IV_PARAMETER", "IV (hex): " + bytesToHex(iv) +
                " | IV (base64): " + bytesToBase64(iv) +
                " | IV (utf8): " + bytesToUtf8(iv) +
                " | Length: " + iv.length + "B");
            logCrypto("IV_PARAMETER_STACK", "Call stack:\n" + getStackTrace());
            return this.$init(iv);
        };
        IvParameterSpec.$init.overload("[B", "int", "int").implementation = function (iv, off, len) {
            logCrypto("IV_PARAMETER", "IV (hex): " + bytesToHex(iv) +
                " | Offset: " + off + " | Length: " + len + "B");
            return this.$init(iv, off, len);
        };
        console.log("[+] IvParameterSpec hooked");
    } catch (e) { console.log("[-] IvParameterSpec: " + e.message); }

    // GCMParameterSpec
    try {
        var GCMParameterSpec = Java.use("javax.crypto.spec.GCMParameterSpec");
        GCMParameterSpec.$init.overload("int", "[B").implementation = function (tagLen, iv) {
            logCrypto("GCM_PARAMETER", "Tag length: " + tagLen +
                " | Nonce (hex): " + bytesToHex(iv) +
                " | Nonce (base64): " + bytesToBase64(iv) +
                " | Length: " + iv.length + "B");
            return this.$init(tagLen, iv);
        };
        console.log("[+] GCMParameterSpec hooked");
    } catch (e) { console.log("[-] GCMParameterSpec: " + e.message); }

    // Cipher
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.getInstance.overload("java.lang.String").implementation = function (t) {
            logCrypto("CIPHER_INIT", "Transformation: " + t);
            return this.getInstance(t);
        };
        Cipher.getInstance.overload("java.lang.String", "java.lang.String").implementation = function (t, p) {
            logCrypto("CIPHER_INIT", "Transformation: " + t + " | Provider: " + p);
            return this.getInstance(t, p);
        };
        Cipher.init.overload("int", "java.security.Key").implementation = function (op, key) {
            var m = op === 1 ? "ENCRYPT" : op === 2 ? "DECRYPT" : "MODE_" + op;
            var kb = key.getEncoded();
            logCrypto("CIPHER_OP", "Mode: " + m +
                " | Algorithm: " + key.getAlgorithm() +
                " | Key (hex): " + bytesToHex(kb) +
                " | Key (base64): " + bytesToBase64(kb));
            logCrypto("CIPHER_OP_STACK", "Call stack:\n" + getStackTrace());
            return this.init(op, key);
        };
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec").implementation = function (op, key, params) {
            var m = op === 1 ? "ENCRYPT" : op === 2 ? "DECRYPT" : "MODE_" + op;
            var kb = key.getEncoded();
            var paramInfo = "";
            try {
                var ivSpec = Java.cast(params, Java.use("javax.crypto.spec.IvParameterSpec"));
                paramInfo = " | IV (hex): " + bytesToHex(ivSpec.getIV());
            } catch (e1) {
                try {
                    var gcm = Java.cast(params, Java.use("javax.crypto.spec.GCMParameterSpec"));
                    paramInfo = " | GCM-IV (hex): " + bytesToHex(gcm.getIV()) + " | TagLen: " + gcm.getTLen();
                } catch (e2) {
                    paramInfo = " | Params: " + params.getClass().getName();
                }
            }
            logCrypto("CIPHER_OP", "Mode: " + m +
                " | Algorithm: " + key.getAlgorithm() +
                " | Key (hex): " + bytesToHex(kb) + paramInfo);
            logCrypto("CIPHER_OP_STACK", "Call stack:\n" + getStackTrace());
            return this.init(op, key, params);
        };
        Cipher.doFinal.overload("[B").implementation = function (input) {
            var result = this.doFinal(input);
            logCrypto("CIPHER_DATA", "Algorithm: " + this.getAlgorithm() +
                " | Input (hex): " + bytesToHex(input) +
                " | Input (utf8): " + bytesToUtf8(input) +
                " | Output (hex): " + bytesToHex(result) +
                " | Output (utf8): " + bytesToUtf8(result));
            return result;
        };
        Cipher.doFinal.overload().implementation = function () {
            var result = this.doFinal();
            logCrypto("CIPHER_DATA", "Algorithm: " + this.getAlgorithm() +
                " | Output (hex): " + bytesToHex(result));
            return result;
        };
        console.log("[+] Cipher hooked");
    } catch (e) { console.log("[-] Cipher: " + e.message); }

    // MessageDigest
    try {
        var MD = Java.use("java.security.MessageDigest");
        MD.getInstance.overload("java.lang.String").implementation = function (algo) {
            logCrypto("HASH_INIT", "Algorithm: " + algo);
            return this.getInstance(algo);
        };
        MD.digest.overload("[B").implementation = function (input) {
            var r = this.digest(input);
            logCrypto("HASH_DATA", "Algorithm: " + this.getAlgorithm() +
                " | Input (utf8): " + bytesToUtf8(input) +
                " | Digest (hex): " + bytesToHex(r));
            return r;
        };
        MD.digest.overload().implementation = function () {
            var r = this.digest();
            logCrypto("HASH_DATA", "Algorithm: " + this.getAlgorithm() +
                " | Digest (hex): " + bytesToHex(r));
            return r;
        };
        console.log("[+] MessageDigest hooked");
    } catch (e) { console.log("[-] MessageDigest: " + e.message); }

    // Mac (HMAC)
    try {
        var Mac = Java.use("javax.crypto.Mac");
        Mac.getInstance.overload("java.lang.String").implementation = function (algo) {
            logCrypto("MAC_INIT", "Algorithm: " + algo);
            return this.getInstance(algo);
        };
        Mac.init.overload("java.security.Key").implementation = function (key) {
            var kb = key.getEncoded();
            logCrypto("MAC_KEY", "Algorithm: " + this.getAlgorithm() +
                " | Key (hex): " + bytesToHex(kb) +
                " | Key (base64): " + bytesToBase64(kb) +
                " | Key (utf8): " + bytesToUtf8(kb));
            logCrypto("MAC_KEY_STACK", "Call stack:\n" + getStackTrace());
            return this.init(key);
        };
        Mac.doFinal.overload("[B").implementation = function (input) {
            var r = this.doFinal(input);
            logCrypto("MAC_DATA", "Algorithm: " + this.getAlgorithm() +
                " | Input (utf8): " + bytesToUtf8(input) +
                " | MAC (hex): " + bytesToHex(r) +
                " | MAC (base64): " + bytesToBase64(r));
            return r;
        };
        Mac.doFinal.overload().implementation = function () {
            var r = this.doFinal();
            logCrypto("MAC_DATA", "Algorithm: " + this.getAlgorithm() +
                " | MAC (hex): " + bytesToHex(r));
            return r;
        };
        console.log("[+] Mac hooked");
    } catch (e) { console.log("[-] Mac: " + e.message); }

    // SecretKeyFactory (PBKDF2, etc.)
    try {
        var SKF = Java.use("javax.crypto.SecretKeyFactory");
        SKF.generateSecret.overload("java.security.spec.KeySpec").implementation = function (spec) {
            var r = this.generateSecret(spec);
            var enc = r.getEncoded();
            logCrypto("KEY_DERIVATION", "Algorithm: " + r.getAlgorithm() +
                " | Derived key (hex): " + bytesToHex(enc) +
                " | Derived key (base64): " + bytesToBase64(enc) +
                " | Length: " + (enc ? enc.length : 0) + "B");
            logCrypto("KEY_DERIVATION_STACK", "Call stack:\n" + getStackTrace());
            return r;
        };
        console.log("[+] SecretKeyFactory hooked");
    } catch (e) { console.log("[-] SecretKeyFactory: " + e.message); }

    // PBEKeySpec
    try {
        var PBE = Java.use("javax.crypto.spec.PBEKeySpec");
        PBE.$init.overload("[C", "[B", "int", "int").implementation = function (pw, salt, iter, keyLen) {
            var p = "(unreadable)";
            try { p = Java.use("java.lang.String").$new(pw); } catch (e) { /* */ }
            logCrypto("PBE_KEY", "Password: " + p +
                " | Salt (hex): " + bytesToHex(salt) +
                " | Iterations: " + iter +
                " | KeyLength: " + keyLen + " bits");
            logCrypto("PBE_KEY_STACK", "Call stack:\n" + getStackTrace());
            return this.$init(pw, salt, iter, keyLen);
        };
        console.log("[+] PBEKeySpec hooked");
    } catch (e) { console.log("[-] PBEKeySpec: " + e.message); }

    // KeyGenerator
    try {
        var KG = Java.use("javax.crypto.KeyGenerator");
        KG.generateKey.implementation = function () {
            var k = this.generateKey();
            var enc = k.getEncoded();
            logCrypto("KEY_GEN", "Algorithm: " + k.getAlgorithm() +
                " | Key (hex): " + bytesToHex(enc) +
                " | Key (base64): " + bytesToBase64(enc));
            return k;
        };
        console.log("[+] KeyGenerator hooked");
    } catch (e) { console.log("[-] KeyGenerator: " + e.message); }

    // KeyStore
    try {
        var KS = Java.use("java.security.KeyStore");
        KS.getKey.overload("java.lang.String", "[C").implementation = function (alias, pw) {
            var k = this.getKey(alias, pw);
            if (k !== null) {
                var enc = k.getEncoded();
                logCrypto("KEYSTORE", "Alias: " + alias +
                    " | Algorithm: " + k.getAlgorithm() +
                    " | Key (hex): " + (enc ? bytesToHex(enc) : "(not exportable)"));
            } else {
                logCrypto("KEYSTORE", "Alias: " + alias + " | Key: null");
            }
            return k;
        };
        console.log("[+] KeyStore hooked");
    } catch (e) { console.log("[-] KeyStore: " + e.message); }
}

// ============================================================================
// HEADER HOOKS
// ============================================================================

function hookAllHeaders() {
    // OkHttp3 Request.Builder
    try {
        var Builder = Java.use("okhttp3.Request$Builder");
        Builder.addHeader.implementation = function (n, v) {
            logHeader("OKHTTP_HEADER", "addHeader(\"" + n + "\", \"" + v + "\")");
            return this.addHeader(n, v);
        };
        Builder.header.implementation = function (n, v) {
            logHeader("OKHTTP_HEADER", "header(\"" + n + "\", \"" + v + "\")");
            return this.header(n, v);
        };
        console.log("[+] OkHttp3 headers hooked");
    } catch (e) { console.log("[-] OkHttp3 headers: " + e.message); }

    // OkHttp3 full request logging
    try {
        var RealCall = Java.use("okhttp3.internal.connection.RealCall");
        RealCall.execute.implementation = function () {
            var req = this.request();
            logHeader("OKHTTP_REQUEST", "Method: " + req.method() +
                " | URL: " + req.url().toString() +
                "\n    Headers:\n    " + req.headers().toString().replace(/\n/g, "\n    "));
            return this.execute();
        };
        console.log("[+] OkHttp3 requests hooked");
    } catch (e) {
        try {
            var RC = Java.use("okhttp3.RealCall");
            RC.execute.implementation = function () {
                var req = this.request();
                logHeader("OKHTTP_REQUEST", req.method() + " " + req.url().toString() +
                    "\n    Headers:\n    " + req.headers().toString().replace(/\n/g, "\n    "));
                return this.execute();
            };
            console.log("[+] OkHttp3 requests (alt) hooked");
        } catch (e2) { console.log("[-] OkHttp3 requests: " + e2.message); }
    }

    // HttpURLConnection
    try {
        var HC = Java.use("java.net.HttpURLConnection");
        HC.setRequestProperty.implementation = function (k, v) {
            logHeader("HTTP_HEADER", "setRequestProperty(\"" + k + "\", \"" + v + "\")");
            return this.setRequestProperty(k, v);
        };
        HC.addRequestProperty.implementation = function (k, v) {
            logHeader("HTTP_HEADER", "addRequestProperty(\"" + k + "\", \"" + v + "\")");
            return this.addRequestProperty(k, v);
        };
        console.log("[+] HttpURLConnection hooked");
    } catch (e) { console.log("[-] HttpURLConnection: " + e.message); }

    // WebView
    try {
        var WV = Java.use("android.webkit.WebView");
        WV.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function (url, headers) {
            var hInfo = "";
            if (headers !== null) {
                var it = headers.entrySet().iterator();
                while (it.hasNext()) {
                    var e = Java.cast(it.next(), Java.use("java.util.Map$Entry"));
                    hInfo += "\n    " + e.getKey() + ": " + e.getValue();
                }
            }
            logHeader("WEBVIEW", "URL: " + url + " | Headers:" + hInfo);
            return this.loadUrl(url, headers);
        };
        console.log("[+] WebView hooked");
    } catch (e) { console.log("[-] WebView: " + e.message); }

    // SharedPreferences (security-related keys)
    try {
        var SPE = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        SPE.putString.implementation = function (k, v) {
            var kw = ["key", "secret", "token", "auth", "api", "sign", "password",
                       "credential", "session", "jwt", "hmac", "bearer"];
            var kl = k.toLowerCase();
            for (var i = 0; i < kw.length; i++) {
                if (kl.indexOf(kw[i]) !== -1) {
                    logHeader("STORED_SECRET", "SharedPref key: \"" + k + "\" | value: \"" + v + "\"");
                    break;
                }
            }
            return this.putString(k, v);
        };
        console.log("[+] SharedPreferences hooked");
    } catch (e) { console.log("[-] SharedPreferences: " + e.message); }

    // Base64 JWT detection
    try {
        var B64 = Java.use("android.util.Base64");
        B64.encodeToString.overload("[B", "int").implementation = function (input, flags) {
            var r = this.encodeToString(input, flags);
            var s = "";
            try { s = Java.use("java.lang.String").$new(input, "UTF-8"); } catch (e) { /* */ }
            if (s.indexOf('"alg"') !== -1 || s.indexOf('"typ"') !== -1 ||
                s.indexOf('"iss"') !== -1 || s.indexOf('"exp"') !== -1) {
                logHeader("JWT_TOKEN", "JWT component: " + s + "\n    Encoded: " + r);
                logHeader("JWT_TOKEN_STACK", "Call stack:\n" + getStackTrace());
            }
            return r;
        };
        console.log("[+] JWT detection hooked");
    } catch (e) { console.log("[-] JWT detection: " + e.message); }
}

// ============================================================================
// MAIN
// ============================================================================

Java.perform(function () {
    console.log("================================================================");
    console.log("  Combined Hooks - Auto Runtime Extractor (Gadget Mode)");
    console.log("================================================================");

    packageName = getPackageName();
    console.log("[*] Package: " + packageName);
    console.log("[*] Crypto output: " + OUTPUT_DIR + "/" + packageName + "/runtime_keys.txt");
    console.log("[*] Header output: " + OUTPUT_DIR + "/" + packageName + "/runtime_headers.txt");

    ensureOutputDir();

    // Write report headers
    var hdr = "================================================================================\n" +
              "Runtime Extraction Report (Auto-Hook via Gadget)\n" +
              "Package: " + packageName + "\n" +
              "Date: " + timestamp() + "\n" +
              "================================================================================\n";
    writeToFile(OUTPUT_DIR + "/" + packageName + "/runtime_keys.txt", hdr);
    writeToFile(OUTPUT_DIR + "/" + packageName + "/runtime_headers.txt", hdr);

    hookAllCrypto();
    hookAllHeaders();

    console.log("================================================================");
    console.log("[+] All hooks installed - monitoring crypto & header operations");
    console.log("================================================================");
});
