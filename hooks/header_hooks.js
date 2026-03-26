/*
 * header_hooks.js - Frida Runtime Hooking Script for HTTP Header Interception
 * =============================================================================
 * Automatically intercepts and logs:
 *   - OkHttp3 Request.Builder header construction
 *   - OkHttp3 Interceptor chains (auth headers, signatures)
 *   - Retrofit @Header annotations
 *   - HttpURLConnection headers
 *   - WebView request headers
 *   - Custom header signing/HMAC construction
 *
 * Captures headers that use secret keys for authentication tokens,
 * API signatures, HMAC-based authorization, and JWT construction.
 *
 * Output is saved to /sdcard/Download/modify/key/<package>/runtime_headers.txt
 *
 * References:
 *   - https://github.com/nicholasgasior/frida-crypto-interceptor
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
    return OUTPUT_DIR + "/" + packageName + "/runtime_headers.txt";
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

function logEntry(tag, data) {
    var entry = "[" + timestamp() + "] [" + tag + "] " + data;
    console.log(entry);
    writeToFile(entry);
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
// OkHttp3 Request.Builder Header Hooking
// ============================================================================

function hookOkHttpRequestBuilder() {
    try {
        var Builder = Java.use("okhttp3.Request$Builder");

        // addHeader(String name, String value)
        Builder.addHeader.implementation = function (name, value) {
            logEntry("OKHTTP_HEADER", "addHeader(\"" + name + "\", \"" + value + "\")");
            return this.addHeader(name, value);
        };

        // header(String name, String value)
        Builder.header.implementation = function (name, value) {
            logEntry("OKHTTP_HEADER", "header(\"" + name + "\", \"" + value + "\")");
            return this.header(name, value);
        };

        console.log("[+] OkHttp3 Request.Builder hooked");
    } catch (e) {
        console.log("[-] OkHttp3 Request.Builder not found (may not use OkHttp): " + e.message);
    }
}

// ============================================================================
// OkHttp3 Interceptor Chain - Capture Full Requests
// ============================================================================

function hookOkHttpInterceptor() {
    try {
        var RealCall = Java.use("okhttp3.internal.connection.RealCall");
        // Hook execute() to see final requests
        RealCall.execute.implementation = function () {
            var request = this.request();
            var url = request.url().toString();
            var method = request.method();
            var headers = request.headers();
            var headerStr = headers.toString();

            logEntry("OKHTTP_REQUEST", "Method: " + method +
                " | URL: " + url +
                "\n    Headers:\n    " + headerStr.replace(/\n/g, "\n    "));
            logEntry("OKHTTP_REQUEST_STACK", "Call stack:\n" + getStackTrace());

            return this.execute();
        };

        console.log("[+] OkHttp3 RealCall.execute hooked");
    } catch (e) {
        console.log("[-] OkHttp3 RealCall not found: " + e.message);

        // Try older OkHttp versions
        try {
            var Call = Java.use("okhttp3.RealCall");
            Call.execute.implementation = function () {
                var request = this.request();
                var url = request.url().toString();
                var method = request.method();
                var headers = request.headers();

                logEntry("OKHTTP_REQUEST", "Method: " + method +
                    " | URL: " + url +
                    "\n    Headers: " + headers.toString().replace(/\n/g, "\n    "));

                return this.execute();
            };
            console.log("[+] OkHttp3 RealCall (alt) hooked");
        } catch (e2) {
            console.log("[-] OkHttp3 RealCall (alt) not found: " + e2.message);
        }
    }
}

// ============================================================================
// HttpURLConnection Header Hooking
// ============================================================================

function hookHttpURLConnection() {
    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");

        HttpURLConnection.setRequestProperty.implementation = function (key, value) {
            logEntry("HTTP_HEADER", "setRequestProperty(\"" + key + "\", \"" + value + "\")");
            return this.setRequestProperty(key, value);
        };

        HttpURLConnection.addRequestProperty.implementation = function (key, value) {
            logEntry("HTTP_HEADER", "addRequestProperty(\"" + key + "\", \"" + value + "\")");
            return this.addRequestProperty(key, value);
        };

        console.log("[+] HttpURLConnection hooked");
    } catch (e) {
        console.log("[-] HttpURLConnection hook failed: " + e);
    }

    // Also hook the HTTPS variant
    try {
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");

        HttpsURLConnection.setRequestProperty.implementation = function (key, value) {
            logEntry("HTTPS_HEADER", "setRequestProperty(\"" + key + "\", \"" + value + "\")");
            return this.setRequestProperty(key, value);
        };

        console.log("[+] HttpsURLConnection hooked");
    } catch (e) {
        console.log("[-] HttpsURLConnection hook failed: " + e);
    }
}

// ============================================================================
// WebView Header Hooking
// ============================================================================

function hookWebView() {
    try {
        var WebView = Java.use("android.webkit.WebView");

        // loadUrl(String url, Map<String, String> additionalHttpHeaders)
        WebView.loadUrl.overload("java.lang.String", "java.util.Map").implementation = function (url, headers) {
            var headerInfo = "";
            if (headers !== null) {
                var entrySet = headers.entrySet();
                var iterator = entrySet.iterator();
                while (iterator.hasNext()) {
                    var entry = Java.cast(iterator.next(), Java.use("java.util.Map$Entry"));
                    headerInfo += "\n    " + entry.getKey() + ": " + entry.getValue();
                }
            }
            logEntry("WEBVIEW_HEADER", "URL: " + url + " | Headers:" + headerInfo);
            return this.loadUrl(url, headers);
        };

        console.log("[+] WebView hooked");
    } catch (e) {
        console.log("[-] WebView hook failed: " + e);
    }
}

// ============================================================================
// JWT / Token Construction Detection
// ============================================================================

function hookBase64ForTokens() {
    try {
        var Base64 = Java.use("android.util.Base64");

        Base64.encodeToString.overload("[B", "int").implementation = function (input, flags) {
            var result = this.encodeToString(input, flags);
            var inputStr = "";
            try {
                var String = Java.use("java.lang.String");
                inputStr = String.$new(input, "UTF-8");
            } catch (e) { /* ignore */ }

            // Detect JWT-like patterns (JSON with header fields)
            if (inputStr.indexOf('"alg"') !== -1 || inputStr.indexOf('"typ"') !== -1 ||
                inputStr.indexOf('"iss"') !== -1 || inputStr.indexOf('"sub"') !== -1 ||
                inputStr.indexOf('"exp"') !== -1) {
                logEntry("JWT_TOKEN", "JWT component detected:" +
                    "\n    Input (utf8): " + inputStr +
                    "\n    Encoded: " + result);
                logEntry("JWT_TOKEN_STACK", "Call stack:\n" + getStackTrace());
            }

            // Detect authorization/signature patterns
            if (result.length > 20 && (inputStr.indexOf("secret") !== -1 ||
                inputStr.indexOf("key") !== -1 || inputStr.indexOf("sign") !== -1)) {
                logEntry("TOKEN_SIGN", "Potential token signing:" +
                    "\n    Input: " + inputStr +
                    "\n    Encoded: " + result);
            }

            return result;
        };

        console.log("[+] Base64 token detection hooked");
    } catch (e) {
        console.log("[-] Base64 hook failed: " + e);
    }
}

// ============================================================================
// SharedPreferences - Detect Stored Keys/Tokens
// ============================================================================

function hookSharedPreferences() {
    try {
        var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl$EditorImpl");

        SharedPreferencesImpl.putString.implementation = function (key, value) {
            // Check for security-related keys
            var securityKeywords = ["key", "secret", "token", "auth", "api", "sign",
                                     "password", "credential", "session", "jwt", "hmac",
                                     "cipher", "encrypt", "hash", "bearer"];
            var keyLower = key.toLowerCase();
            var isSecurityRelated = false;

            for (var i = 0; i < securityKeywords.length; i++) {
                if (keyLower.indexOf(securityKeywords[i]) !== -1) {
                    isSecurityRelated = true;
                    break;
                }
            }

            if (isSecurityRelated) {
                logEntry("STORED_SECRET", "SharedPreferences key: \"" + key + "\" | value: \"" + value + "\"");
            }

            return this.putString(key, value);
        };

        console.log("[+] SharedPreferences hooked");
    } catch (e) {
        console.log("[-] SharedPreferences hook failed: " + e);
    }
}

// ============================================================================
// String Concatenation for Header Building Detection
// ============================================================================

function hookStringBuilder() {
    try {
        var StringBuilder = Java.use("java.lang.StringBuilder");

        // Monitor toString() for auth-related patterns
        StringBuilder.toString.implementation = function () {
            var result = this.toString();

            // Detect authorization header patterns
            if (result !== null && result.length > 10) {
                var lower = result.toLowerCase();
                if (lower.indexOf("bearer ") === 0 ||
                    lower.indexOf("basic ") === 0 ||
                    lower.indexOf("digest ") === 0 ||
                    lower.indexOf("hmac ") === 0 ||
                    (lower.indexOf("authorization") !== -1 && lower.indexOf(":") !== -1)) {
                    logEntry("AUTH_HEADER_BUILD", "Authorization pattern: " + result);
                    logEntry("AUTH_HEADER_BUILD_STACK", "Call stack:\n" + getStackTrace());
                }
            }

            return result;
        };

        console.log("[+] StringBuilder auth detection hooked");
    } catch (e) {
        console.log("[-] StringBuilder hook failed: " + e);
    }
}

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================

Java.perform(function () {
    console.log("==============================================");
    console.log("  Header Hooks - Runtime Header Extractor");
    console.log("==============================================");

    packageName = getPackageName();
    console.log("[*] Package: " + packageName);
    console.log("[*] Output: " + getOutputPath());

    ensureOutputDir();

    writeToFile("================================================================================");
    writeToFile("Runtime Header Extraction Report");
    writeToFile("Package: " + packageName);
    writeToFile("Date: " + timestamp());
    writeToFile("================================================================================");
    writeToFile("");

    hookOkHttpRequestBuilder();
    hookOkHttpInterceptor();
    hookHttpURLConnection();
    hookWebView();
    hookBase64ForTokens();
    hookSharedPreferences();
    hookStringBuilder();

    console.log("==============================================");
    console.log("[+] All header hooks installed successfully");
    console.log("[*] Waiting for HTTP operations...");
    console.log("==============================================");
});
