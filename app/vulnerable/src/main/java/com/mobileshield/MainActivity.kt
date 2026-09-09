package com.mobileshield

import android.annotation.SuppressLint
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.appcompat.app.AppCompatActivity
import java.security.MessageDigest

/*
 * Training-only vulnerable Android activity.
 *
 * The weaknesses in this file are intentional and use synthetic
 * values. Do not reuse this implementation in a real application.
 */
class MainActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "MobileShield"
        private const val API_BASE_URL =
            "http://api.mobileshield.test"
        private const val API_KEY =
            "DEMO_API_KEY_DO_NOT_USE_IN_PRODUCTION"
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val accountId =
            intent.getStringExtra("account_id")
                ?: "demo-account-001"

        val sessionToken =
            intent.getStringExtra("session_token")
                ?: "synthetic-session-token"

        /*
         * Intentional weakness:
         * sensitive authentication data written to application logs.
         */
        Log.d(
            TAG,
            "Opening account=$accountId " +
                "session=$sessionToken apiKey=$API_KEY",
        )

        /*
         * Intentional weakness:
         * session and account data stored in plaintext preferences.
         */
        getSharedPreferences(
            "customer_session",
            MODE_PRIVATE,
        )
            .edit()
            .putString("account_id", accountId)
            .putString("session_token", sessionToken)
            .putString("api_key", API_KEY)
            .apply()

        val webView = WebView(this)

        /*
         * Intentional weaknesses:
         * JavaScript and local file access enabled together.
         */
        webView.settings.javaScriptEnabled = true
        webView.settings.allowFileAccess = true
        webView.settings.allowContentAccess = true
        webView.settings.allowUniversalAccessFromFileURLs = true

        /*
         * Intentional weakness:
         * sensitive token exposed through a JavaScript interface.
         */
        webView.addJavascriptInterface(
            AccountBridge(sessionToken),
            "MobileBridge",
        )

        /*
         * Intentional weakness:
         * untrusted intent data used in a cleartext URL.
         */
        webView.loadUrl(
            "$API_BASE_URL/account?accountId=$accountId",
        )

        setContentView(webView)

        /*
         * Intentional weakness:
         * weak MD5 hashing used for a security-sensitive value.
         */
        val accountReference = weakHash(accountId)

        Log.d(
            TAG,
            "Generated account reference: $accountReference",
        )
    }

    private fun weakHash(value: String): String {
        val digest = MessageDigest.getInstance("MD5")
            .digest(value.toByteArray())

        return Base64.encodeToString(
            digest,
            Base64.NO_WRAP,
        )
    }

    class AccountBridge(
        private val sessionToken: String,
    ) {
        @JavascriptInterface
        fun getSessionToken(): String {
            return sessionToken
        }
    }
}