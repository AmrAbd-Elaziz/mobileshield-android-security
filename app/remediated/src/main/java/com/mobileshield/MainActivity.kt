package com.mobileshield

import android.annotation.SuppressLint
import android.net.Uri
import android.os.Bundle
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import java.security.MessageDigest

/*
 * Training-only remediated Android activity.
 *
 * This version demonstrates safer mobile-development controls:
 * - HTTPS-only communication
 * - No hardcoded secrets
 * - No sensitive logging
 * - No plaintext credential storage
 * - Restricted WebView configuration
 * - No JavaScript bridge
 * - Modern SHA-256 hashing */
class MainActivity : AppCompatActivity() {

    private var secureWebView: WebView? = null

    companion object {
        private const val API_BASE_URL =
            "https://api.mobileshield.test"

        private const val DEFAULT_ACCOUNT_ID =
            "demo-account-001"
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        /*
         * External intent data is not trusted.
         * The production application should obtain the account
         * identity from an authenticated server-side session.
         */
        val accountId = DEFAULT_ACCOUNT_ID

        val webView = WebView(this)
        
        secureWebView = webView

        configureSecureWebView(webView)

        val accountUri = Uri.parse(API_BASE_URL)
            .buildUpon()
            .appendPath("account")
            .appendQueryParameter(
                "accountId",
                accountId,
            )
            .build()

        webView.loadUrl(accountUri.toString())

        setContentView(webView)

        /*
         * This reference is not used as authentication,
         * authorization or credential material.
         */
        generateAccountReference(accountId)
    }

    private fun configureSecureWebView(
        webView: WebView,
    ) {
        with(webView.settings) {
            javaScriptEnabled = false
            allowFileAccess = false
            allowContentAccess = false
            allowFileAccessFromFileURLs = false
            allowUniversalAccessFromFileURLs = false
        }

        webView.webViewClient = object : WebViewClient() {

            override fun shouldOverrideUrlLoading(
                view: WebView?,
                url: String?,
            ): Boolean {
                if (url == null) {
                    return true
                }

                val destination = Uri.parse(url)

                return destination.scheme != "https" ||
                    destination.host !=
                    "api.mobileshield.test"
            }
        }
    }

    private fun generateAccountReference(
        value: String,
    ): String {
        val digest = MessageDigest
            .getInstance("SHA-256")
            .digest(value.toByteArray(Charsets.UTF_8))

        return digest.joinToString("") { byte ->
            "%02x".format(byte)
        }
    }

    override fun onDestroy() {
        secureWebView?.apply {
            stopLoading()
            loadUrl("about:blank")
            clearHistory()
            clearCache(true)
            removeAllViews()
            destroy()
    }

    secureWebView = nullW
    super.onDestroy()
}
}
