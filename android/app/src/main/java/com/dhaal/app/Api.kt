package com.dhaal.app

import org.json.JSONObject
import java.io.DataOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID

/** Blocking HTTP client for the Cloud Run API. Call from a background thread only. */
object Api {
    const val BASE = "https://dhaal-151886458985.asia-south1.run.app"

    /** Bearer token from /v1/auth/login; loaded from Prefs by the activity and the guard service. */
    @Volatile var token: String = ""

    class Part(val name: String, val filename: String, val mime: String, val bytes: ByteArray)
    class AuthRequired : RuntimeException("Sign in required")

    private fun open(path: String, timeoutMs: Int): HttpURLConnection =
        (URL(BASE.trimEnd('/') + path).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = 10_000
            readTimeout = timeoutMs
            doOutput = true
            if (token.isNotBlank()) setRequestProperty("Authorization", "Bearer $token")
        }

    fun postJson(path: String, body: JSONObject, timeoutMs: Int = 20_000): JSONObject {
        val conn = open(path, timeoutMs)
        conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
        conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
        return read(conn)
    }

    fun postMultipart(path: String, fields: Map<String, String>, files: List<Part>, timeoutMs: Int = 90_000): JSONObject {
        val boundary = "----sv" + UUID.randomUUID().toString().replace("-", "")
        val conn = open(path, timeoutMs)
        conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
        DataOutputStream(conn.outputStream).use { out ->
            fun line(s: String) = out.write((s + "\r\n").toByteArray(Charsets.UTF_8))
            for ((k, v) in fields) {
                line("--$boundary")
                line("Content-Disposition: form-data; name=\"$k\"")
                line("")
                line(v)
            }
            for (p in files) {
                line("--$boundary")
                line("Content-Disposition: form-data; name=\"${p.name}\"; filename=\"${p.filename}\"")
                line("Content-Type: ${p.mime}")
                line("")
                out.write(p.bytes)
                line("")
            }
            line("--$boundary--")
        }
        return read(conn)
    }

    private fun read(conn: HttpURLConnection): JSONObject {
        val code = conn.responseCode
        val stream = if (code in 200..299) conn.inputStream else conn.errorStream
        val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() } ?: ""
        conn.disconnect()
        if (code == 401) throw AuthRequired()
        if (code !in 200..299) throw RuntimeException("Server error $code: ${text.take(200)}")
        return JSONObject(text)
    }
}
