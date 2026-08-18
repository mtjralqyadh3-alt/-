package com.apax.security.scanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

object FileHash {
    suspend fun sha256(file: File): String = withContext(Dispatchers.IO) {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(1024 * 1024)
            while (true) { val n = input.read(buffer); if (n <= 0) break; digest.update(buffer, 0, n) }
        }
        digest.digest().joinToString("") { "%02x".format(it) }
    }
}

class VirusTotalClient(private val apiKey: String) {
    suspend fun lookupHash(hash: String): String = request("https://www.virustotal.com/api/v3/files/$hash")

    suspend fun uploadFile(file: File): String = withContext(Dispatchers.IO) {
        require(apiKey.isNotBlank()) { "لم يتم إدخال مفتاح VirusTotal" }
        val boundary = "----ApaxBoundary${System.currentTimeMillis()}"
        val connection = (URL("https://www.virustotal.com/api/v3/files").openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"; doOutput = true; connectTimeout = 30000; readTimeout = 120000
            setRequestProperty("x-apikey", apiKey); setRequestProperty("Accept", "application/json")
            setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
        }
        try {
            connection.outputStream.use { out ->
                out.write("--$boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"${file.name.replace(Regex("[^A-Za-z0-9._-]"), "_")}\"\r\nContent-Type: application/octet-stream\r\n\r\n".toByteArray())
                file.inputStream().use { it.copyTo(out) }
                out.write("\r\n--$boundary--\r\n".toByteArray())
            }
            readResponse(connection)
        } finally { connection.disconnect() }
    }

    private suspend fun request(url: String): String = withContext(Dispatchers.IO) {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"; connectTimeout = 15000; readTimeout = 30000
            setRequestProperty("x-apikey", apiKey); setRequestProperty("Accept", "application/json")
        }
        try { readResponse(connection) } finally { connection.disconnect() }
    }

    private fun readResponse(connection: HttpURLConnection): String {
        val code = connection.responseCode
        val body = (if (code in 200..299) connection.inputStream else connection.errorStream)?.bufferedReader()?.readText().orEmpty()
        if (code !in 200..299) error("VirusTotal HTTP $code: ${body.take(300)}")
        return body
    }
}
