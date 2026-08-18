package com.apax.security.scanner

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.net.Socket
import java.nio.ByteBuffer

class ClamAvClient(private val host: String, private val port: Int) {
    suspend fun scan(file: File): String = withContext(Dispatchers.IO) {
        require(host.isNotBlank()) { "أدخل عنوان خادم ClamAV" }
        Socket(host, port).use { socket ->
            socket.soTimeout = 120_000
            val input = socket.getInputStream(); val output = socket.getOutputStream()
            output.write("zINSTREAM\u0000".toByteArray(Charsets.US_ASCII))
            file.inputStream().use { stream ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val count = stream.read(buffer)
                    if (count <= 0) break
                    output.write(ByteBuffer.allocate(4).putInt(count).array())
                    output.write(buffer, 0, count)
                }
            }
            output.write(byteArrayOf(0, 0, 0, 0)); output.flush()
            input.bufferedReader(Charsets.US_ASCII).readLine() ?: "لم تصل نتيجة من ClamAV"
        }
    }
}
