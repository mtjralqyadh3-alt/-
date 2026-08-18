package com.apax.security.security

import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.provider.OpenableColumns
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class VaultManager(private val context: Context) {
    private val vaultDir = File(context.filesDir, "vault").apply { mkdirs() }
    private val alias = "apax_vault_aes256"

    private val key: SecretKey
        get() {
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            (store.getKey(alias, null) as? SecretKey)?.let { return it }
            return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
                init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setRandomizedEncryptionRequired(true).build())
            }.generateKey()
        }

    data class VaultItem(val file: File, val originalName: String, val size: Long)
    fun list(): List<VaultItem> = vaultDir.listFiles()?.filter { it.extension == "apax" }?.sortedBy { it.name }
        ?.map { VaultItem(it, it.name.removeSuffix(".apax"), it.length()) } ?: emptyList()

    fun originalName(uri: Uri): String {
        var cursor: Cursor? = null
        return try {
            cursor = context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            if (cursor?.moveToFirst() == true) cursor.getString(0) else (uri.lastPathSegment ?: "selected_file")
        } finally { cursor?.close() }
    }

    fun importEncrypted(uri: Uri, displayName: String): VaultItem {
        val safe = displayName.substringAfterLast('/').replace(Regex("[^A-Za-z0-9._-]"), "_").ifBlank { "selected_file" }
        val outFile = File(vaultDir, "$safe.apax")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
        val input = requireNotNull(context.contentResolver.openInputStream(uri)) { "لا يمكن قراءة الملف المحدد" }
        input.use { source ->
            outFile.outputStream().use { raw ->
                raw.write(cipher.iv.size)
                raw.write(cipher.iv)
                CipherOutputStream(raw, cipher).use { encrypted -> source.copyTo(encrypted) }
            }
        }
        return VaultItem(outFile, safe, outFile.length())
    }

    fun delete(item: VaultItem): Boolean = item.file.delete()

    fun decryptToUri(target: Uri, item: VaultItem) {
        item.file.inputStream().use { raw ->
            val ivSize = raw.read()
            require(ivSize in 12..16) { "ملف خزنة غير صالح" }
            val iv = ByteArray(ivSize)
            require(raw.read(iv) == ivSize) { "بيانات ناقصة" }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv)) }
            CipherInputStream(raw, cipher).use { decrypted ->
                val output = requireNotNull(context.contentResolver.openOutputStream(target)) { "لا يمكن الكتابة إلى الوجهة" }
                output.use { decrypted.copyTo(it) }
            }
        }
    }

    fun decryptTo(target: File, item: VaultItem) {
        item.file.inputStream().use { raw ->
            val ivSize = raw.read()
            require(ivSize in 12..16) { "ملف خزنة غير صالح" }
            val iv = ByteArray(ivSize)
            require(raw.read(iv) == ivSize) { "بيانات ناقصة" }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv)) }
            CipherInputStream(raw, cipher).use { decrypted -> target.outputStream().use { decrypted.copyTo(it) } }
        }
    }
}
