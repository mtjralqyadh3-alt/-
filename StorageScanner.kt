package com.apax.security.scanner

import android.os.Environment
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

 data class FileFinding(val file: File, val reason: String, val size: Long)

class StorageScanner {
    suspend fun scan(): List<FileFinding> = withContext(Dispatchers.IO) {
        val root = Environment.getExternalStorageDirectory()
        val result = ArrayList<FileFinding>()
        walk(root, result)
        result.sortedWith(compareByDescending<FileFinding> { it.size }.thenBy { it.file.path })
    }

    private fun walk(dir: File, result: MutableList<FileFinding>) {
        if (!dir.exists() || !dir.canRead()) return
        val children = runCatching { dir.listFiles() }.getOrNull() ?: return
        for (file in children) {
            if (file.isDirectory) { if (file.name != "Android") walk(file, result); continue }
            val name = file.name.lowercase()
            val reason = when {
                file.length() == 0L -> "ملف فارغ"
                name.endsWith(".tmp") || name.endsWith(".temp") || name.endsWith(".log") || name == ".ds_store" -> "ملف مؤقت/سجل قابل للمراجعة"
                file.length() >= 100L * 1024L * 1024L -> "ملف كبير؛ ليس ضاراً بالضرورة"
                else -> null
            }
            if (reason != null) result.add(FileFinding(file, reason, file.length()))
        }
    }
}
