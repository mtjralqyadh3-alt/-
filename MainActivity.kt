package com.apax.security.ui

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.widget.ArrayAdapter
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.apax.security.databinding.ActivityMainBinding
import com.apax.security.scanner.SecurityScanner
import com.apax.security.scanner.StorageScanner
import com.apax.security.security.VaultManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.security.MessageDigest

class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding
    private val scanner by lazy { SecurityScanner(this) }
    private val storageScanner by lazy { StorageScanner() }
    private val vault by lazy { VaultManager(this) }
    private var vaultUnlocked = false
    private var scanAfterPermission = false
    private var restoreItem: VaultManager.VaultItem? = null
    private val pickFile = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri ?: return@registerForActivityResult
        lifecycleScope.launch {
            runCatching { vault.importEncrypted(uri, vault.originalName(uri)) }
                .onSuccess { refreshVault(); toast("تم تشفير ${it.originalName} ونقله إلى الخزنة") }
                .onFailure { toast("فشل التشفير: ${it.message}") }
        }
    }
    private val restorePicker = registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val item = restoreItem
        if (uri == null || item == null) return@registerForActivityResult
        lifecycleScope.launch { runCatching { withContext(Dispatchers.IO) { vault.decryptToUri(uri, item) } }.onSuccess { toast("تمت استعادة ${item.originalName}") }.onFailure { toast("فشل الاستعادة: ${it.message}") } }
    }
    private val mediaPermission = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { results ->
        val denied = results.filterValues { !it }.keys
        if (denied.isEmpty() && scanAfterPermission) { scanAfterPermission = false; runScan() }
        else if (denied.isNotEmpty()) { scanAfterPermission = false; binding.scanStatus.text = "لم تُمنح كل أذونات الوسائط؛ لم يبدأ فحص الملفات." }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.scanButton.setOnClickListener { requestAccessThenScan() }
        binding.scanStorageButton.setOnClickListener { requestStorageScan() }
        binding.storageButton.setOnClickListener { openAllFilesSettings() }
        binding.launcherSettingsButton.setOnClickListener { startActivity(Intent(Settings.ACTION_HOME_SETTINGS)) }
        binding.unlockButton.setOnClickListener { unlockOrCalculate() }
        binding.clearButton.setOnClickListener { binding.calculatorInput.text?.clear(); binding.calculatorResult.text = "" }
        binding.importButton.setOnClickListener { if (vaultUnlocked) pickFile.launch(arrayOf("image/*", "video/*", "audio/*", "application/pdf", "text/plain")) else toast("افتح الخزنة أولاً") }
        refreshVault()
        updateAccessStatus()
    }

    override fun onResume() { super.onResume(); updateAccessStatus(); if (scanAfterPermission && (Build.VERSION.SDK_INT < 30 || Environment.isExternalStorageManager())) { requestMediaAccess() } }

    private fun requestAccessThenScan() {
        if (Build.VERSION.SDK_INT >= 30 && !Environment.isExternalStorageManager()) { scanAfterPermission = true; binding.scanStatus.text = "امنح الوصول في صفحة النظام ثم عد للتطبيق."; openAllFilesSettings(); return }
        requestMediaAccess()
    }

    private fun requestMediaAccess() {
        val permissions = if (Build.VERSION.SDK_INT >= 33) arrayOf(Manifest.permission.READ_MEDIA_IMAGES, Manifest.permission.READ_MEDIA_VIDEO) else arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE)
        if (Build.VERSION.SDK_INT < 33 || permissions.any { checkSelfPermission(it) != android.content.pm.PackageManager.PERMISSION_GRANTED }) { mediaPermission.launch(permissions) } else runScan()
    }

    private fun requestStorageScan() {
        if (Build.VERSION.SDK_INT >= 30 && !Environment.isExternalStorageManager()) { toast("امنح الوصول إلى جميع الملفات أولاً"); openAllFilesSettings(); return }
        binding.storageScanStatus.text = "جاري قراءة الملفات المتاحة..."
        binding.scanStorageButton.isEnabled = false
        lifecycleScope.launch {
            runCatching { storageScanner.scan() }.onSuccess { findings ->
                binding.storageScanStatus.text = "تمت مراجعة الملفات المتاحة: ${findings.size} عنصر يحتاج مراجعة. لم يتم حذف أي ملف."
                binding.storageScanResult.text = findings.take(100).joinToString("\\n\\n") { "${it.reason}: ${it.file.path}\\nالحجم: ${it.size / 1024} KB" }.ifBlank { "لم يتم العثور على ملفات ضمن التصنيفات المحددة." }
            }.onFailure { binding.storageScanStatus.text = "فشل فحص التخزين: ${it.message}" }
            binding.scanStorageButton.isEnabled = true
        }
    }

    private fun runScan() {
        binding.scanStatus.text = "جاري فحص التطبيقات المثبتة فعلياً..."
        binding.scanButton.isEnabled = false
        lifecycleScope.launch {
            runCatching { scanner.scanInstalledApps() }.onSuccess { results ->
                val high = results.count { it.riskScore >= 60 }
                binding.scanStatus.text = "اكتمل فحص ${results.size} تطبيقاً. نتائج heuristic: $high عالي، ${results.count { it.riskScore in 30..59 }} متوسط، ${results.count { it.riskScore < 30 }} منخفض. هذه ليست نتيجة Malware مؤكدة."
                binding.scanResult.text = results.take(80).joinToString("\n\n") { app -> "${app.label}\n${app.packageName}\nالأذونات الحساسة الممنوحة: ${app.grantedSensitive.ifEmpty { listOf("لا يوجد") }.joinToString()}\nالدرجة الإرشادية: ${app.riskScore}/100\nAPK: ${app.apkPath ?: "غير متاح"}" }
            }.onFailure { binding.scanStatus.text = "فشل الفحص: ${it.message}" }
            binding.scanButton.isEnabled = true
        }
    }

    private fun unlockOrCalculate() {
        val text = binding.calculatorInput.text?.toString()?.replace(" ", "").orEmpty()
        if (text == "apax781008103") { vaultUnlocked = true; binding.vaultStatus.text = "الخزنة مفتوحة — تشفير AES-256-GCM فعال"; binding.importButton.isEnabled = true; refreshVault(); return }
        val pattern = Regex("^-?\\d+(?:[.]\\d+)?(?:[+\\-*/]-?\\d+(?:[.]\\d+)?)+$")
        if (!pattern.matches(text)) { toast("أدخل عملية حسابية صحيحة أو الرمز السري"); return }
        runCatching { calculate(text) }.onSuccess { binding.calculatorResult.text = it.toString() }.onFailure { toast("عملية غير صالحة") }
    }

    private fun calculate(expression: String): Double {
        val tokens = Regex("(?<=[+\\-*/])|(?=[+\\-*/])").split(expression).filter { it.isNotEmpty() }.toMutableList(); var i = 1
        while (i < tokens.size - 1) { if (tokens[i] == "*" || tokens[i] == "/") { val a = tokens[i - 1].toDouble(); val b = tokens[i + 1].toDouble(); require(tokens[i] != "/" || b != 0.0); tokens[i - 1] = if (tokens[i] == "*") (a * b).toString() else (a / b).toString(); tokens.removeAt(i); tokens.removeAt(i); i-- }; i += 2 }
        var result = tokens[0].toDouble(); i = 1; while (i < tokens.size - 1) { val b = tokens[i + 1].toDouble(); result = if (tokens[i] == "+") result + b else result - b; i += 2 }; return result
    }

    private fun refreshVault() {
        if (!::binding.isInitialized) return
        val items = vault.list()
        binding.vaultList.adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, items.map { "${it.originalName} — ${it.size / 1024} KB" })
        binding.vaultList.setOnItemClickListener { _, _, position, _ -> if (vaultUnlocked) { restoreItem = items[position]; restorePicker.launch(items[position].originalName) } else toast("افتح الخزنة أولاً") }
        binding.vaultList.setOnItemLongClickListener { _, _, position, _ -> if (!vaultUnlocked) { toast("افتح الخزنة أولاً"); true } else { val item = items[position]; if (vault.delete(item)) { refreshVault(); toast("تم حذف الملف المشفر") }; true } }
    }

    private fun openAllFilesSettings() { if (Build.VERSION.SDK_INT >= 30) startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:$packageName"))) else toast("هذا الإصدار لا يحتاج وصول جميع الملفات") }
    private fun updateAccessStatus() { binding.accessStatus.text = if (Build.VERSION.SDK_INT < 30 || Environment.isExternalStorageManager()) "الوصول الخاص للملفات: مُفعّل" else "الوصول الخاص للملفات: غير مُفعّل" }
    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_LONG).show()
}
