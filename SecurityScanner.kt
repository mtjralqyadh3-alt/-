package com.apax.security.scanner

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

 data class AppRisk(val label: String, val packageName: String, val grantedSensitive: List<String>, val riskScore: Int, val apkPath: String?)

class SecurityScanner(private val context: Context) {
    private val pm = context.packageManager
    private val sensitive = mapOf(
        "android.permission.CAMERA" to "الكاميرا",
        "android.permission.RECORD_AUDIO" to "الميكروفون",
        "android.permission.ACCESS_FINE_LOCATION" to "الموقع الدقيق",
        "android.permission.ACCESS_COARSE_LOCATION" to "الموقع التقريبي",
        "android.permission.READ_SMS" to "قراءة SMS",
        "android.permission.SEND_SMS" to "إرسال SMS",
        "android.permission.READ_CONTACTS" to "جهات الاتصال",
        "android.permission.REQUEST_INSTALL_PACKAGES" to "تثبيت حزم"
    )

    suspend fun scanInstalledApps(): List<AppRisk> = withContext(Dispatchers.IO) {
        val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_META_DATA
        val packages: List<PackageInfo> = pm.getInstalledPackages(flags)
        packages.mapNotNull { info ->
            val app = info.applicationInfo ?: return@mapNotNull null
            val requested = info.requestedPermissions ?: emptyArray()
            val granted = info.requestedPermissions?.indices
                ?.filter { index -> (info.requestedPermissionsFlags?.getOrNull(index) ?: 0) and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0 }
                ?.mapNotNull { requested.getOrNull(it) } ?: emptyList()
            val sensitiveGranted = granted.mapNotNull { sensitive[it] }
            val score = (sensitiveGranted.size * 12 + if (app.flags and ApplicationInfo.FLAG_SYSTEM != 0) 0 else 5).coerceAtMost(100)
            AppRisk(pm.getApplicationLabel(app).toString(), info.packageName, sensitiveGranted, score, app.sourceDir)
        }.sortedByDescending { it.riskScore }
    }
}
