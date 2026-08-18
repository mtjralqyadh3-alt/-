package com.apax.security.ui

import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Bundle
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class LauncherActivity : AppCompatActivity() {
    private val prefs by lazy { getSharedPreferences("launcher", MODE_PRIVATE) }
    private lateinit var list: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(24, 24, 24, 24) }
        setContentView(list)
        renderApps()
    }

    override fun onResume() { super.onResume(); if (::list.isInitialized) renderApps() }

    private fun renderApps() {
        list.removeAllViews()
        addText("Apax Home", 28f, true)
        addText("اضغط على التطبيق لفتحه. اضغط مطولاً لإخفائه أو إظهاره.", 15f, false)
        val apps = packageManager.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), PackageManager.MATCH_ALL)
            .distinctBy { it.activityInfo.packageName }.sortedBy { it.loadLabel(packageManager).toString() }
        val visible = apps.filterNot { isHidden(it.activityInfo.packageName) }
        val hidden = apps.filter { isHidden(it.activityInfo.packageName) }
        addText("التطبيقات الظاهرة (${visible.size})", 20f, true)
        visible.forEach { addApp(it, false) }
        addText("التطبيقات المخفية داخل Apax (${hidden.size})", 20f, true)
        if (hidden.isEmpty()) addText("لا توجد تطبيقات مخفية حالياً.", 15f, false)
        hidden.forEach { addApp(it, true) }
    }

    private fun addApp(resolve: android.content.pm.ResolveInfo, hidden: Boolean) {
        val packageName = resolve.activityInfo.packageName
        val row = TextView(this).apply {
            text = "${resolve.loadLabel(packageManager)}\n$packageName"; textSize = 17f; setTextColor(Color.WHITE); gravity = Gravity.CENTER_VERTICAL; setPadding(16, 18, 16, 18)
            setOnClickListener { packageManager.getLaunchIntentForPackage(packageName)?.let(::startActivity) ?: Toast.makeText(context, "لا يمكن تشغيل هذا التطبيق", Toast.LENGTH_SHORT).show() }
            setOnLongClickListener { prefs.edit().putBoolean("hidden_$packageName", !hidden).apply(); renderApps(); Toast.makeText(context, if (hidden) "أُعيد إلى القائمة الظاهرة" else "أُخفي داخل Apax Home", Toast.LENGTH_SHORT).show(); true }
        }
        list.addView(row, LinearLayout.LayoutParams(-1, LinearLayout.LayoutParams.WRAP_CONTENT))
    }

    private fun isHidden(packageName: String) = prefs.getBoolean("hidden_$packageName", false)
    private fun addText(text: String, size: Float, bold: Boolean) { list.addView(TextView(this).apply { this.text = text; textSize = size; if (bold) setTypeface(null, android.graphics.Typeface.BOLD); setPadding(0, 12, 0, 8) }) }
}
