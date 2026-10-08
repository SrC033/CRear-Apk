import os
import sys
import shutil
import subprocess
import re
import base64
import requests
from flask import Flask, render_template, request, jsonify, Response
from flaskwebgui import FlaskUI

def resolve_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), relative_path)

app = Flask(__name__, template_folder=resolve_path("templates"))

if hasattr(sys, '_MEIPASS'):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

GRADLE_BIN = resolve_path(os.path.join("gradle", "gradle-8.2-bin", "gradle-8.2", "bin", "gradle.bat"))

# ============================================================
# CONFIGURACIÓN JDK PORTABLE
# ============================================================
def encontrar_jdk_portable():
    """Busca un JDK portable dentro del proyecto"""
    
    rutas_posibles = [
        os.path.join(BASE_DIR, "OpenJDK17U-jdk_x64_windows_hotspot_17.0.19_10", "jdk-17.0.19+10"),
        os.path.join(BASE_DIR, "jdk-17.0.12+7"),
        os.path.join(BASE_DIR, "jdk-17"),
        os.path.join(BASE_DIR, "jdk"),
        os.path.join(BASE_DIR, "java"),
        os.path.join(BASE_DIR, "jre"),
    ]
    
    for ruta in rutas_posibles:
        if os.path.exists(ruta):
            java_exe = os.path.join(ruta, "bin", "java.exe")
            if os.path.exists(java_exe):
                print(f"✅ JDK portable encontrado: {ruta}")
                return ruta
    
    print("⚠️ No se encontró JDK portable en el proyecto")
    return None

JDK_PORTABLE = encontrar_jdk_portable()

# ============================================================
# CONFIGURACIÓN ANDROID SDK PORTABLE
# ============================================================
def encontrar_android_sdk_portable():
    """Busca un Android SDK portable dentro del proyecto"""
    
    rutas_posibles = [
        os.path.join(BASE_DIR, "android-sdk"),
        os.path.join(BASE_DIR, "sdk"),
        os.path.join(BASE_DIR, "Android", "Sdk"),
        os.path.join(BASE_DIR, "android-sdk-windows"),
    ]
    
    for ruta in rutas_posibles:
        if os.path.exists(ruta):
            if os.path.exists(os.path.join(ruta, "platforms")) and \
               os.path.exists(os.path.join(ruta, "build-tools")):
                print(f"✅ Android SDK portable encontrado: {ruta}")
                return ruta
    
    print("⚠️ No se encontró Android SDK portable")
    return None

ANDROID_SDK_PORTABLE = encontrar_android_sdk_portable()

# ============================================================
# DICCIONARIO DE PERMISOS
# ============================================================
ALL_PERMISSIONS = {
    "INTERNET": "android.permission.INTERNET",
    "ACCESS_NETWORK_STATE": "android.permission.ACCESS_NETWORK_STATE",
    "ACCESS_WIFI_STATE": "android.permission.ACCESS_WIFI_STATE",
    "ACCESS_FINE_LOCATION": "android.permission.ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION": "android.permission.ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION": "android.permission.ACCESS_BACKGROUND_LOCATION",
    "READ_EXTERNAL_STORAGE": "android.permission.READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE": "android.permission.WRITE_EXTERNAL_STORAGE",
    "READ_MEDIA_IMAGES": "android.permission.READ_MEDIA_IMAGES",
    "READ_MEDIA_VIDEO": "android.permission.READ_MEDIA_VIDEO",
    "READ_MEDIA_AUDIO": "android.permission.READ_MEDIA_AUDIO",
    "CAMERA": "android.permission.CAMERA",
    "RECORD_AUDIO": "android.permission.RECORD_AUDIO",
    "MODIFY_AUDIO_SETTINGS": "android.permission.MODIFY_AUDIO_SETTINGS",
    "POST_NOTIFICATIONS": "android.permission.POST_NOTIFICATIONS",
    "DOWNLOAD_WITHOUT_NOTIFICATION": "android.permission.DOWNLOAD_WITHOUT_NOTIFICATION",
    "FOREGROUND_SERVICE": "android.permission.FOREGROUND_SERVICE",
    "VIBRATE": "android.permission.VIBRATE",
    "WAKE_LOCK": "android.permission.WAKE_LOCK",
}

DEFAULT_PERMISSIONS = [
    "INTERNET",
    "ACCESS_NETWORK_STATE",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "READ_MEDIA_IMAGES",
    "READ_MEDIA_VIDEO",
]

def sanitizar_package_name(name):
    clean = re.sub(r'[^a-zA-Z0-9]', '', name)
    if not clean:
        clean = "app"
    if clean[0].isdigit():
        clean = "app" + clean
    return f"com.{clean.lower()}.app"

def analizar_permisos_html(html_content):
    permisos_detectados = set()
    permisos_detectados.add("INTERNET")
    permisos_detectados.add("ACCESS_NETWORK_STATE")
    
    if re.search(r'navigator\.geolocation|getCurrentPosition|watchPosition|ubicacion|ubicación|location', html_content, re.IGNORECASE):
        permisos_detectados.add("ACCESS_FINE_LOCATION")
        permisos_detectados.add("ACCESS_COARSE_LOCATION")
    
    if re.search(r'download|descargar|\.pdf|FileReader|createObjectURL|localStorage|PDF|input.*type.*file|files|fileInput|archivo', html_content, re.IGNORECASE):
        permisos_detectados.add("READ_EXTERNAL_STORAGE")
        permisos_detectados.add("WRITE_EXTERNAL_STORAGE")
        permisos_detectados.add("READ_MEDIA_IMAGES")
        permisos_detectados.add("READ_MEDIA_VIDEO")
    
    if re.search(r'Notification|notificacion|notificación|push|alert', html_content, re.IGNORECASE):
        permisos_detectados.add("POST_NOTIFICATIONS")
    
    if re.search(r'background|foreground|service', html_content, re.IGNORECASE):
        permisos_detectados.add("FOREGROUND_SERVICE")
    
    if re.search(r'vibrate|vibrar|vibration', html_content, re.IGNORECASE):
        permisos_detectados.add("VIBRATE")
        permisos_detectados.add("WAKE_LOCK")
    
    if re.search(r'getUserMedia.*video|camera|webcam|cámara|camara|video\s+id', html_content, re.IGNORECASE):
        permisos_detectados.add("CAMERA")
    
    if re.search(r'getUserMedia.*audio|record|grabar|microfono|micrófono|voice', html_content, re.IGNORECASE):
        permisos_detectados.add("RECORD_AUDIO")
        permisos_detectados.add("MODIFY_AUDIO_SETTINGS")
    
    return list(permisos_detectados)

# ============================================================
# 1. JAVA TEMPLATE
# ============================================================
def generar_java_template(permisos_seleccionados, package_name):
    permisos_java = ""
    for perm in permisos_seleccionados:
        if perm in ALL_PERMISSIONS:
            permisos_java += f'        listPermissionsNeeded.add(Manifest.permission.{perm});\n'
    
    return f"""package {package_name};

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.webkit.PermissionRequest;
import android.webkit.GeolocationPermissions;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.CookieManager;
import android.net.http.SslError;
import android.webkit.SslErrorHandler;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.content.Context;
import android.util.Log;
import android.webkit.DownloadListener;
import android.content.Intent;
import android.net.Uri;
import android.os.Environment;
import android.webkit.URLUtil;
import android.app.DownloadManager;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import android.location.LocationManager;
import android.provider.Settings;
import android.widget.Toast;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient.FileChooserParams;

public class MainActivity extends AppCompatActivity {{
    
    private WebView webView;
    private static final int PERMISSION_REQUEST_CODE = 1234;
    private static final int LOCATION_SETTINGS_REQUEST = 5678;
    private static final int FILE_CHOOSER_REQUEST_CODE = 9999;
    private static final String TAG = "Primogenito";
    private DownloadManager downloadManager;
    private ValueCallback<Uri[]> filePathCallback;
    private ValueCallback<Uri> filePathCallbackLegacy;

    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        
        downloadManager = (DownloadManager) getSystemService(Context.DOWNLOAD_SERVICE);
        
        webView = new WebView(this);
        WebSettings webSettings = webView.getSettings();
        
        webSettings.setJavaScriptEnabled(true);
        webSettings.setDomStorageEnabled(true);
        webSettings.setDatabaseEnabled(true);
        webSettings.setGeolocationEnabled(true);
        webSettings.setAllowFileAccess(true);
        webSettings.setAllowContentAccess(true);
        webSettings.setJavaScriptCanOpenWindowsAutomatically(true);
        webSettings.setLoadWithOverviewMode(true);
        webSettings.setUseWideViewPort(true);
        webSettings.setSupportZoom(true);
        webSettings.setBuiltInZoomControls(true);
        webSettings.setDisplayZoomControls(false);
        webSettings.setBlockNetworkImage(false);
        webSettings.setBlockNetworkLoads(false);
        webSettings.setAllowUniversalAccessFromFileURLs(true);
        webSettings.setAllowFileAccessFromFileURLs(true);
        webSettings.setCacheMode(WebSettings.LOAD_DEFAULT);
        webSettings.setSaveFormData(true);
        webSettings.setGeolocationEnabled(true);
        
        CookieManager cookieManager = CookieManager.getInstance();
        cookieManager.setAcceptCookie(true);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {{
            cookieManager.setAcceptThirdPartyCookies(webView, true);
            webSettings.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        }}
        
        webSettings.setMediaPlaybackRequiresUserGesture(false);

        webView.setWebViewClient(new WebViewClient() {{
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, String url) {{
                if (url.endsWith(".pdf") || url.contains("/descargar_factura/")) {{
                    descargarArchivo(url);
                    return true;
                }}
                view.loadUrl(url);
                return true;
            }}

            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {{
                handler.proceed();
            }}

            @Override
            public void onPageFinished(WebView view, String url) {{
                super.onPageFinished(view, url);
                view.evaluateJavascript(
                    "console.log('✅ WebView cargado correctamente');" +
                    "if (typeof reconectarServidor === 'function') {{" +
                    "  console.log('✅ reconectarServidor disponible');" +
                    "}}", null);
            }}
        }});
        
        webView.setDownloadListener(new DownloadListener() {{
            @Override
            public void onDownloadStart(String url, String userAgent, String contentDisposition, String mimeType, long contentLength) {{
                if (url.endsWith(".pdf") || url.contains("/descargar_factura/") || "application/pdf".equals(mimeType)) {{
                    descargarArchivo(url);
                }} else {{
                    try {{
                        Intent intent = new Intent(Intent.ACTION_VIEW);
                        intent.setData(Uri.parse(url));
                        startActivity(intent);
                    }} catch (Exception e) {{
                        Log.e(TAG, "Error al abrir URL: " + e.getMessage());
                    }}
                }}
            }}
        }});
        
        webView.setWebChromeClient(new WebChromeClient() {{
            @Override
            public void onPermissionRequest(final PermissionRequest request) {{
                runOnUiThread(new Runnable() {{
                    @Override
                    public void run() {{
                        request.grant(request.getResources());
                    }}
                }});
            }}

            @Override
            public void onGeolocationPermissionsShowPrompt(String origin, GeolocationPermissions.Callback callback) {{
                callback.invoke(origin, true, false);
            }}
            
            @Override
            public boolean onShowFileChooser(WebView webView, ValueCallback<Uri[]> filePathCallback, FileChooserParams fileChooserParams) {{
                MainActivity.this.filePathCallback = filePathCallback;
                Intent intent = fileChooserParams.createIntent();
                try {{
                    startActivityForResult(intent, FILE_CHOOSER_REQUEST_CODE);
                }} catch (Exception e) {{
                    MainActivity.this.filePathCallback = null;
                    return false;
                }}
                return true;
            }}
            
            @SuppressWarnings("unused")
            public void openFileChooser(ValueCallback<Uri> uploadMsg) {{
                MainActivity.this.filePathCallbackLegacy = uploadMsg;
                Intent i = new Intent(Intent.ACTION_GET_CONTENT);
                i.addCategory(Intent.CATEGORY_OPENABLE);
                i.setType("*/*");
                startActivityForResult(Intent.createChooser(i, "Seleccionar Archivo"), FILE_CHOOSER_REQUEST_CODE);
            }}
            
            @SuppressWarnings("unused")
            public void openFileChooser(ValueCallback<Uri> uploadMsg, String acceptType) {{
                MainActivity.this.filePathCallbackLegacy = uploadMsg;
                Intent i = new Intent(Intent.ACTION_GET_CONTENT);
                i.addCategory(Intent.CATEGORY_OPENABLE);
                i.setType("*/*");
                startActivityForResult(Intent.createChooser(i, "Seleccionar Archivo"), FILE_CHOOSER_REQUEST_CODE);
            }}
            
            @SuppressWarnings("unused")
            public void openFileChooser(ValueCallback<Uri> uploadMsg, String acceptType, String capture) {{
                MainActivity.this.filePathCallbackLegacy = uploadMsg;
                Intent i = new Intent(Intent.ACTION_GET_CONTENT);
                i.addCategory(Intent.CATEGORY_OPENABLE);
                i.setType("*/*");
                startActivityForResult(Intent.createChooser(i, "Seleccionar Archivo"), FILE_CHOOSER_REQUEST_CODE);
            }}
        }});

        setContentView(webView);
        checkAndRequestPermissions();
        webView.loadUrl("file:///android_asset/index.html");
    }}
    
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {{
        super.onActivityResult(requestCode, resultCode, data);
        
        if (requestCode == FILE_CHOOSER_REQUEST_CODE) {{
            if (filePathCallback != null) {{
                Uri[] results = null;
                if (resultCode == RESULT_OK && data != null) {{
                    String dataString = data.getDataString();
                    if (dataString != null) {{
                        results = new Uri[]{{Uri.parse(dataString)}};
                    }}
                }}
                filePathCallback.onReceiveValue(results);
                filePathCallback = null;
            }} else if (filePathCallbackLegacy != null) {{
                Uri result = (resultCode == RESULT_OK && data != null) ? data.getData() : null;
                filePathCallbackLegacy.onReceiveValue(result);
                filePathCallbackLegacy = null;
            }}
        }}
    }}

    private void descargarArchivo(String url) {{
        try {{
            DownloadManager.Request request = new DownloadManager.Request(Uri.parse(url));
            request.setAllowedNetworkTypes(DownloadManager.Request.NETWORK_WIFI | DownloadManager.Request.NETWORK_MOBILE);
            request.setAllowedOverRoaming(false);
            request.setTitle("Descargando PDF...");
            request.setDescription("Descargando comprobante desde PRIMOGÉNITO");
            
            String fileName = URLUtil.guessFileName(url, null, "application/pdf");
            if (fileName == null || fileName.isEmpty()) {{
                fileName = "comprobante_" + System.currentTimeMillis() + ".pdf";
            }}
            if (!fileName.endsWith(".pdf")) {{
                fileName += ".pdf";
            }}
            
            request.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, fileName);
            request.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
            
            downloadManager.enqueue(request);
            Log.d(TAG, "📥 Descargando PDF: " + fileName);
            
            webView.evaluateJavascript(
                "if (typeof mostrarStatus === 'function') {{" +
                "  mostrarStatus('📥 Descargando PDF...', 'info');" +
                "}}", null);
                
        }} catch (Exception e) {{
            Log.e(TAG, "Error al descargar: " + e.getMessage());
            webView.evaluateJavascript(
                "if (typeof mostrarStatus === 'function') {{" +
                "  mostrarStatus('❌ Error al descargar PDF', 'error');" +
                "}}", null);
        }}
    }}

    private void checkAndRequestPermissions() {{
        List<String> listPermissionsNeeded = new ArrayList<>();
        
{permisos_java}
        
        List<String> reqPermissions = new ArrayList<>();
        for (String perm : listPermissionsNeeded) {{
            try {{
                if (ContextCompat.checkSelfPermission(this, perm) != PackageManager.PERMISSION_GRANTED) {{
                    reqPermissions.add(perm);
                }}
            }} catch (Exception e) {{
                Log.w(TAG, "Permiso no soportado: " + perm);
            }}
        }}

        if (!reqPermissions.isEmpty()) {{
            ActivityCompat.requestPermissions(this, reqPermissions.toArray(new String[0]), PERMISSION_REQUEST_CODE);
            Log.d(TAG, "📱 Solicitando " + reqPermissions.size() + " permisos");
        }} else {{
            Log.d(TAG, "✅ Todos los permisos ya están concedidos");
        }}
    }}

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {{
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CODE) {{
            int granted = 0;
            int denied = 0;
            for (int i = 0; i < permissions.length; i++) {{
                if (grantResults[i] == PackageManager.PERMISSION_GRANTED) {{
                    granted++;
                    Log.d(TAG, "✅ Permiso concedido: " + permissions[i]);
                }} else {{
                    denied++;
                    Log.w(TAG, "⚠️ Permiso denegado: " + permissions[i]);
                }}
            }}
            Log.d(TAG, "📊 Permisos: " + granted + " concedidos, " + denied + " denegados");
        }}
    }}
}}"""

# ============================================================
# 2. MANIFEST
# ============================================================
def generar_manifest(permisos_seleccionados, app_name, package_name):
    permisos_unicos = list(set(permisos_seleccionados))
    
    permisos_xml = ""
    for perm in permisos_unicos:
        perm_name = ALL_PERMISSIONS.get(perm, "")
        if perm_name:
            permisos_xml += f'    <uses-permission android:name="{perm_name}" />\n'
    
    features = ""
    if "ACCESS_FINE_LOCATION" in permisos_unicos or "ACCESS_COARSE_LOCATION" in permisos_unicos:
        features += '    <uses-feature android:name="android.hardware.location.gps" android:required="false" />\n'
        features += '    <uses-feature android:name="android.hardware.location" android:required="false" />\n'
    
    if "CAMERA" in permisos_unicos:
        features += '    <uses-feature android:name="android.hardware.camera" android:required="false" />\n'
    
    return f"""<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools"
    package="{package_name}">
    
    <!-- ===== PERMISOS SELECCIONADOS ===== -->
{permisos_xml}
    
    <!-- ===== FEATURES ===== -->
{features}
    
    <application
        android:allowBackup="true"
        android:label="{app_name}"
        android:icon="@mipmap/ic_launcher"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:usesCleartextTraffic="true"
        android:networkSecurityConfig="@xml/network_security_config"
        android:requestLegacyExternalStorage="true"
        android:theme="@style/Theme.AppCompat.Light.NoActionBar"
        tools:targetApi="31">
        
        <activity android:name=".MainActivity" 
            android:exported="true"
            android:launchMode="singleTop"
            android:configChanges="orientation|screenSize|keyboardHidden">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        
        <provider
            android:name="androidx.core.content.FileProvider"
            android:authorities="{package_name}.fileprovider"
            android:exported="false"
            android:grantUriPermissions="true">
            <meta-data
                android:name="android.support.FILE_PROVIDER_PATHS"
                android:resource="@xml/file_paths" />
        </provider>
    </application>
</manifest>"""

# ============================================================
# 3. BUILD GRADLE (APP)
# ============================================================
def generar_build_gradle_app(package_name):
    return f"""plugins {{ 
    id 'com.android.application'
}}
android {{
    namespace '{package_name}'
    compileSdk 34
    
    defaultConfig {{
        applicationId "{package_name}"
        minSdk 21
        targetSdk 34
        versionCode 1
        versionName "1.0"
    }}
    
    compileOptions {{
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }}
}}
dependencies {{ 
    implementation 'androidx.appcompat:appcompat:1.6.1'
}}"""

# ============================================================
# 4. NETWORK SECURITY CONFIG
# ============================================================
NETWORK_SECURITY_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">trycloudflare.com</domain>
        <domain includeSubdomains="true">cloudflare.com</domain>
        <domain includeSubdomains="true">localhost</domain>
        <domain includeSubdomains="true">127.0.0.1</domain>
        <domain includeSubdomains="true">10.0.2.2</domain>
    </domain-config>
</network-security-config>"""

FILE_PATHS_XML = """<?xml version="1.0" encoding="utf-8"?>
<paths>
    <external-path name="external_files" path="." />
    <external-files-path name="external_files" path="." />
    <cache-path name="cache_files" path="." />
    <external-cache-path name="external_cache_files" path="." />
    <files-path name="files" path="." />
</paths>"""

# ============================================================
# 5. GRADLE FILES
# ============================================================
SETTINGS_GRADLE = """pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { 
        google()
        mavenCentral()
    }
}
rootProject.name = "HtmlToApk"
include ':app'"""

BUILD_GRADLE_ROOT = """buildscript {
    repositories { 
        google()
        mavenCentral()
    }
    dependencies { 
        classpath 'com.android.tools.build:gradle:8.2.2'
    }
}"""

GRADLE_PROPERTIES = """android.useAndroidX=true
android.enableJetifier=true
org.gradle.jvmargs=-Xmx4096m
org.gradle.parallel=true
org.gradle.caching=true
org.gradle.daemon=true
kotlin.stdlib.default.dependency=false
"""

# ============================================================
# 6. ESTADO GLOBAL
# ============================================================
pending_file_content = None
chosen_app_name = "MiAppHTML"
pending_icon_base64 = None
selected_permissions = []

def sanitize_filename(name):
    return re.sub(r'[\\/*?:"<>| ]', "_", name)

# ============================================================
# 7. RUTAS FLASK
# ============================================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/permisos', methods=['GET'])
def api_permisos():
    permisos_lista = []
    for key, value in ALL_PERMISSIONS.items():
        categoria = "Otros"
        if "LOCATION" in key or "GPS" in key:
            categoria = "Ubicación"
        elif "STORAGE" in key or "MEDIA" in key or "EXTERNAL" in key:
            categoria = "Almacenamiento"
        elif "CAMERA" in key:
            categoria = "Cámara"
        elif "AUDIO" in key or "MICROPHONE" in key or "RECORD" in key:
            categoria = "Micrófono/Audio"
        elif "NOTIFICATION" in key:
            categoria = "Notificaciones"
        elif "FOREGROUND" in key or "SERVICE" in key:
            categoria = "Servicios"
        elif "WIFI" in key or "NETWORK" in key:
            categoria = "Red"
        elif "VIBRATE" in key or "WAKE" in key:
            categoria = "Sistema"
        elif "DOWNLOAD" in key:
            categoria = "Descargas"
        
        permisos_lista.append({
            "id": key,
            "nombre": key,
            "permiso": value,
            "categoria": categoria,
            "seleccionado": key in DEFAULT_PERMISSIONS,
            "detectado": False,
            "es_esencial": key in DEFAULT_PERMISSIONS
        })
    
    permisos_lista.sort(key=lambda x: (not x["es_esencial"], x["categoria"], x["nombre"]))
    return jsonify({"ok": True, "permisos": permisos_lista})

@app.route('/api/analizar', methods=['POST'])
def api_analizar():
    data = request.get_json()
    html_content = data.get('html', '')
    
    permisos_detectados = analizar_permisos_html(html_content)
    
    permisos_completos = []
    for key, value in ALL_PERMISSIONS.items():
        categoria = "Otros"
        if "LOCATION" in key or "GPS" in key:
            categoria = "Ubicación"
        elif "STORAGE" in key or "MEDIA" in key or "EXTERNAL" in key:
            categoria = "Almacenamiento"
        elif "CAMERA" in key:
            categoria = "Cámara"
        elif "AUDIO" in key or "MICROPHONE" in key or "RECORD" in key:
            categoria = "Micrófono/Audio"
        elif "NOTIFICATION" in key:
            categoria = "Notificaciones"
        elif "FOREGROUND" in key or "SERVICE" in key:
            categoria = "Servicios"
        elif "WIFI" in key or "NETWORK" in key:
            categoria = "Red"
        elif "VIBRATE" in key or "WAKE" in key:
            categoria = "Sistema"
        elif "DOWNLOAD" in key:
            categoria = "Descargas"
        
        es_detectado = key in permisos_detectados
        es_esencial = key in DEFAULT_PERMISSIONS
        
        permisos_completos.append({
            "id": key,
            "nombre": key,
            "permiso": value,
            "categoria": categoria,
            "detectado": es_detectado,
            "es_esencial": es_esencial,
            "seleccionado": es_detectado or es_esencial
        })
    
    permisos_completos.sort(key=lambda x: (not x["detectado"], not x["es_esencial"], x["categoria"], x["nombre"]))
    
    return jsonify({
        "ok": True,
        "permisos": permisos_completos,
        "detectados": permisos_detectados,
        "total_detectados": len(permisos_detectados)
    })

@app.route('/prepare', methods=['POST'])
def prepare():
    global pending_file_content, chosen_app_name, pending_icon_base64, selected_permissions
    data = request.get_json()
    
    raw_content = data.get('content', '')
    chosen_app_name = data.get('appName', 'MiAppHTML')
    pending_icon_base64 = data.get('iconBase64', None)
    selected_permissions = data.get('permissions', DEFAULT_PERMISSIONS.copy())
    
    # Inyección Android
    inyeccion_android = """
    <script>
    (function() {
        console.log('📱 Inicializando modo Android...');
        var originalFetch = window.fetch;
        var maxIntentos = 3;
        
        window.fetch = function(url, options) {
            if (typeof url === 'string' && url.includes('/api/')) {
                console.log('📡 Fetch API:', url);
                
                if (url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
                    url = url.replace('http://', 'https://');
                }
                
                var newOptions = options || {};
                newOptions.headers = newOptions.headers || {};
                newOptions.headers['Content-Type'] = 'application/json';
                newOptions.headers['Accept'] = 'application/json';
                newOptions.mode = 'cors';
                newOptions.credentials = 'same-origin';
                
                function fetchWithTimeout(timeoutMs) {
                    return new Promise(function(resolve, reject) {
                        var timeoutId = setTimeout(function() {
                            reject(new Error('Timeout de conexión'));
                        }, timeoutMs);
                        
                        originalFetch(url, newOptions)
                            .then(function(response) {
                                clearTimeout(timeoutId);
                                resolve(response);
                            })
                            .catch(function(error) {
                                clearTimeout(timeoutId);
                                reject(error);
                            });
                    });
                }
                
                return new Promise(function(resolve, reject) {
                    function intentar(intento) {
                        console.log('📤 Intento ' + intento + ' de ' + maxIntentos);
                        fetchWithTimeout(30000)
                            .then(function(response) {
                                console.log('✅ Fetch exitoso en intento ' + intento);
                                resolve(response);
                            })
                            .catch(function(error) {
                                console.log('❌ Error intento ' + intento + ':', error.message);
                                if (intento < maxIntentos) {
                                    setTimeout(function() { intentar(intento + 1); }, 2000);
                                } else {
                                    reject(error);
                                }
                            });
                    }
                    intentar(1);
                });
            }
            return originalFetch(url, options);
        };
        
        console.log('✅ Fetch interceptado para Android');
        
        window.reconectarServidor = function() {
            var enlace = document.getElementById('enlaceMadre');
            if (enlace && enlace.value) {
                console.log('🔄 Reintentando conexión al servidor...');
                if (typeof API_URL !== 'undefined') {
                    API_URL = enlace.value.trim();
                }
                if (typeof conectarConMadre === 'function') {
                    conectarConMadre();
                }
            }
        };
        
        window.addEventListener('unhandledrejection', function(event) {
            if (event.reason && event.reason.message) {
                var msg = event.reason.message;
                if (msg.includes('Failed to fetch') || 
                    msg.includes('NetworkError') ||
                    msg.includes('Timeout')) {
                    console.log('⚠️ Error de red detectado:', msg);
                    if (typeof mostrarStatus === 'function') {
                        mostrarStatus('⚠️ Problema de red. Reintentando...', 'wait');
                    }
                    setTimeout(function() {
                        if (typeof reconectarServidor === 'function') {
                            reconectarServidor();
                        }
                    }, 2000);
                }
            }
        });
        
        console.log('✅ Inyección Android completada');
        
        document.addEventListener('click', function(e) {
            var target = e.target;
            if (target.tagName === 'INPUT' && target.type === 'file') {
                console.log('📁 Click en file input detectado');
            }
        });
        
        console.log('✅ File input listener instalado');
    })();
    </script>
    """
    
    if '</body>' in raw_content:
        raw_content = raw_content.replace('</body>', inyeccion_android + '</body>')
    else:
        raw_content = raw_content + inyeccion_android
    
    pending_file_content = raw_content
    return jsonify({"success": True})

@app.route('/stream-compile')
def stream_compile():
    global pending_file_content, chosen_app_name, pending_icon_base64, selected_permissions
    if not pending_file_content:
        return Response("data: Error: No hay archivo cargado\n\n", mimetype='text/event-stream')

    def generate():
        try:
            if not os.path.exists(GRADLE_BIN):
                error_msg = f"No se encontró Gradle en: {GRADLE_BIN}"
                print(f"\n❌ ERROR: {error_msg}\n")
                yield f"data: ERROR: ❌ {error_msg}\n\n"
                return

            package_name = sanitizar_package_name(chosen_app_name)
            print(f"📦 Package name generado: {package_name}")

            project_dir = os.path.join(BASE_DIR, 'android_build_env')
            app_dir = os.path.join(project_dir, 'app')
            assets_dir = os.path.join(app_dir, "src", "main", "assets")
            
            package_path = package_name.replace('.', os.sep)
            java_dir = os.path.join(app_dir, "src", "main", "java", package_path)
            
            manifest_dir = os.path.join(app_dir, "src", "main")
            res_dir = os.path.join(app_dir, "src", "main", "res")
            xml_dir = os.path.join(res_dir, "xml")
            
            yield "data: [1/6] Preparando entorno de construcción...\n\n"
            print("\n📱 INICIANDO COMPILACIÓN...")
            print(f"📋 Nombre: {chosen_app_name}")
            print(f"📦 Package: {package_name}")
            print(f"📋 Permisos seleccionados: {len(selected_permissions)}")
            
            if os.path.exists(project_dir):
                shutil.rmtree(project_dir)
                
            os.makedirs(assets_dir, exist_ok=True)
            os.makedirs(java_dir, exist_ok=True)
            os.makedirs(xml_dir, exist_ok=True)
            
            yield "data: [2/6] Generando iconos...\n\n"
            print("🖼️ Generando iconos...")
            
            mipmaps = ['mipmap', 'mipmap-hdpi', 'mipmap-mdpi', 'mipmap-xhdpi', 'mipmap-xxhdpi', 'mipmap-xxxhdpi']
            icon_data = None
            
            if pending_icon_base64:
                try:
                    icon_data = base64.b64decode(pending_icon_base64)
                except Exception as e:
                    print(f"⚠️ Error decodificando icono: {e}")
                    icon_data = None
            
            if not icon_data:
                pixel_transparent_b64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
                icon_data = base64.b64decode(pixel_transparent_b64)
            
            for folder in mipmaps:
                folder_path = os.path.join(res_dir, folder)
                os.makedirs(folder_path, exist_ok=True)
                with open(os.path.join(folder_path, "ic_launcher.png"), "wb") as f:
                    f.write(icon_data)
                with open(os.path.join(folder_path, "ic_launcher_round.png"), "wb") as f:
                    f.write(icon_data)

            yield "data: [3/6] Generando archivos de código...\n\n"
            print("📝 Generando archivos de código...")
            
            permisos_unicos = list(set(selected_permissions))
            
            java_template = generar_java_template(permisos_unicos, package_name)
            manifest_template = generar_manifest(permisos_unicos, chosen_app_name, package_name)
            build_gradle_app = generar_build_gradle_app(package_name)
            
            with open(os.path.join(assets_dir, 'index.html'), 'w', encoding='utf-8') as f:
                f.write(pending_file_content)
            print("✅ index.html guardado")
            
            with open(os.path.join(java_dir, "MainActivity.java"), "w", encoding="utf-8") as f: 
                f.write(java_template)
            print(f"✅ MainActivity.java guardado en: {java_dir}")
            
            with open(os.path.join(manifest_dir, "AndroidManifest.xml"), "w", encoding="utf-8") as f: 
                f.write(manifest_template)
            print("✅ AndroidManifest.xml guardado")
            
            with open(os.path.join(xml_dir, "network_security_config.xml"), "w", encoding="utf-8") as f:
                f.write(NETWORK_SECURITY_CONFIG)
            print("✅ network_security_config.xml guardado")
            
            with open(os.path.join(xml_dir, "file_paths.xml"), "w", encoding="utf-8") as f:
                f.write(FILE_PATHS_XML)
            print("✅ file_paths.xml guardado")
            
            with open(os.path.join(project_dir, "build.gradle"), "w", encoding="utf-8") as f: 
                f.write(BUILD_GRADLE_ROOT)
            print("✅ build.gradle (root) guardado")
            
            with open(os.path.join(project_dir, "settings.gradle"), "w", encoding="utf-8") as f: 
                f.write(SETTINGS_GRADLE)
            print("✅ settings.gradle guardado")
            
            with open(os.path.join(app_dir, "build.gradle"), "w", encoding="utf-8") as f: 
                f.write(build_gradle_app)
            print("✅ build.gradle (app) guardado")
            
            with open(os.path.join(project_dir, "gradle.properties"), "w", encoding="utf-8") as f: 
                f.write(GRADLE_PROPERTIES)
            print("✅ gradle.properties guardado")
            
            yield "data: [4/6] Configurando variables de entorno...\n\n"
            print("🔧 Configurando variables de entorno...")
            
            env = os.environ.copy()
            
            # 1. USAR JDK PORTABLE
            if JDK_PORTABLE and os.path.exists(JDK_PORTABLE):
                jdk_home = JDK_PORTABLE
                env["JAVA_HOME"] = jdk_home
                env["PATH"] = os.path.join(jdk_home, "bin") + os.pathsep + env["PATH"]
                print(f"✅ Usando JDK PORTABLE: {jdk_home}")
                
                java_exe = os.path.join(jdk_home, "bin", "java.exe")
                if os.path.exists(java_exe):
                    print(f"✅ java.exe encontrado en: {java_exe}")
                else:
                    print(f"⚠️ java.exe NO encontrado en: {java_exe}")
            else:
                # FALLBACK: Intentar usar JDK de Android Studio
                studio_jdk = "C:\\Program Files\\Android\\Android Studio\\jbr"
                if os.path.exists(studio_jdk):
                    env["JAVA_HOME"] = studio_jdk
                    env["PATH"] = os.path.join(studio_jdk, "bin") + os.pathsep + env["PATH"]
                    print(f"✅ JAVA_HOME: {studio_jdk}")
                else:
                    if "JAVA_HOME" in os.environ:
                        env["JAVA_HOME"] = os.environ["JAVA_HOME"]
                        print(f"✅ Usando JAVA_HOME del sistema: {os.environ['JAVA_HOME']}")
                    else:
                        print("⚠️ No se encontró ningún JDK")
                        yield "data: ERROR: ❌ No se encontró JDK en el sistema\n\n"
                        return

            # 2. CONFIGURAR ANDROID SDK PORTABLE
            android_sdk_portable = os.path.join(BASE_DIR, "android-sdk")
            print(f"🔍 Buscando SDK en: {android_sdk_portable}")

            if os.path.exists(android_sdk_portable):
                # Verificar que tiene las herramientas necesarias
                plataformas = os.path.join(android_sdk_portable, "platforms")
                build_tools = os.path.join(android_sdk_portable, "build-tools")
                
                if os.path.exists(plataformas) and os.path.exists(build_tools):
                    env["ANDROID_HOME"] = android_sdk_portable
                    env["ANDROID_SDK_ROOT"] = android_sdk_portable
                    print(f"✅ Usando ANDROID SDK PORTABLE: {android_sdk_portable}")
                    print(f"   📂 Platforms: {plataformas}")
                    print(f"   📂 Build-tools: {build_tools}")
                    
                    # Crear local.properties para Gradle (CORREGIDO)
                    local_properties_path = os.path.join(project_dir, "local.properties")
                    # Usar ruta con barras normales (/) en lugar de backslashes
                    sdk_path = android_sdk_portable.replace('\\', '/')
                    with open(local_properties_path, "w", encoding="utf-8") as f:
                        f.write(f"sdk.dir={sdk_path}\n")
                    print(f"✅ local.properties creado en: {local_properties_path}")
                    print(f"   📝 sdk.dir={sdk_path}")
                else:
                    print("⚠️ SDK portable encontrado pero faltan herramientas")
                    print(f"   Platforms existe: {os.path.exists(plataformas)}")
                    print(f"   Build-tools existe: {os.path.exists(build_tools)}")
                    yield "data: ⚠️ Faltan herramientas en el SDK portable\n\n"
                    yield "data: 📌 Ejecuta en CMD:\n"
                    yield "data:    cd android-sdk\\cmdline-tools\\latest\\bin\n"
                    yield "data:    sdkmanager 'platform-tools' 'platforms;android-34' 'build-tools;34.0.0'\n\n"
            else:
                print(f"⚠️ No se encontró SDK portable en: {android_sdk_portable}")
                # Intentar usar el SDK del sistema
                android_home = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Android", "Sdk")
                if os.path.exists(android_home):
                    env["ANDROID_HOME"] = android_home
                    env["ANDROID_SDK_ROOT"] = android_home
                    print(f"✅ ANDROID_HOME (sistema): {android_home}")
                else:
                    print("⚠️ No se encontró Android SDK en el sistema")
                    yield "data: ERROR: ❌ No se encontró Android SDK\n\n"
                    yield "data: 📌 Asegúrate de tener android-sdk en la raíz del proyecto\n\n"
                    return

            # Mostrar información de las variables
            print(f"📋 JAVA_HOME configurado: {env.get('JAVA_HOME', 'No configurado')}")
            print(f"📋 ANDROID_HOME configurado: {env.get('ANDROID_HOME', 'No configurado')}")

            yield f"data: [5/6] Compilando '{chosen_app_name}' con {len(permisos_unicos)} permisos...\n\n"
            print(f"\n🔨 Iniciando compilación con {len(permisos_unicos)} permisos...")
            print(f"📂 Directorio: {project_dir}")
            print(f"📦 Package: {package_name}")
            
            cmd = f'"{GRADLE_BIN}" clean assembleDebug'
            print(f"📝 Comando: {cmd}")
            
            process = subprocess.Popen(
                cmd, shell=True, cwd=project_dir, env=env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
            )
            
            output_lines = []
            error_detected = False
            
            for line in process.stdout:
                clean_line = line.strip()
                if clean_line:
                    if "ERROR" in clean_line or "FAILURE" in clean_line or "Exception" in clean_line:
                        error_detected = True
                        print(f"❌ {clean_line}")
                        yield f"data: ❌ {clean_line}\n\n"
                    elif "BUILD SUCCESSFUL" in clean_line:
                        print(f"✅ {clean_line}")
                    else:
                        print(f"   {clean_line}")
                    
                    if clean_line:
                        yield f"data: {clean_line}\n\n"
                    
                    output_lines.append(clean_line)

            process.wait()
            
            if process.returncode == 0 and not error_detected:
                print("\n✅ COMPILACIÓN EXITOSA!")
                
                apk_generated = os.path.join(app_dir, "build", "outputs", "apk", "debug", "app-debug.apk")
                if os.path.exists(apk_generated):
                    output_folder = os.path.join(BASE_DIR, "apks_generados")
                    os.makedirs(output_folder, exist_ok=True)
                    
                    safe_name = sanitize_filename(chosen_app_name)
                    final_apk = os.path.join(output_folder, f"{safe_name}.apk")
                    
                    shutil.copy(apk_generated, final_apk)
                    print(f"✅ APK copiada a: {final_apk}")
                    
                    source_code_folder = os.path.join(output_folder, safe_name)
                    if os.path.exists(source_code_folder):
                        shutil.rmtree(source_code_folder)
                    shutil.copytree(project_dir, source_code_folder)
                    
                    txt_folder = os.path.join(source_code_folder, f"{safe_name}_txt")
                    os.makedirs(txt_folder, exist_ok=True)
                    
                    files_to_txt = {
                        os.path.join(java_dir, "MainActivity.java"): "MainActivity.txt",
                        os.path.join(manifest_dir, "AndroidManifest.xml"): "AndroidManifest.txt",
                        os.path.join(assets_dir, "index.html"): "index.txt",
                        os.path.join(project_dir, "build.gradle"): "build_root.txt",
                        os.path.join(app_dir, "build.gradle"): "build_app.txt",
                        os.path.join(project_dir, "settings.gradle"): "settings.txt",
                        os.path.join(project_dir, "gradle.properties"): "gradle_properties.txt",
                        os.path.join(xml_dir, "network_security_config.xml"): "network_security_config.txt",
                        os.path.join(xml_dir, "file_paths.xml"): "file_paths.txt"
                    }
                    
                    for src_file, dest_txt_name in files_to_txt.items():
                        if os.path.exists(src_file):
                            shutil.copy(src_file, os.path.join(txt_folder, dest_txt_name))
                    
                    yield f"data: SUCCESS: ✅ APK generada en: apks_generados/{safe_name}.apk\n\n"
                    yield f"data: SUCCESS: ✅ Código fuente en: apks_generados/{safe_name}/\n\n"
                    yield f"data: SUCCESS: 📦 Package: {package_name}\n\n"
                    print(f"✅ Código fuente guardado en: {source_code_folder}")
                else:
                    error_msg = "No se encontró el archivo APK generado"
                    print(f"❌ ERROR: {error_msg}")
                    yield f"data: ERROR: ❌ {error_msg}\n\n"
            else:
                print("\n❌ COMPILACIÓN FALLIDA!")
                print(f"Código de salida: {process.returncode}")
                
                error_summary = []
                for line in output_lines:
                    if "ERROR" in line or "FAILURE" in line or "Exception" in line:
                        error_summary.append(line)
                
                if error_summary:
                    print("\n📋 RESUMEN DE ERRORES:")
                    for err in error_summary[:10]:
                        print(f"   ❌ {err}")
                    
                    yield f"data: ERROR: ❌ La compilación falló. Errores detectados:\n\n"
                    for err in error_summary[:5]:
                        yield f"data: ❌ {err}\n\n"
                else:
                    yield "data: ERROR: ❌ La compilación falló sin errores específicos. Revisa los logs.\n\n"
                
                yield "data: ERROR: ❌ La compilación falló\n\n"
                
        except Exception as e:
            error_msg = str(e)
            print(f"\n❌ ERROR EXCEPCIÓN: {error_msg}")
            import traceback
            traceback.print_exc()
            yield f"data: ERROR: ❌ {error_msg}\n\n"

    return Response(generate(), mimetype='text/event-stream')

if __name__ == '__main__':
    FlaskUI(
        app=app,
        server="flask",
        width=650,
        height=750
    ).run()