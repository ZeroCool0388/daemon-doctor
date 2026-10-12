package dev.daemondoctor.ui

import android.Manifest
import android.app.Application
import android.content.Context
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.mlkit.vision.MlKitAnalyzer
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import dev.daemondoctor.core.Alert
import dev.daemondoctor.core.AlertButton
import dev.daemondoctor.core.HistoryEntry
import dev.daemondoctor.core.ServiceRow
import dev.daemondoctor.core.Session
import dev.daemondoctor.core.Snapshot
import dev.daemondoctor.core.buttonsFor
import dev.daemondoctor.key.openSigner
import dev.daemondoctor.net.UrlHttp
import dev.daemondoctor.push.PushHub
import dev.daemondoctor.push.firebaseConfigured
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

private const val PREFS = "daemon-doctor"
private const val PREF_PAIRING = "pairing"
private const val POLL_EVERY_MS = 15_000L

class DoctorViewModel(app: Application) : AndroidViewModel(app) {
    private val prefs = app.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    private val session = Session(openSigner(app), UrlHttp()) {
        System.currentTimeMillis() / 1000
    }
    private val work = Dispatchers.IO.limitedParallelism(1)
    private val snapshotState = kotlinx.coroutines.flow.MutableStateFlow(session.snapshot())
    val state = snapshotState

    init {
        prefs.getString(PREF_PAIRING, null)?.let { saved ->
            if (session.restore(saved)) {
                publish()
            }
        }
        if (firebaseConfigured(app)) {
            PushHub.onWake = {
                viewModelScope.launch(work) {
                    session.poll()
                    publish()
                }
            }
        }
        viewModelScope.launch(work) {
            while (isActive) {
                session.poll()
                publish()
                delay(POLL_EVERY_MS)
            }
        }
    }

    fun setDemo(on: Boolean) {
        viewModelScope.launch(work) {
            session.setDemo(on)
            publish()
        }
    }

    suspend fun pair(payload: String): String? = withContext(work) {
        val trimmed = payload.trim()
        val err = session.pair(trimmed)
        if (err == null) {
            prefs.edit().putString(PREF_PAIRING, trimmed).apply()
        }
        publish()
        err
    }

    suspend fun press(alertId: String, button: AlertButton): String? = withContext(work) {
        val err = session.press(alertId, button)
        publish()
        err
    }

    fun findAlert(id: String): Alert? {
        val snap = snapshotState.value
        return snap.alerts.find { it.id == id } ?: snap.history.find { it.alert.id == id }?.alert
    }

    fun historyOutcome(id: String): String? {
        return snapshotState.value.history.find { it.alert.id == id }?.outcome
    }

    override fun onCleared() {
        PushHub.onWake = null
    }

    private fun publish() {
        snapshotState.value = session.snapshot()
    }
}

@Composable
fun DaemonDoctorTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = lightColorScheme()) {
        Surface(modifier = Modifier.fillMaxSize(), content = content)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DoctorApp(vm: DoctorViewModel = viewModel()) {
    val state by vm.state.collectAsStateWithLifecycle()
    val nav = rememberNavController()
    val tabs = listOf(
        Tab("alerts", "Alerts", Icons.Filled.Notifications),
        Tab("status", "Status", Icons.Filled.Info),
        Tab("history", "History", Icons.AutoMirrored.Filled.List),
        Tab("pair", "Pair", Icons.Filled.Settings),
    )
    Scaffold(
        topBar = { TopAppBar(title = { Text("Daemon Doctor") }) },
        bottomBar = {
            val current = nav.currentBackStackEntryAsState().value?.destination?.route
            NavigationBar {
                tabs.forEach { tab ->
                    val selected = current == tab.route || (tab.route == "alerts" && current?.startsWith("detail") == true)
                    NavigationBarItem(
                        selected = selected,
                        onClick = { nav.goTab(tab.route) },
                        icon = { Icon(tab.icon, contentDescription = tab.label) },
                        label = { Text(tab.label) },
                    )
                }
            }
        },
    ) { padding ->
        NavHost(
            navController = nav,
            startDestination = "alerts",
            modifier = Modifier.padding(padding),
        ) {
            composable("alerts") { AlertsScreen(state, vm, nav) }
            composable("status") { StatusScreen(state.services) }
            composable("history") { HistoryScreen(state.history, nav) }
            composable("pair") { PairScreen(state, vm) }
            composable("detail/{id}") { entry ->
                DetailScreen(
                    alert = vm.findAlert(entry.arguments?.getString("id").orEmpty()),
                    outcome = vm.historyOutcome(entry.arguments?.getString("id").orEmpty()),
                    vm = vm,
                    onBack = { nav.popBackStack() },
                )
            }
        }
    }
}

private data class Tab(
    val route: String,
    val label: String,
    val icon: androidx.compose.ui.graphics.vector.ImageVector,
)

private fun NavHostController.goTab(route: String) {
    navigate(route) {
        popUpTo(graph.findStartDestination().id) { saveState = true }
        launchSingleTop = true
        restoreState = true
    }
}

@Composable
private fun AlertsScreen(state: Snapshot, vm: DoctorViewModel, nav: NavHostController) {
    val scope = rememberCoroutineScope()
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Notice(state)
        if (state.alerts.isEmpty()) {
            Text("No alerts.")
        }
        state.alerts.forEach { alert ->
            AlertCard(alert, active = true, outcome = null, onPress = { button ->
                if (button == AlertButton.Details) {
                    nav.navigate("detail/${alert.id}")
                } else {
                    scope.launch { vm.press(alert.id, button) }
                }
            })
        }
    }
}

@Composable
private fun StatusScreen(services: List<ServiceRow>) {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Services", style = MaterialTheme.typography.titleMedium)
        if (services.isEmpty()) {
            Text("No services yet. Pair with a Mac, or turn demo mode on.")
        }
        services.forEach { row ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(row.name, fontWeight = FontWeight.SemiBold)
                    Text(row.status)
                    Text(row.detail)
                }
            }
        }
    }
}

@Composable
private fun HistoryScreen(history: List<HistoryEntry>, nav: NavHostController) {
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Alert history", style = MaterialTheme.typography.titleMedium)
        if (history.isEmpty()) {
            Text("Nothing has been ignored or signed yet.")
        }
        history.asReversed().forEach { entry ->
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text(entry.outcome, fontWeight = FontWeight.SemiBold)
                    Text(entry.alert.serviceName)
                    Text(entry.alert.message)
                    Text(formatEpoch(entry.atEpoch))
                    TextButton(onClick = { nav.navigate("detail/${entry.alert.id}") }) {
                        Text("Details")
                    }
                }
            }
        }
    }
}

@Composable
private fun DetailScreen(alert: Alert?, outcome: String?, vm: DoctorViewModel, onBack: () -> Unit) {
    val scope = rememberCoroutineScope()
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        if (alert == null) {
            Text("That alert is no longer on this phone.")
            return
        }
        Text(alert.serviceName, style = MaterialTheme.typography.titleMedium)
        Text(alert.message)
        if (alert.process.isNotEmpty()) {
            Text("Process: ${alert.process}")
        }
        Text("Kind: ${alert.kind.replace('_', ' ')}")
        if (outcome != null) {
            Text("Outcome: $outcome")
        }
        val stillActive = outcome == null
        if (stillActive) {
            ButtonRow(buttonsFor(alert)) { button ->
                if (button == AlertButton.Details) {
                    return@ButtonRow
                }
                scope.launch {
                    if (vm.press(alert.id, button) == null) {
                        onBack()
                    }
                }
            }
        }
    }
}

@Composable
private fun PairScreen(state: Snapshot, vm: DoctorViewModel) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var paste by remember { mutableStateOf("") }
    var message by remember { mutableStateOf<String?>(null) }
    var scanGeneration by remember { mutableIntStateOf(0) }
    val hasCamera = remember {
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)
    }
    var granted by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED,
        )
    }
    val launcher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {
        granted = it
    }
    LaunchedEffect(hasCamera) {
        if (hasCamera && !granted) {
            launcher.launch(Manifest.permission.CAMERA)
        }
    }
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Notice(state)
        Text(state.pairedLabel)
        Text("Key storage: ${state.keyBackend}")
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Demo mode")
            Switch(checked = state.demo, onCheckedChange = { vm.setDemo(it) })
        }
        Text("Demo mode uses built-in alerts and does not call a relay.")
        if (hasCamera && granted) {
            Text("Point the camera at the pairing code on the Mac. The picture stays on this phone.")
            key(scanGeneration) {
                QrScanner(onPayload = { payload ->
                    scope.launch { message = vm.pair(payload) ?: "Paired." }
                })
            }
            TextButton(onClick = { scanGeneration += 1 }) {
                Text("Scan again")
            }
        } else if (!hasCamera) {
            Text("This device has no camera. Paste the pairing text instead.")
        } else {
            Text("Camera permission is off. Paste the pairing text, or allow the camera and reopen this screen.")
            TextButton(onClick = { launcher.launch(Manifest.permission.CAMERA) }) {
                Text("Allow camera")
            }
        }
        OutlinedTextField(
            value = paste,
            onValueChange = { paste = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text("Pairing text") },
            minLines = 2,
        )
        Button(onClick = { scope.launch { message = vm.pair(paste) ?: "Paired." } }) {
            Text("Pair with this text")
        }
        if (message != null) {
            Text(message!!)
        }
    }
}

@Composable
private fun QrScanner(onPayload: (String) -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val previewView = remember {
        PreviewView(context).apply {
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
    }
    var handled by remember { mutableStateOf(false) }
    AndroidView(
        factory = { previewView },
        modifier = Modifier.fillMaxWidth().height(240.dp),
    )
    DisposableEffect(lifecycleOwner) {
        val future = ProcessCameraProvider.getInstance(context)
        val executor = ContextCompat.getMainExecutor(context)
        val listener = Runnable {
            try {
                val provider = future.get()
                val preview = Preview.Builder().build().also {
                    it.surfaceProvider = previewView.surfaceProvider
                }
                val scanner = BarcodeScanning.getClient()
                val analysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                analysis.setAnalyzer(
                    executor,
                    MlKitAnalyzer(
                        listOf(scanner),
                        ImageAnalysis.COORDINATE_SYSTEM_ORIGINAL,
                        executor,
                    ) { result ->
                        val value = result.getValue(scanner)?.firstOrNull { it.format == Barcode.FORMAT_QR_CODE }?.rawValue
                        if (value.isNullOrBlank() || handled) {
                            return@MlKitAnalyzer
                        }
                        handled = true
                        onPayload(value)
                    },
                )
                provider.unbindAll()
                provider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    analysis,
                )
            } catch (_: Exception) {
                // No camera, or the camera is busy. The paste field is the fallback.
            }
        }
        future.addListener(listener, executor)
        onDispose {
            try {
                future.get().unbindAll()
            } catch (_: Exception) {
            }
        }
    }
}

@Composable
private fun AlertCard(
    alert: Alert,
    active: Boolean,
    outcome: String?,
    onPress: (AlertButton) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(alert.serviceName, fontWeight = FontWeight.SemiBold)
            Text(alert.message)
            if (outcome != null) {
                Text(outcome)
            }
            if (active) {
                ButtonRow(buttonsFor(alert), onPress)
            }
        }
    }
}

@Composable
private fun ButtonRow(buttons: List<AlertButton>, onPress: (AlertButton) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
        buttons.forEach { button ->
            TextButton(onClick = { onPress(button) }) {
                Text(buttonLabel(button))
            }
        }
    }
}

@Composable
private fun Notice(state: Snapshot) {
    if (state.notice.isNotEmpty()) {
        Text(state.notice)
    }
}

private fun buttonLabel(button: AlertButton): String {
    return when (button) {
        AlertButton.Fix -> "Fix it"
        AlertButton.Stop -> "Stop"
        AlertButton.Ignore -> "Ignore"
        AlertButton.Details -> "Details"
    }
}

private fun formatEpoch(epoch: Long): String {
    val format = SimpleDateFormat("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.US)
    format.timeZone = TimeZone.getTimeZone("UTC")
    return format.format(Date(epoch * 1000))
}
