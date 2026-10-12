package dev.daemondoctor

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import dev.daemondoctor.ui.DaemonDoctorTheme
import dev.daemondoctor.ui.DoctorApp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            DaemonDoctorTheme {
                DoctorApp()
            }
        }
    }
}
