package dev.daemondoctor.push

import android.content.Context
import com.google.firebase.FirebaseApp
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

/** Wake hook. FCM calls it when a message arrives. Polling does not use it. */
object PushHub {
    @Volatile
    var onWake: (() -> Unit)? = null
}

class AlertFirebaseService : FirebaseMessagingService() {
    override fun onMessageReceived(message: RemoteMessage) {
        PushHub.onWake?.invoke()
    }
}

/** True only when a google-services resource was packaged with the app. */
fun firebaseConfigured(context: Context): Boolean {
    return try {
        FirebaseApp.initializeApp(context) != null
    } catch (_: Exception) {
        false
    }
}
