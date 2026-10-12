package dev.daemondoctor.key

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import dev.daemondoctor.core.PhoneSigner
import dev.daemondoctor.core.SoftwareSigner
import dev.daemondoctor.core.loadOrCreateSeed
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature

private const val ALIAS = "daemon-doctor-phone"
private const val SEED_FILE = "phone-ed25519.seed"

/** Uses the Android Keystore when Ed25519 is available, otherwise an app-private seed. */
fun openSigner(context: Context): PhoneSigner {
    try {
        return KeystoreSigner()
    } catch (_: Exception) {
        val seed = loadOrCreateSeed(
            read = {
                try {
                    context.openFileInput(SEED_FILE).use { it.readBytes() }
                } catch (_: Exception) {
                    null
                }
            },
            write = { bytes ->
                context.openFileOutput(SEED_FILE, Context.MODE_PRIVATE).use { it.write(bytes) }
            },
        )
        return SoftwareSigner(seed)
    }
}

private class KeystoreSigner : PhoneSigner {
    override val backend: String = "android-keystore"
    override val publicKey: ByteArray

    init {
        val ks = keyStore()
        if (!ks.containsAlias(ALIAS)) {
            val generator = KeyPairGenerator.getInstance("Ed25519", "AndroidKeyStore")
            val spec = KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            ).build()
            generator.initialize(spec)
            generator.generateKeyPair()
        }
        publicKey = rawPublic(keyStore())
    }

    override fun sign(message: ByteArray): ByteArray {
        val entry = keyStore().getEntry(ALIAS, null) as KeyStore.PrivateKeyEntry
        val signature = Signature.getInstance("Ed25519")
        signature.initSign(entry.privateKey)
        signature.update(message)
        return signature.sign()
    }
}

private fun keyStore(): KeyStore {
    return KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
}

private fun rawPublic(ks: KeyStore): ByteArray {
    val entry = ks.getEntry(ALIAS, null) as KeyStore.PrivateKeyEntry
    val encoded = entry.certificate.publicKey.encoded
    check(encoded.size >= 32) { "keystore public key" }
    return encoded.copyOfRange(encoded.size - 32, encoded.size)
}
