package dev.daemondoctor.core

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.SecureRandom
import java.util.Base64

/** Software Ed25519. The Android Keystore path lives in the app module. */
class SoftwareSigner(seed: ByteArray) : PhoneSigner {
    private val privateKey = Ed25519PrivateKeyParameters(seed.copyOf(), 0)

    override val backend: String = "app-private"
    override val publicKey: ByteArray = privateKey.generatePublicKey().encoded

    override fun sign(message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, privateKey)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }
}

fun verifyEd25519(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
    if (publicKey.size != 32 || signature.size != 64) {
        return false
    }
    val signer = Ed25519Signer()
    signer.init(false, Ed25519PublicKeyParameters(publicKey, 0))
    signer.update(message, 0, message.size)
    return signer.verifySignature(signature)
}

fun newSeed(): ByteArray {
    val seed = ByteArray(32)
    SecureRandom().nextBytes(seed)
    return seed
}

fun loadOrCreateSeed(read: () -> ByteArray?, write: (ByteArray) -> Unit): ByteArray {
    val existing = read()
    if (existing != null && existing.size == 32) {
        return existing
    }
    val seed = newSeed()
    write(seed)
    return seed
}

enum class KeyBackend {
    KEYSTORE,
    APP_PRIVATE,
}

fun selectBackend(keystoreEd25519: Boolean): KeyBackend {
    return if (keystoreEd25519) KeyBackend.KEYSTORE else KeyBackend.APP_PRIVATE
}

interface PhoneSigner {
    val backend: String
    val publicKey: ByteArray
    fun sign(message: ByteArray): ByteArray
}

fun b64Url(raw: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(raw)

fun b64UrlDecode(text: String): ByteArray = Base64.getUrlDecoder().decode(text)
