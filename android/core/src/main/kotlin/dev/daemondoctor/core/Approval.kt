package dev.daemondoctor.core

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

const val APPROVAL_TTL_SECONDS = 10 * 60L
const val CLOCK_SKEW_SECONDS = 60L

private val HEX_ID = Regex("^[0-9a-f]{32}$")
val ALLOWED_FIXES = setOf("stop", "restart", "force-restart", "relaunch", "launchctl_kickstart")

data class Approval(
    val macId: String,
    val alertId: String,
    val fixId: String,
    val nonce: String,
    val expiresUnix: Long,
    val publicKey: ByteArray,
    val signature: ByteArray,
)

fun canonicalBytes(approval: Approval): ByteArray {
    val text = listOf(
        "daemon-doctor/approval/v1",
        "mac_id=${approval.macId}",
        "alert_id=${approval.alertId}",
        "fix_id=${approval.fixId}",
        "nonce=${approval.nonce}",
        "expires_unix=${approval.expiresUnix}",
    ).joinToString("\n")
    return text.toByteArray(Charsets.UTF_8)
}

fun signApproval(
    signer: PhoneSigner,
    macId: String,
    alertId: String,
    fixId: String,
    nonce: String,
    expiresUnix: Long,
): Approval {
    val draft = Approval(
        macId = macId,
        alertId = alertId,
        fixId = fixId,
        nonce = nonce,
        expiresUnix = expiresUnix,
        publicKey = signer.publicKey,
        signature = ByteArray(0),
    )
    val signature = signer.sign(canonicalBytes(draft))
    return draft.copy(signature = signature)
}

/** Why an approval must not be sent. Null means the local checks passed. */
fun expiryRejection(expiresUnix: Long, nowUnix: Long): String? {
    if (expiresUnix <= nowUnix) {
        return "expired"
    }
    if (expiresUnix > nowUnix + APPROVAL_TTL_SECONDS + CLOCK_SKEW_SECONDS) {
        return "window"
    }
    return null
}

fun approvalShapeError(approval: Approval): String? {
    if (!HEX_ID.matches(approval.macId) || !HEX_ID.matches(approval.alertId) || !HEX_ID.matches(approval.nonce)) {
        return "malformed"
    }
    if (approval.fixId.isEmpty() || approval.fixId.any { it == '\n' || it == '\r' }) {
        return "malformed"
    }
    if (approval.fixId !in ALLOWED_FIXES) {
        return "wrong_fix"
    }
    if (approval.publicKey.size != 32 || approval.signature.size != 64) {
        return "malformed"
    }
    return null
}

fun approvalJson(approval: Approval): String {
    return buildJsonObject {
        put("mac_id", JsonPrimitive(approval.macId))
        put("alert_id", JsonPrimitive(approval.alertId))
        put("fix_id", JsonPrimitive(approval.fixId))
        put("nonce", JsonPrimitive(approval.nonce))
        put("expires_unix", JsonPrimitive(approval.expiresUnix))
        put("public_key", JsonPrimitive(b64Url(approval.publicKey)))
        put("signature", JsonPrimitive(b64Url(approval.signature)))
    }.toString()
}

fun randomNonce(): String {
    val raw = ByteArray(16)
    java.security.SecureRandom().nextBytes(raw)
    return raw.joinToString("") { "%02x".format(it) }
}

fun hexIdOk(value: String): Boolean = HEX_ID.matches(value)

fun jsonHasCommand(obj: JsonObject): Boolean = obj.containsKey("command")
