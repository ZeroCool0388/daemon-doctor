package dev.daemondoctor.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

data class HttpResponse(val status: Int, val body: String)

interface Http {
    fun send(method: String, url: String, body: String?): HttpResponse
}

data class RelayEvent(val id: Long, val kind: String, val body: JsonObject)

private val json = Json { ignoreUnknownKeys = true }

fun relayUrl(base: String, macId: String, box: String): String {
    return base.trimEnd('/') + "/v1/macs/" + macId + "/" + box
}

fun pairingBody(payload: PairingPayload, publicKey: ByteArray): String {
    require(publicKey.size == 32)
    val secret = payload.code.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    val pairingId = MessageDigest.getInstance("SHA-256").digest(secret)
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    val canonical = listOf(
        "daemon-doctor/pairing/v2",
        "mac_id=${payload.macId}",
        "mac_public_key=${b64Url(payload.macPublicKey)}",
        "pairing_id=$pairingId",
        "phone_public_key=${b64Url(publicKey)}",
    ).joinToString("\n")
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(secret, "HmacSHA256"))
    val proof = b64Url(mac.doFinal(canonical.toByteArray(Charsets.UTF_8)))
    return "{\"pairing_id\":${quote(pairingId)},\"public_key\":${quote(b64Url(publicKey))},\"proof\":${quote(proof)}}"
}

private fun quote(value: String): String {
    val escaped = value.replace("\\", "\\\\").replace("\"", "\\\"")
    return "\"$escaped\""
}

fun parseEvents(body: String): List<RelayEvent> {
    val root = json.parseToJsonElement(body).jsonObject
    val events = root["events"] as? JsonArray ?: return emptyList()
    return events.mapNotNull { element ->
        val obj = element.jsonObject
        val id = obj["id"]?.jsonPrimitive?.longOrNull ?: return@mapNotNull null
        val kind = obj["kind"]?.jsonPrimitive?.content ?: ""
        val payload = obj["body"]?.jsonObject ?: JsonObject(emptyMap())
        RelayEvent(id, kind, payload)
    }
}

data class PairingPayload(
    val macId: String,
    val macPublicKey: ByteArray,
    val code: String,
    val relayUrl: String,
)

fun parsePairingPayload(raw: String): PairingPayload? {
    val parts = raw.trim().split(":")
    if (parts.size < 6 || parts[0] != "daemon-doctor" || parts[1] != "2") {
        return null
    }
    if (!hexIdOk(parts[2]) || !hexIdOk(parts[4])) {
        return null
    }
    val key = try {
        b64UrlDecode(parts[3])
    } catch (_: IllegalArgumentException) {
        return null
    }
    if (key.size != 32) {
        return null
    }
    return PairingPayload(
        macId = parts[2],
        macPublicKey = key,
        code = parts[4],
        relayUrl = parts.drop(5).joinToString(":"),
    )
}

data class Alert(
    val id: String,
    val serviceId: String,
    val serviceName: String,
    val kind: String,
    val message: String,
    val actions: List<String>,
    val process: String,
    val atEpoch: Long,
)

enum class AlertButton { Fix, Stop, Ignore, Details }

fun alertFromRelay(body: JsonObject, atEpoch: Long): Alert? {
    val id = body.string("alert_id") ?: return null
    if (!hexIdOk(id)) {
        return null
    }
    val actions = (body["actions"] as? JsonArray)
        ?.mapNotNull { it.jsonPrimitive.content }
        ?.filter { it in ALLOWED_FIXES }
        ?: emptyList()
    val serviceId = body.string("service_id") ?: ""
    val serviceName = body.string("service_name") ?: serviceId
    return Alert(
        id = id,
        serviceId = serviceId,
        serviceName = serviceName.ifEmpty { serviceId },
        kind = body.string("kind") ?: "",
        message = body.string("message") ?: "",
        actions = actions,
        process = body.string("process") ?: "",
        atEpoch = atEpoch,
    )
}

private fun JsonObject.string(key: String): String? {
    val value = this[key] ?: return null
    val primitive = value.jsonPrimitive
    if (primitive.booleanOrNull != null) {
        return null
    }
    return primitive.content
}

fun buttonsFor(alert: Alert): List<AlertButton> {
    val out = mutableListOf<AlertButton>()
    if (fixIdFor(alert, AlertButton.Fix) != null) {
        out += AlertButton.Fix
    }
    if (fixIdFor(alert, AlertButton.Stop) != null) {
        out += AlertButton.Stop
    }
    out += AlertButton.Ignore
    out += AlertButton.Details
    return out
}

fun fixIdFor(alert: Alert, button: AlertButton): String? {
    val chosen = when (button) {
        AlertButton.Stop -> if ("stop" in alert.actions) "stop" else null
        AlertButton.Fix -> when {
            "restart" in alert.actions -> "restart"
            "force-restart" in alert.actions -> "force-restart"
            "relaunch" in alert.actions -> "relaunch"
            "launchctl_kickstart" in alert.actions -> "launchctl_kickstart"
            else -> null
        }
        else -> null
    }
    if (chosen == null || chosen !in ALLOWED_FIXES) {
        return null
    }
    return chosen
}

data class ServiceRow(val id: String, val name: String, val status: String, val detail: String)

data class HistoryEntry(val alert: Alert, val outcome: String, val atEpoch: Long)
