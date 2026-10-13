package dev.daemondoctor.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class CoreTest {
    @Test
    fun relaunchIsAllowlistedWithoutAcceptingCommandText() {
        val page = """{"events":[{"id":4,"kind":"alerts","body":{"alert_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","service_id":"example-app","service_name":"Example App","kind":"missing_flags","message":"Required settings are missing.","actions":["relaunch","relaunch; touch marker"]}}]}"""
        val event = parseEvents(page).single()
        val alert = requireNotNull(alertFromRelay(event.body, 1_700_000_000))
        assertEquals(listOf("relaunch"), alert.actions)
        assertEquals("relaunch", fixIdFor(alert, AlertButton.Fix))
        assertEquals(listOf(AlertButton.Fix, AlertButton.Ignore, AlertButton.Details), buttonsFor(alert))
        assertEquals(listOf(AlertButton.Ignore, AlertButton.Details), buttonsFor(alert.copy(actions = listOf("relaunch; touch marker"))))
        val approval = Approval("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "relaunch", "cccccccccccccccccccccccccccccccc", 1_700_000_100L, ByteArray(32), ByteArray(64))
        assertNull(approvalShapeError(approval))
        assertEquals("wrong_fix", approvalShapeError(approval.copy(fixId = "relaunch; touch marker")))
    }

    @Test
    fun relaunchFixButtonPostsSignedApproval() {
        val http = RecordingHttp()
        val signer = SoftwareSigner(ByteArray(32) { 9 })
        val session = Session(signer, http) { 1_700_000_000 }
        val payload = "daemon-doctor:2:0123456789abcdef0123456789abcdef:${b64Url(ByteArray(32) { 1 })}:00112233445566778899aabbccddeeff:https://relay.example.invalid"
        assertTrue(session.restore(payload))
        http.nextBody = """{"events":[{"id":4,"kind":"alerts","body":{"alert_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","service_id":"example-app","service_name":"Example App","kind":"missing_flags","message":"Required settings are missing.","actions":["relaunch"]}}]}"""
        assertNull(session.poll())
        val alert = session.snapshot().alerts.single()
        assertEquals(listOf(AlertButton.Fix, AlertButton.Ignore, AlertButton.Details), buttonsFor(alert))
        assertNull(session.press(alert.id, AlertButton.Fix))
        val post = http.calls.single { it.method == "POST" }
        assertTrue(post.url.endsWith("/v1/macs/0123456789abcdef0123456789abcdef/approvals"))
        val sent = Json.parseToJsonElement(requireNotNull(post.body)).jsonObject
        assertFalse(jsonHasCommand(sent))
        assertEquals("relaunch", sent.string("fix_id"))
        assertEquals(alert.id, sent.string("alert_id"))
        val approval = Approval(
            macId = sent.string("mac_id"),
            alertId = sent.string("alert_id"),
            fixId = sent.string("fix_id"),
            nonce = sent.string("nonce"),
            expiresUnix = sent.string("expires_unix").toLong(),
            publicKey = b64UrlDecode(sent.string("public_key")),
            signature = b64UrlDecode(sent.string("signature")),
        )
        assertNull(approvalShapeError(approval))
        assertEquals(1_700_000_000 + APPROVAL_TTL_SECONDS, approval.expiresUnix)
        assertTrue(verifyEd25519(signer.publicKey, canonicalBytes(approval), approval.signature))
        assertTrue(session.snapshot().alerts.isEmpty())
        assertEquals("Sent relaunch", session.snapshot().history.single().outcome)
    }

    @Test
    fun pairingProofMatchesTheMacWithoutSendingSecret() {
        val vector = Json.parseToJsonElement(File("../../testdata/pairing-vector.json").readText()).jsonObject
        val payload = "daemon-doctor:2:${vector.string("mac_id")}:${vector.string("mac_public_key")}:${vector.string("secret")}:https://your-relay.example.workers.dev"
        val parsed = requireNotNull(parsePairingPayload(payload))
        val key = b64UrlDecode(vector.string("phone_public_key"))
        val body = pairingBody(parsed, key)
        val registration = Json.parseToJsonElement(body).jsonObject
        assertEquals(setOf("pairing_id", "public_key", "proof"), registration.keys)
        assertEquals(vector.string("pairing_id"), registration.string("pairing_id"))
        assertEquals(vector.string("proof"), registration.string("proof"))
        assertFalse(body.contains(parsed.code))
        val otherKey = key.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val changed = Json.parseToJsonElement(pairingBody(parsed, otherKey)).jsonObject
        assertFalse(registration.string("proof") == changed.string("proof"))
        val otherMac = parsed.copy(macId = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        assertFalse(body == pairingBody(otherMac, key))
        assertNull(parsePairingPayload(payload.replace("daemon-doctor:2:", "daemon-doctor:1:")))
    }

    @Test
    fun crossLanguageVectors() {
        val file = File("../../testdata/approval-vectors.json")
        val root = Json.parseToJsonElement(file.readText()).jsonObject
        val vectors = root.getValue("vectors").jsonArray
        assertTrue(vectors.size >= 2)
        var sawGo = false
        var sawJdk = false
        for (element in vectors) {
            val item = element.jsonObject
            val seed = item.string("seed_hex").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val signer = SoftwareSigner(seed)
            assertEquals(item.string("public_key_b64"), b64Url(signer.publicKey))
            val approval = Approval(
                macId = item.string("mac_id"),
                alertId = item.string("alert_id"),
                fixId = item.string("fix_id"),
                nonce = item.string("nonce"),
                expiresUnix = item.string("expires_unix").toLong(),
                publicKey = signer.publicKey,
                signature = b64UrlDecode(item.string("signature_b64")),
            )
            assertTrue(verifyEd25519(signer.publicKey, canonicalBytes(approval), approval.signature))
            val resigned = signApproval(
                signer,
                approval.macId,
                approval.alertId,
                approval.fixId,
                approval.nonce,
                approval.expiresUnix,
            )
            assertEquals(item.string("signature_b64"), b64Url(resigned.signature))
            when (item.string("produced_by")) {
                "go" -> sawGo = true
                "jdk" -> sawJdk = true
            }
        }
        assertTrue(sawGo)
        assertTrue(sawJdk)
    }

    @Test
    fun expiryWindowMatchesTheMac() {
        val now = 1_700_000_000L
        assertEquals("expired", expiryRejection(now - 11 * 60, now))
        assertNull(expiryRejection(now + APPROVAL_TTL_SECONDS, now))
        assertEquals("window", expiryRejection(now + APPROVAL_TTL_SECONDS + CLOCK_SKEW_SECONDS + 1, now))
    }

    @Test
    fun pairingPayloadKeepsRelayColons() {
        val payload = "daemon-doctor:2:0123456789abcdef0123456789abcdef:ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ:00112233445566778899aabbccddeeff:https://relay.example.invalid/mailbox"
        val parsed = parsePairingPayload(payload)
        requireNotNull(parsed)
        assertEquals("https://relay.example.invalid/mailbox", parsed.relayUrl)
        assertEquals("0123456789abcdef0123456789abcdef", parsed.macId)
        assertNull(parsePairingPayload("not-a-code"))
    }

    @Test
    fun relayDropsActionsOutsideTheAllowlist() {
        val page = """
            {"events":[{"id":4,"kind":"alerts","body":{"alert_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","service_id":"example-desktop-app","service_name":"Example Desktop App","kind":"down","message":"Example Desktop App has stopped. It is not running.","actions":["restart","restart; touch marker"],"process":"example-desktop-app"}}]}
        """.trimIndent()
        val events = parseEvents(page)
        assertEquals(1, events.size)
        val alert = alertFromRelay(events[0].body, 1_700_000_000)
        requireNotNull(alert)
        assertEquals(listOf("restart"), alert.actions)
        assertFalse(jsonHasCommand(events[0].body))
        assertEquals(listOf(AlertButton.Fix, AlertButton.Ignore, AlertButton.Details), buttonsFor(alert))
    }

    @Test
    fun kickstartStaysOnTheAllowlist() {
        val page = """
            {"events":[{"id":5,"kind":"alerts","body":{"alert_id":"cccccccccccccccccccccccccccccccc","service_id":"example-health","service_name":"Example Health","kind":"launchd_job","message":"Example Health has not had a successful run in the last 10 minutes.","actions":["launchctl_kickstart","launchctl kickstart -k gui/501/evil"],"process":""}}]}
        """.trimIndent()
        val alert = alertFromRelay(parseEvents(page).single().body, 1_700_000_000)
        requireNotNull(alert)
        assertEquals(listOf("launchctl_kickstart"), alert.actions)
        assertEquals("launchctl_kickstart", fixIdFor(alert, AlertButton.Fix))
        assertEquals(listOf(AlertButton.Fix, AlertButton.Ignore, AlertButton.Details), buttonsFor(alert))
    }

    @Test
    fun demoModeSignsWithoutCallingTheRelay() {
        val http = RecordingHttp()
        val session = Session(SoftwareSigner(ByteArray(32) { 7 }), http) { 1_700_000_000 }
        val snap = session.snapshot()
        assertTrue(snap.demo)
        assertEquals(4, snap.alerts.size)
        assertEquals(3, snap.services.size)
        assertEquals(listOf(AlertButton.Stop, AlertButton.Ignore, AlertButton.Details), buttonsFor(snap.alerts[2]))
        assertNull(session.press(snap.alerts[0].id, AlertButton.Fix))
        assertTrue(http.calls.isEmpty())
        val after = session.snapshot()
        assertEquals(3, after.alerts.size)
        assertEquals("Signed restart in demo mode", after.history.single().outcome)
        assertNull(session.press("44444444444444444444444444444444", AlertButton.Ignore))
        assertEquals("Ignored", session.snapshot().history.last().outcome)
    }

    @Test
    fun liveApprovalIsPostedAndVerified() {
        val http = RecordingHttp()
        val signer = SoftwareSigner(ByteArray(32) { 9 })
        val session = Session(signer, http) { 1_700_000_000 }
        session.setDemo(false)
        val payload = "daemon-doctor:2:0123456789abcdef0123456789abcdef:${b64Url(ByteArray(32) { 1 })}:00112233445566778899aabbccddeeff:https://relay.example.invalid"
        assertNull(session.pair(payload))
        assertEquals("POST", http.calls.single().method)
        assertTrue(http.calls.single().url.endsWith("/v1/macs/0123456789abcdef0123456789abcdef/pairing"))
        assertFalse(http.calls.single().body!!.contains("00112233445566778899aabbccddeeff"))
        assertTrue(http.calls.single().body!!.contains("\"proof\""))
        http.calls.clear()
        http.nextBody = """
            {"events":[{"id":1,"kind":"alerts","body":{"alert_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","service_id":"syncthing","service_name":"Syncthing","kind":"down","message":"Syncthing has stopped. It is not running.","actions":["restart","stop"],"process":"syncthing"}}]}
        """.trimIndent()
        assertNull(session.poll())
        val alert = session.snapshot().alerts.single()
        assertEquals(listOf(AlertButton.Fix, AlertButton.Stop, AlertButton.Ignore, AlertButton.Details), buttonsFor(alert))
        assertNull(session.press(alert.id, AlertButton.Stop))
        val post = http.calls.last { it.method == "POST" }
        assertTrue(post.url.endsWith("/approvals"))
        assertFalse(post.body!!.contains("command"))
        val sent = Json.parseToJsonElement(post.body!!).jsonObject
        assertEquals("stop", sent.string("fix_id"))
        assertEquals("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", sent.string("alert_id"))
        val signature = b64UrlDecode(sent.string("signature"))
        val approval = Approval(
            macId = sent.string("mac_id"),
            alertId = sent.string("alert_id"),
            fixId = sent.string("fix_id"),
            nonce = sent.string("nonce"),
            expiresUnix = sent.string("expires_unix").toLong(),
            publicKey = b64UrlDecode(sent.string("public_key")),
            signature = signature,
        )
        assertEquals(1_700_000_000 + APPROVAL_TTL_SECONDS, approval.expiresUnix)
        assertTrue(verifyEd25519(signer.publicKey, canonicalBytes(approval), signature))
        assertEquals("Sent stop", session.snapshot().history.single().outcome)
        assertEquals("using the machine", rowStatus("cpu_hog"))
    }

    @Test
    fun leavingDemoDropsFakeAlerts() {
        val http = RecordingHttp()
        val session = Session(SoftwareSigner(ByteArray(32) { 3 }), http) { 1_700_000_000 }
        val payload = "daemon-doctor:2:0123456789abcdef0123456789abcdef:${b64Url(ByteArray(32) { 1 })}:00112233445566778899aabbccddeeff:https://relay.example.invalid"
        assertTrue(session.restore(payload))
        assertFalse(session.snapshot().demo)
        assertTrue(session.snapshot().paired)
        assertTrue(session.snapshot().alerts.isEmpty())
        session.setDemo(true)
        assertEquals(4, session.snapshot().alerts.size)
        session.setDemo(false)
        assertTrue(session.snapshot().alerts.isEmpty())
        assertTrue(http.calls.isEmpty())
    }

    @Test
    fun seedFileIsReused() {
        var stored: ByteArray? = null
        val first = loadOrCreateSeed({ stored }, { stored = it })
        val second = loadOrCreateSeed({ stored }, { stored = it })
        assertTrue(first.contentEquals(second))
        assertEquals(32, first.size)
    }

    @Test
    fun keystoreSelection() {
        assertEquals(KeyBackend.KEYSTORE, selectBackend(true))
        assertEquals(KeyBackend.APP_PRIVATE, selectBackend(false))
    }
}

private fun kotlinx.serialization.json.JsonObject.string(key: String): String = getValue(key).jsonPrimitive.content

private class RecordingHttp : Http {
    val calls = mutableListOf<Call>()
    var nextBody: String = """{"stored":true}"""

    override fun send(method: String, url: String, body: String?): HttpResponse {
        calls.add(Call(method, url, body))
        val response = if (method == "GET") nextBody else """{"stored":true}"""
        return HttpResponse(200, response)
    }
}

private data class Call(val method: String, val url: String, val body: String?)

private fun rowStatus(kind: String): String {
    val alert = Alert("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "unwatched", "ExampleTool", kind, "message", listOf("stop"), "ExampleTool", 0)
    return when (alert.kind) {
        "cpu_hog", "memory_hog" -> "using the machine"
        else -> alert.kind
    }
}
