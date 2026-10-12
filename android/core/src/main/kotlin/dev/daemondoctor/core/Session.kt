package dev.daemondoctor.core

data class Snapshot(
    val demo: Boolean,
    val paired: Boolean,
    val pairedLabel: String,
    val keyBackend: String,
    val alerts: List<Alert>,
    val history: List<HistoryEntry>,
    val services: List<ServiceRow>,
    val notice: String,
)

class Session(
    private val signer: PhoneSigner,
    private val http: Http,
    private val now: () -> Long,
) {
    var demo: Boolean = true
        private set
    var paired: PairingPayload? = null
        private set
    private val active = mutableListOf<Alert>()
    private val history = mutableListOf<HistoryEntry>()
    private var after = 0L
    private var notice = "Demo mode is on. No relay is used."

    init {
        loadDemo()
    }

    fun snapshot(): Snapshot {
        return Snapshot(
            demo = demo,
            paired = paired != null,
            pairedLabel = paired?.let { "Paired with ${it.macId.take(8)}" } ?: "Not paired",
            keyBackend = signer.backend,
            alerts = active.toList(),
            history = history.toList(),
            services = services(),
            notice = notice,
        )
    }

    fun setDemo(on: Boolean) {
        demo = on
        if (on) {
            loadDemo()
            notice = "Demo mode is on. No relay is used."
            return
        }
        active.clear()
        notice = if (paired == null) {
            "Demo mode is off. Pair with a Mac to receive alerts."
        } else {
            "Demo mode is off."
        }
    }

    /** Remembers a pairing this phone already registered. Does not call the relay. */
    fun restore(raw: String): Boolean {
        val parsed = parsePairingPayload(raw) ?: return false
        if (parsed.relayUrl.isEmpty()) {
            return false
        }
        paired = parsed
        demo = false
        active.clear()
        notice = "Paired. Waiting for alerts."
        return true
    }

    fun loadDemo() {
        active.clear()
        active.addAll(demoAlerts())
    }

    /** Returns an error message, or null when the phone key was registered. */
    fun pair(payload: String): String? {
        val parsed = parsePairingPayload(payload) ?: return "That code is not a Daemon Doctor pairing code."
        if (parsed.relayUrl.isEmpty()) {
            return "The pairing code has no relay URL."
        }
        val response = http.send(
            "POST",
            relayUrl(parsed.relayUrl, parsed.macId, "pairing"),
            pairingBody(parsed, signer.publicKey),
        )
        if (response.status != 200) {
            return "The relay did not accept the phone key (${response.status})."
        }
        paired = parsed
        demo = false
        active.clear()
        after = 0L
        notice = "Paired. The phone key is registered."
        return null
    }

    /** Returns an error message, or null when the poll finished. */
    fun poll(): String? {
        val current = paired ?: return null
        if (demo) {
            return null
        }
        val response = http.send(
            "GET",
            relayUrl(current.relayUrl, current.macId, "alerts") + "?after=$after&limit=100",
            null,
        )
        if (response.status != 200) {
            notice = "The relay did not return alerts (${response.status})."
            return notice
        }
        val events = try {
            parseEvents(response.body)
        } catch (_: Exception) {
            notice = "The relay response was not a mailbox page."
            return notice
        }
        for (event in events) {
            if (event.id > after) {
                after = event.id
            }
            val alert = alertFromRelay(event.body, now()) ?: continue
            if (active.none { it.id == alert.id } && history.none { it.alert.id == alert.id }) {
                active.add(alert)
            }
        }
        notice = ""
        return null
    }

    /** Returns an error message, or null when the button was applied. */
    fun press(alertId: String, button: AlertButton): String? {
        val alert = active.find { it.id == alertId } ?: return "That alert is no longer in the list."
        when (button) {
            AlertButton.Details -> return null
            AlertButton.Ignore -> {
                active.remove(alert)
                history.add(HistoryEntry(alert, "Ignored", now()))
                notice = "Ignored."
                return null
            }
            AlertButton.Fix, AlertButton.Stop -> {
                val fixId = fixIdFor(alert, button) ?: return "That action is not offered."
                val expires = now() + APPROVAL_TTL_SECONDS
                val rejection = expiryRejection(expires, now())
                if (rejection != null) {
                    return rejection
                }
                val approval = signApproval(
                    signer = signer,
                    macId = paired?.macId ?: "0123456789abcdef0123456789abcdef",
                    alertId = alert.id,
                    fixId = fixId,
                    nonce = randomNonce(),
                    expiresUnix = expires,
                )
                val shape = approvalShapeError(approval)
                if (shape != null) {
                    return shape
                }
                if (!verifyEd25519(approval.publicKey, canonicalBytes(approval), approval.signature)) {
                    return "The phone could not sign that approval."
                }
                if (!demo) {
                    val current = paired ?: return "Pair with a Mac before sending an approval."
                    val response = http.send(
                        "POST",
                        relayUrl(current.relayUrl, current.macId, "approvals"),
                        approvalJson(approval),
                    )
                    if (response.status != 200) {
                        return "The relay did not accept the approval (${response.status})."
                    }
                    history.add(HistoryEntry(alert, "Sent $fixId", now()))
                    notice = "Sent $fixId."
                } else {
                    history.add(HistoryEntry(alert, "Signed $fixId in demo mode", now()))
                    notice = "Signed $fixId. Demo mode keeps it on this phone."
                }
                active.remove(alert)
                return null
            }
        }
    }

    private fun services(): List<ServiceRow> {
        if (demo) {
            return demoServices()
        }
        val rows = linkedMapOf<String, ServiceRow>()
        for (entry in history) {
            rows[entry.alert.serviceId] = rowFrom(entry.alert)
        }
        for (alert in active) {
            rows[alert.serviceId] = rowFrom(alert)
        }
        return rows.values.toList()
    }
}

fun demoAlerts(): List<Alert> {
    return listOf(
        Alert(
            id = "11111111111111111111111111111111",
            serviceId = "example-desktop-app",
            serviceName = "Example Desktop App",
            kind = "down",
            message = "Example Desktop App has stopped. It is not running.",
            actions = listOf("restart"),
            process = "example-desktop-app",
            atEpoch = 1_700_000_000,
        ),
        Alert(
            id = "22222222222222222222222222222222",
            serviceId = "example-desktop-app",
            serviceName = "Example Desktop App",
            kind = "stuck",
            message = "Example Desktop App is open but has no established outbound connection on port 443, so it looks stuck.",
            actions = listOf("force-restart"),
            process = "example-desktop-app",
            atEpoch = 1_700_000_100,
        ),
        Alert(
            id = "33333333333333333333333333333333",
            serviceId = "unwatched",
            serviceName = "ExampleTool",
            kind = "cpu_hog",
            message = "A process that is not on the watched list (ExampleTool) has used 90% of the CPU for 5 minutes.",
            actions = listOf("stop"),
            process = "ExampleTool",
            atEpoch = 1_700_000_200,
        ),
        Alert(
            id = "44444444444444444444444444444444",
            serviceId = "this-mac",
            serviceName = "This Mac",
            kind = "network_down",
            message = "The Mac lost its internet connection. Checks are paused until it returns.",
            actions = emptyList(),
            process = "",
            atEpoch = 1_700_000_300,
        ),
    )
}

fun demoServices(): List<ServiceRow> {
    return listOf(
        ServiceRow("example-desktop-app", "Example Desktop App", "down", "Example Desktop App has stopped. It is not running."),
        ServiceRow("syncthing", "Syncthing", "ok", "No alert."),
        ServiceRow("this-mac", "This Mac", "paused", "The Mac lost its internet connection. Checks are paused until it returns."),
    )
}

private fun rowFrom(alert: Alert): ServiceRow {
    val status = when (alert.kind) {
        "down" -> "down"
        "stuck" -> "running but stuck"
        "network_down" -> "paused"
        "cpu_hog", "memory_hog" -> "using the machine"
        else -> alert.kind
    }
    return ServiceRow(alert.serviceId, alert.serviceName, status, alert.message)
}
