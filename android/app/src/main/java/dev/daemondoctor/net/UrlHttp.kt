package dev.daemondoctor.net

import dev.daemondoctor.core.Http
import dev.daemondoctor.core.HttpResponse
import java.net.HttpURLConnection
import java.net.URL

class UrlHttp : Http {
    override fun send(method: String, url: String, body: String?): HttpResponse {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 15_000
            readTimeout = 15_000
            setRequestProperty("Accept", "application/json")
            if (body != null) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }
        }
        if (body != null) {
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
        }
        val status = conn.responseCode
        val stream = if (status in 200..299) conn.inputStream else conn.errorStream
        val text = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
        conn.disconnect()
        return HttpResponse(status, text)
    }
}
