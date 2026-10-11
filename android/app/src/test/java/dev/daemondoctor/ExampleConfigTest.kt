package dev.daemondoctor

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ExampleConfigTest {
    @Test
    fun googleServicesExampleIsAPlaceholder() {
        val file = findExample()
        val text = file.readText()
        assertTrue(text.contains("\"current_key\": \"placeholder-not-a-real-key\""))
        assertTrue(text.contains("dev.daemondoctor"))
        assertFalse(text.contains("private_key"))
        assertFalse(Regex("AIza[0-9A-Za-z_\\-]{20,}").containsMatchIn(text))
    }
}

private fun findExample(): File {
    var dir: File? = File(".").absoluteFile
    repeat(6) {
        val current = dir ?: return@repeat
        val nested = File(current, "android/google-services.json.example")
        if (nested.isFile) {
            return nested
        }
        val local = File(current, "google-services.json.example")
        if (local.isFile) {
            return local
        }
        dir = current.parentFile
    }
    error("google-services.json.example not found from ${File(".").absolutePath}")
}
