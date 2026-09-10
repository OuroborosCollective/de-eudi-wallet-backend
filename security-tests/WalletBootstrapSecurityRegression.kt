package securitytests

import de.eudiwallet.backend.shared.WalletBootstrapSecurity
import de.eudiwallet.backend.shared.WalletBootstrapSecurityException
import java.util.Locale
import java.util.Properties
import java.util.Random
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Exercises the actual production policy, with no Spring/HSM stubs or copied validator. */
object WalletBootstrapSecurityRegression {
    private var groups = 0
    private var assertions = 0
    private val failures = mutableListOf<String>()
    private val initialProperties = System.getProperties().clone() as Properties
    private val services = listOf("combined", "mdvm", "pns", "rwsca", "wpb")
    private val pins = linkedMapOf(
        "spring.main.allow-bean-definition-overriding" to "false",
        "spring.main.allow-circular-references" to "false",
        "spring.main.lazy-initialization" to "false",
        "spring.main.register-shutdown-hook" to "true",
        "spring.jmx.enabled" to "false",
        "spring.jndi.ignore" to "true",
        "management.endpoint.shutdown.enabled" to "false",
        "management.endpoint.env.show-values" to "never",
        "management.endpoint.configprops.show-values" to "never",
        "management.endpoint.health.show-details" to "never",
        "management.endpoint.health.show-components" to "never",
        "server.error.include-exception" to "false",
        "server.error.include-message" to "never",
        "server.error.include-binding-errors" to "never",
        "server.error.include-stacktrace" to "never",
        "server.error.include-path" to "never",
        "server.error.whitelabel.enabled" to "false",
        "spring.h2.console.enabled" to "false",
        "spring.h2.console.settings.trace" to "false",
        "spring.h2.console.settings.web-allow-others" to "false",
    )

    private fun assertThat(ok: Boolean, message: String) {
        assertions++
        check(ok) { message }
    }

    private fun reset() { System.setProperties(initialProperties.clone() as Properties) }

    private inline fun group(name: String, block: () -> Unit) {
        reset()
        try {
            block()
            println("PASS $name")
        } catch (e: Exception) {
            // Fixed group names only; do not accidentally print test payloads.
            failures.add(name)
            println("FAIL $name (${e.javaClass.simpleName})")
        } finally {
            groups++
            reset()
        }
    }

    private fun reject(vararg args: String, service: String = "rwsca"): WalletBootstrapSecurityException {
        val before = System.getProperties().clone() as Properties
        val exception = try {
            WalletBootstrapSecurity.validateAndCopy(arrayOf(*args), service)
            null
        } catch (e: WalletBootstrapSecurityException) { e }
        assertThat(exception != null, "policy must reject the input")
        assertThat(System.getProperties() == before, "rejected startup must not change JVM properties")
        return checkNotNull(exception)
    }

    private fun accept(vararg args: String, service: String = "rwsca") {
        val input = arrayOf(*args)
        val copy = WalletBootstrapSecurity.validateAndCopy(input, service)
        assertThat(copy !== input && copy.contentEquals(input), "validated copy must preserve accepted arguments")
        if (input.isNotEmpty()) {
            input[0] = "changed-after-return"
            assertThat(copy[0] != input[0], "returned array must not alias the caller array")
        }
        pins.forEach { (key, value) ->
            assertThat(System.getProperty(key) == value, "all required properties must be pinned")
        }
    }

    private fun aliases(key: String): List<String> = listOf(
        key,
        key.replace("-", ""),
        key.replace('-', '_'),
        key.replace('.', '_').replace('-', '_').uppercase(Locale.ROOT),
        key.split('-').mapIndexed { index, part ->
            if (index == 0) part else part.replaceFirstChar { it.uppercaseChar() }
        }.joinToString(""),
    ).distinct()

    @JvmStatic
    fun main(args: Array<String>) {
        require(args.isEmpty())
        group("all-service-entry-policies-and-safe-arguments") {
            services.forEach { service ->
                accept("--server.port=8443", "--spring.profiles.active=production", service = service)
            }
        }
        group("compact-pinned-aliases") {
            pins.forEach { (name, value) ->
                val unsafe = if (value == "false") "true" else if (value == "true") "false" else "always"
                aliases(name).forEach { alias -> services.forEach { reject("--$alias=$unsafe", service = it) } }
            }
        }
        group("correct-pin-aliases-remain-functional") {
            pins.forEach { (name, value) -> aliases(name).forEach { accept("--$it=$value") } }
        }
        group("indexed-management-wildcards") {
            listOf("web", "jmx").forEach { transport ->
                listOf("", "[0]", "[1]", "[2147483647]").forEach { index ->
                    reject("--management.endpoints.$transport.exposure.include$index=*")
                    reject("--management.endpoints.$transport.exposure.include$index=health, * ")
                }
            }
        }
        group("safe-indexed-management-options-remain-functional") {
            accept("--management.endpoints.web.exposure.include[0]=health", "--management.endpoints.web.exposure.include[1]=info")
        }
        group("indexed-config-source-overrides") {
            listOf("spring.main.sources", "spring.autoconfigure.exclude", "spring.config.location", "spring.config.import").forEach {
                reject("--$it[0]=example.InvalidSource")
            }
        }
        group("indexed-forbidden-profiles") {
            listOf("active", "include").forEach { property ->
                listOf("", "[0]", "[1]").forEach { index ->
                    reject("--spring.profiles.$property$index=production,build-docs")
                }
            }
        }
        group("prepared-environment-profile-regression") {
            WalletBootstrapSecurity.validatePreparedEnvironment(arrayOf("rwsca", "production"), arrayOf("default"), "rwsca")
            var caught = false
            try {
                WalletBootstrapSecurity.validatePreparedEnvironment(arrayOf("build-docs"), emptyArray(), "rwsca")
            } catch (_: WalletBootstrapSecurityException) { caught = true }
            assertThat(caught, "expanded documentation profile must be rejected")
        }
        group("indexed-scalar-pins") {
            pins.forEach { (key, value) -> reject("--$key[0]=$value") }
        }
        group("indexed-secrets") {
            listOf("token[0]", "wallet.password[0]", "hsm.slots[0].pin", "clientSecret", "oauth.accessToken[0]").forEach {
                reject("--$it=TEST_ONLY_NOT_A_REAL_SECRET")
            }
        }
        group("duplicate-normalized-pins") {
            reject("--server.error.include-stacktrace=never", "--server.error.includestacktrace=never")
        }
        group("no-user-controlled-key-in-errors") {
            val sentinel = "TestOnlySensitiveKeyMarker"
            val e = reject("--$sentinel=one", "--$sentinel=two")
            assertThat(!e.stackTraceToString().contains(sentinel, ignoreCase = true), "errors must not echo untrusted keys")
        }
        group("reject-before-any-property-write") { reject("--debug") }
        group("late-pin-conflict-is-read-only") {
            System.setProperty("spring.h2.console.settings.web-allow-others", "true")
            reject()
        }
        group("compact-system-property-conflict") {
            System.setProperty("spring.main.allowbeandefinitionoverriding", "true")
            reject()
        }
        group("indexed-system-property-conflict") {
            System.setProperty("spring.jmx.enabled[0]", "false")
            reject()
        }
        group("opaque-configuration-rejection-is-read-only") {
            System.setProperty("spring.application.json", "{\"spring\":{}}")
            reject()
        }
        group("early-forbidden-profile-is-read-only") {
            System.setProperty("spring.profiles.active", "build-docs")
            reject()
        }
        group("exact-argument-byte-boundary") {
            val prefix = "--description="
            accept(prefix + "x".repeat(8192 - prefix.length))
            reject(prefix + "x".repeat(8193 - prefix.length))
        }
        group("exact-total-byte-boundary") {
            val atLimit = (0..7).map { i -> "--arg$i=" + "x".repeat(8192 - "--arg$i=".length) }.toTypedArray()
            accept(*atLimit)
            reject(*atLimit, "x")
        }
        group("argument-count-boundary") {
            accept(*(0..127).map { "--arg$it=value" }.toTypedArray())
            reject(*(0..128).map { "--arg$it=value" }.toTypedArray())
        }
        group("unicode-and-surrogate-boundaries") {
            accept("--description=Grüße-\uD83D\uDE00")
            reject("--description=" + "€".repeat(3000))
            listOf('\u0000', '\n', '\u202E', '\u2066', '\uD800', '\uDC00').forEach { reject("--description=x${it}y") }
        }
        group("invalid-and-unknown-service-rejection") {
            reject("")
            reject("--")
            reject("--=value")
            reject(service = "unexpected-service")
        }
        group("seeded-alias-variations-5000") {
            val random = Random(260910)
            val compact = "springmainallowbeandefinitionoverriding"
            repeat(5000) {
                val alias = buildString {
                    compact.forEach { char ->
                        if (isNotEmpty()) append(listOf("", ".", "-", "_")[random.nextInt(4)])
                        append(if (random.nextBoolean()) char.uppercaseChar() else char)
                    }
                }
                reject("--$alias=true")
            }
        }
        group("concurrent-successful-validation-256") {
            accept()
            val pool = Executors.newFixedThreadPool(8)
            try {
                val futures = pool.invokeAll((0..255).map { index -> Callable {
                    val original = arrayOf("--request-label=worker-$index")
                    val result = WalletBootstrapSecurity.validateAndCopy(original, services[index % services.size])
                    result !== original && result.contentEquals(original)
                } }, 30, TimeUnit.SECONDS)
                futures.forEach { assertThat(!it.isCancelled && it.get(), "concurrent result must preserve snapshot") }
            } finally {
                pool.shutdownNow()
                assertThat(pool.awaitTermination(5, TimeUnit.SECONDS), "test workers must terminate")
            }
        }
        System.setProperties(initialProperties)
        println("BOOTSTRAP_REGRESSION groups=$groups assertions=$assertions failures=${failures.size}")
        check(failures.isEmpty()) { "Failed fixed group names: ${failures.joinToString()}" }
    }
}
