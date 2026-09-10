package de.eudiwallet.backend

import de.eudiwallet.backend.shared.runWalletService
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationPropertiesScan
import java.lang.management.ManagementFactory
import java.nio.charset.StandardCharsets
import java.util.Locale

private const val SERVICE_MODE = "combined"

/**
 * Security-sensitive wallet backend bootstrap.
 *
 * Scope:
 * - keeps the service mode immutable at this entry point;
 * - validates process arguments before Spring sees them;
 * - rejects secret-bearing command-line properties;
 * - rejects high-risk Spring/JVM startup overrides;
 * - pins a small set of fail-closed Spring defaults;
 * - never logs raw command-line arguments or their values.
 *
 * Deliberately NOT implemented here:
 * - authentication / authorization;
 * - TLS or reverse-proxy policy;
 * - key / credential loading;
 * - attestation or cryptographic verification;
 * - database / migration policy.
 *
 * Those belong to their respective trust boundaries. The launcher must not
 * pretend to provide security that can only be proven deeper in the runtime.
 */
@SpringBootApplication(proxyBeanMethods = false)
@ConfigurationPropertiesScan
@Suppress("UtilityClassWithPublicConstructor")
class WalletBackendApplication

fun main(args: Array<String>) {
    val validatedArgs = WalletBootstrapSecurity.validateAndCopy(args)
    runWalletService<WalletBackendApplication>(validatedArgs, SERVICE_MODE)
}

private object WalletBootstrapSecurity {
    private const val MAX_ARGUMENT_COUNT = 128
    private const val MAX_ARGUMENT_BYTES = 8 * 1024
    private const val MAX_TOTAL_ARGUMENT_BYTES = 64 * 1024

    /**
     * These values are security/reliability invariants for this bootstrap.
     *
     * System properties outrank environment/config-data in Spring Boot.
     * CLI and SPRING_APPLICATION_JSON can outrank system properties, therefore
     * both are separately validated/restricted below.
     */
    private data class PinnedProperty(
        val propertyName: String,
        val requiredValue: String,
    )

    private val pinnedSpringProperties =
        listOf(
            PinnedProperty("spring.main.allow-bean-definition-overriding", "false"),
            PinnedProperty("spring.main.allow-circular-references", "false"),
            PinnedProperty("spring.main.lazy-initialization", "false"),
            PinnedProperty("spring.main.register-shutdown-hook", "true"),
            PinnedProperty("spring.jmx.enabled", "false"),
            PinnedProperty("spring.jndi.ignore", "true"),
            PinnedProperty("management.endpoint.shutdown.enabled", "false"),
            PinnedProperty("management.endpoint.env.show-values", "never"),
            PinnedProperty("management.endpoint.configprops.show-values", "never"),
            PinnedProperty("management.endpoint.health.show-details", "never"),
            PinnedProperty("management.endpoint.health.show-components", "never"),
            PinnedProperty("server.error.include-exception", "false"),
            PinnedProperty("server.error.include-message", "never"),
            PinnedProperty("server.error.include-binding-errors", "never"),
            PinnedProperty("server.error.include-stacktrace", "never"),
            PinnedProperty("server.error.include-path", "never"),
            PinnedProperty("server.error.whitelabel.enabled", "false"),
            PinnedProperty("spring.h2.console.enabled", "false"),
            PinnedProperty("spring.h2.console.settings.trace", "false"),
            PinnedProperty("spring.h2.console.settings.web-allow-others", "false"),
        )

    private val pinnedSpringPropertiesByCanonicalKey =
        pinnedSpringProperties.associateBy { canonicalizePropertyKey(it.propertyName) }

    /**
     * These are intentionally rejected when supplied from the command line.
     * They can materially alter what configuration is loaded or which
     * auto-configuration is present before the application has established
     * its own trust policy.
     */
    private val forbiddenCliSourceKeys =
        setOf(
            "spring.application.json",
            "spring.main.sources",
            "spring.autoconfigure.exclude",
            "spring.config.name",
            "spring.config.location",
            "spring.config.additional.location",
            "spring.config.import",
        )

    /**
     * The service mode is owned by this source file and passed directly to
     * runWalletService(). A second command-line mode creates two sources of
     * truth and is therefore rejected.
     */
    private val serviceModeOverrideKeys =
        setOf(
            "mode",
            "service.mode",
            "wallet.mode",
            "wallet.service.mode",
            "mdvm.mode",
            "mdvm.service.mode",
        )

    private val forbiddenExactFlags =
        setOf(
            "debug",
            "trace",
        )

    private val sensitiveTerminalKeyParts =
        setOf(
            "password",
            "passwd",
            "secret",
            "token",
            "credential",
            "credentials",
            "pin",
            "pwd",
            "apikey",
            "privatekey",
            "clientsecret",
            "accesstoken",
            "refreshtoken",
            "bearertoken",
            "authorization",
        )

    private val sensitiveKeySuffixes =
        setOf(
            ".api.key",
            ".private.key",
            ".signing.key",
            ".encryption.key",
            ".client.secret",
            ".access.token",
            ".refresh.token",
            ".bearer.token",
            ".key.password",
            ".key.store.password",
            ".keystore.password",
            ".trust.store.password",
            ".truststore.password",
        )

    private val forbiddenJvmSystemPropertyPrefixes =
        setOf(
            "com.sun.management.jmxremote",
        )

    private val forbiddenJvmSystemProperties =
        setOf(
            "javax.net.debug",
            "java.security.debug",
        )

    fun validateAndCopy(args: Array<String>): Array<String> {
        validateJvmRuntime()
        pinSpringSecurityProperties()
        validateOpaqueHighPrecedenceConfiguration()
        validateArguments(args)
        return args.copyOf()
    }

    private fun validateArguments(args: Array<String>) {
        securityCheck(args.size <= MAX_ARGUMENT_COUNT) {
            "Bootstrap rejected: too many application arguments"
        }

        var totalBytes = 0
        val seenOptionKeys = HashSet<String>()

        args.forEachIndexed { index, rawArgument ->
            securityCheck(rawArgument.isNotBlank()) {
                "Bootstrap rejected: blank application argument at index $index"
            }

            validateUnicode(rawArgument, index)

            val argumentBytes = rawArgument.toByteArray(StandardCharsets.UTF_8).size
            securityCheck(argumentBytes <= MAX_ARGUMENT_BYTES) {
                "Bootstrap rejected: application argument at index $index is too large"
            }

            totalBytes = addExactBounded(totalBytes, argumentBytes)
            securityCheck(totalBytes <= MAX_TOTAL_ARGUMENT_BYTES) {
                "Bootstrap rejected: combined application arguments are too large"
            }

            if (rawArgument.startsWith("--")) {
                validateSpringStyleOption(rawArgument, index, seenOptionKeys)
            }
        }
    }

    private fun validateSpringStyleOption(
        rawArgument: String,
        index: Int,
        seenOptionKeys: MutableSet<String>,
    ) {
        val optionBody = rawArgument.substring(2)
        securityCheck(optionBody.isNotBlank()) {
            "Bootstrap rejected: empty option at index $index"
        }

        val separatorIndex = optionBody.indexOf('=')
        val rawKey =
            if (separatorIndex >= 0) {
                optionBody.substring(0, separatorIndex)
            } else {
                optionBody
            }

        securityCheck(rawKey.isNotBlank()) {
            "Bootstrap rejected: empty option key at index $index"
        }

        val canonicalKey = canonicalizePropertyKey(rawKey)

        securityCheck(canonicalKey.isNotBlank()) {
            "Bootstrap rejected: invalid option key at index $index"
        }

        /*
         * Ambiguous repeated properties are rejected even if the textual values
         * happen to match. There must be one source occurrence per CLI key.
         */
        securityCheck(seenOptionKeys.add(canonicalKey)) {
            "Bootstrap rejected: duplicate option key '$canonicalKey'"
        }

        securityCheck(canonicalKey !in forbiddenExactFlags) {
            "Bootstrap rejected: diagnostic flag '$canonicalKey' is forbidden"
        }

        securityCheck(canonicalKey !in forbiddenCliSourceKeys) {
            "Bootstrap rejected: runtime config-source override '$canonicalKey' is forbidden"
        }

        securityCheck(canonicalKey !in serviceModeOverrideKeys) {
            "Bootstrap rejected: service mode is immutable and cannot be overridden"
        }

        securityCheck(!isSensitiveCliProperty(canonicalKey)) {
            /*
             * Never echo the value. Command-line secrets are commonly visible to
             * process inspection and may also end up in crash/support tooling.
             */
            "Bootstrap rejected: secret-bearing command-line property is forbidden"
        }

        pinnedSpringPropertiesByCanonicalKey[canonicalKey]?.let { pinned ->
            val suppliedValue =
                if (separatorIndex >= 0) {
                    optionBody.substring(separatorIndex + 1)
                } else {
                    ""
                }

            securityCheck(suppliedValue.equals(pinned.requiredValue, ignoreCase = true)) {
                "Bootstrap rejected: pinned security property '$canonicalKey' cannot be weakened"
            }
        }

        validateHighRiskManagementOption(canonicalKey, optionBody, separatorIndex)
    }

    private fun validateHighRiskManagementOption(
        canonicalKey: String,
        optionBody: String,
        separatorIndex: Int,
    ) {
        if (canonicalKey != "management.endpoints.web.exposure.include" &&
            canonicalKey != "management.endpoints.jmx.exposure.include"
        ) {
            return
        }

        val value =
            if (separatorIndex >= 0) {
                optionBody.substring(separatorIndex + 1)
            } else {
                ""
            }

        val containsWildcard =
            value
                .split(',')
                .asSequence()
                .map { it.trim() }
                .any { it == "*" }

        securityCheck(!containsWildcard) {
            "Bootstrap rejected: wildcard management endpoint exposure is forbidden"
        }
    }

    private fun pinSpringSecurityProperties() {
        val systemProperties = System.getProperties()
        val systemPropertyNames = systemProperties.stringPropertyNames()

        pinnedSpringProperties.forEach { pinned ->
            val canonicalPinnedKey = canonicalizePropertyKey(pinned.propertyName)

            systemPropertyNames
                .asSequence()
                .filter { canonicalizePropertyKey(it) == canonicalPinnedKey }
                .forEach { existingName ->
                    val existingValue = systemProperties.getProperty(existingName)
                    securityCheck(existingValue.equals(pinned.requiredValue, ignoreCase = true)) {
                        "Bootstrap rejected: JVM property '$canonicalPinnedKey' conflicts with the pinned security policy"
                    }
                }

            System.setProperty(pinned.propertyName, pinned.requiredValue)
        }
    }

    private fun validateOpaqueHighPrecedenceConfiguration() {
        /*
         * Spring Boot gives SPRING_APPLICATION_JSON / spring.application.json
         * very high property-source precedence. An opaque JSON blob could
         * otherwise bypass the individually pinned/validated CLI properties.
         */
        securityCheck(System.getenv("SPRING_APPLICATION_JSON").isNullOrBlank()) {
            "Bootstrap rejected: SPRING_APPLICATION_JSON is disabled by the strict startup policy"
        }

        securityCheck(System.getProperty("spring.application.json").isNullOrBlank()) {
            "Bootstrap rejected: spring.application.json is disabled by the strict startup policy"
        }
    }

    private fun validateJvmRuntime() {
        val inputArguments = ManagementFactory.getRuntimeMXBean().inputArguments

        inputArguments.forEach { argument ->
            val normalized = argument.lowercase(Locale.ROOT)

            securityCheck(
                !normalized.startsWith("-agentlib:jdwp") &&
                    !normalized.startsWith("-xrunjdwp"),
            ) {
                "Bootstrap rejected: JVM debug transport is enabled"
            }

            securityCheck(normalized != "-xx:+heapdumponoutofmemoryerror") {
                "Bootstrap rejected: automatic heap dumps are forbidden for the wallet process"
            }

            securityCheck(!normalized.startsWith("-xx:onoutofmemoryerror=")) {
                "Bootstrap rejected: JVM OnOutOfMemoryError command hooks are forbidden"
            }
        }

        forbiddenJvmSystemProperties.forEach { propertyName ->
            securityCheck(System.getProperty(propertyName).isNullOrBlank()) {
                "Bootstrap rejected: JVM diagnostic property '$propertyName' is enabled"
            }
        }

        val attachSelf = System.getProperty("jdk.attach.allowAttachSelf")
        securityCheck(!attachSelf.equals("true", ignoreCase = true)) {
            "Bootstrap rejected: self-attach is enabled"
        }

        /*
         * Reject remote JMX at the JVM level, independently of spring.jmx.enabled.
         * Only property names are inspected; values are never logged.
         */
        val systemPropertyNames = System.getProperties().stringPropertyNames()
        val hasRemoteJmxProperty =
            systemPropertyNames.any { name ->
                forbiddenJvmSystemPropertyPrefixes.any { prefix ->
                    name == prefix || name.startsWith("$prefix.")
                }
            }

        securityCheck(!hasRemoteJmxProperty) {
            "Bootstrap rejected: JVM remote JMX configuration is present"
        }
    }

    private fun validateUnicode(
        value: String,
        index: Int,
    ) {
        var offset = 0
        while (offset < value.length) {
            val codePoint = value.codePointAt(offset)

            securityCheck(!isForbiddenCodePoint(codePoint)) {
                "Bootstrap rejected: unsafe Unicode/control character in argument at index $index"
            }

            offset += Character.charCount(codePoint)
        }
    }

    private fun isForbiddenCodePoint(codePoint: Int): Boolean =
        Character.isISOControl(codePoint) ||
            codePoint in 0xD800..0xDFFF ||
            codePoint == 0x2028 ||
            codePoint == 0x2029 ||
            codePoint == 0x200E ||
            codePoint == 0x200F ||
            codePoint in 0x202A..0x202E ||
            codePoint in 0x2066..0x2069

    private fun isSensitiveCliProperty(canonicalKey: String): Boolean {
        val terminal = canonicalKey.substringAfterLast('.', canonicalKey)

        return terminal in sensitiveTerminalKeyParts ||
            sensitiveKeySuffixes.any { canonicalKey.endsWith(it) }
    }

    private fun canonicalizePropertyKey(rawKey: String): String {
        val normalized =
            buildString(rawKey.length) {
                var previousWasSeparator = false

                rawKey
                    .trim()
                    .forEachIndexed { index, character ->
                        val separator =
                            character == '.' ||
                                character == '-' ||
                                character == '_'

                        val previousCharacter = rawKey.getOrNull(index - 1)
                        val camelCaseBoundary =
                            character.isUpperCase() &&
                                previousCharacter != null &&
                                (previousCharacter.isLowerCase() || previousCharacter.isDigit())

                        if (separator || camelCaseBoundary) {
                            if (!previousWasSeparator && isNotEmpty()) {
                                append('.')
                            }
                        }

                        if (!separator) {
                            append(character.lowercaseChar())
                        }

                        previousWasSeparator = separator
                    }
            }

        return normalized.trim('.')
    }

    private fun addExactBounded(
        current: Int,
        delta: Int,
    ): Int {
        securityCheck(delta >= 0 && current <= Int.MAX_VALUE - delta) {
            "Bootstrap rejected: application argument size overflow"
        }
        return current + delta
    }

    private inline fun securityCheck(
        condition: Boolean,
        lazyMessage: () -> String,
    ) {
        if (!condition) {
            throw WalletBootstrapSecurityException(lazyMessage())
        }
    }
}

/**
 * Dedicated type so callers/tests can distinguish deliberate startup-policy
 * rejection from ordinary application failures without exposing secret values.
 */
private class WalletBootstrapSecurityException(
    message: String,
) : IllegalStateException(message)
