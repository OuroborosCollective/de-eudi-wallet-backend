package de.eudiwallet.backend.shared

import java.lang.management.ManagementFactory
import java.nio.charset.StandardCharsets
import java.util.Locale

/**
 * Process-wide wallet bootstrap security policy.
 *
 * This object is deliberately shared by every Spring Boot entry point so that
 * combined and standalone services cannot drift into different startup trust
 * boundaries. It validates only process/bootstrap concerns; protocol, HSM and
 * attestation checks remain owned by their dedicated components.
 */
object WalletBootstrapSecurity {
    private const val MAX_ARGUMENT_COUNT = 128
    private const val MAX_ARGUMENT_BYTES = 8 * 1024
    private const val MAX_TOTAL_ARGUMENT_BYTES = 64 * 1024

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
        pinnedSpringProperties.associateBy { policyKey(it.propertyName) }

    private val forbiddenCliSourceKeys =
        setOf(
            "spring.application.json",
            "spring.main.sources",
            "spring.autoconfigure.exclude",
            "spring.config.name",
            "spring.config.location",
            "spring.config.additional.location",
            "spring.config.import",
        ).mapTo(HashSet(), ::policyKey)

    private val serviceModeOverrideKeys =
        setOf(
            "mode",
            "service.mode",
            "wallet.mode",
            "wallet.service.mode",
            "mdvm.mode",
            "mdvm.service.mode",
        ).mapTo(HashSet(), ::policyKey)

    private val forbiddenExactFlags = setOf("debug", "trace")

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

    private val forbiddenJvmSystemPropertyPrefixes = setOf("com.sun.management.jmxremote")
    private val forbiddenJvmSystemProperties = setOf("javax.net.debug", "java.security.debug")
    private val allowedServiceProfiles = setOf("combined", "mdvm", "pns", "rwsca", "wpb")
    private val forbiddenRuntimeProfiles = setOf("build-docs")

    fun validateAndCopy(
        args: Array<String>,
        serviceProfile: String,
    ): Array<String> {
        securityCheck(serviceProfile in allowedServiceProfiles) {
            "Bootstrap rejected: unknown wallet service profile"
        }
        securityCheck(args.size <= MAX_ARGUMENT_COUNT) {
            "Bootstrap rejected: too many application arguments"
        }
        // Validate the same snapshot that is returned, before changing JVM state.
        val arguments = args.copyOf()
        validateJvmRuntime()
        validateOpaqueHighPrecedenceConfiguration()
        validateEarlyProfileSources()
        validateArguments(arguments)
        pinSpringSecurityProperties()
        return arguments
    }

    fun validatePreparedEnvironment(
        activeProfiles: Array<String>,
        defaultProfiles: Array<String>,
        serviceProfile: String,
    ) {
        securityCheck(serviceProfile in allowedServiceProfiles) {
            "Bootstrap rejected: unknown wallet service profile"
        }
        val resolved =
            (activeProfiles.asSequence() + defaultProfiles.asSequence())
                .map { it.trim().lowercase(Locale.ROOT) }
                .filter { it.isNotEmpty() }
                .toSet()
        securityCheck(resolved.intersect(forbiddenRuntimeProfiles).isEmpty()) {
            "Bootstrap rejected: documentation-only Spring profile is forbidden at runtime"
        }
    }

    private fun validateEarlyProfileSources() {
        sequenceOf(
            System.getenv("SPRING_PROFILES_ACTIVE"),
            System.getenv("SPRING_PROFILES_INCLUDE"),
            System.getProperty("spring.profiles.active"),
            System.getProperty("spring.profiles.include"),
        ).filterNotNull().forEach(::rejectForbiddenProfiles)
    }

    private fun rejectForbiddenProfiles(rawProfiles: String) {
        val profiles =
            rawProfiles
                .split(',', ';')
                .asSequence()
                .map { it.trim().lowercase(Locale.ROOT) }
                .filter { it.isNotEmpty() }
                .toSet()
        securityCheck(profiles.intersect(forbiddenRuntimeProfiles).isEmpty()) {
            "Bootstrap rejected: documentation-only Spring profile is forbidden at runtime"
        }
    }

    private fun validateArguments(args: Array<String>) {
        securityCheck(args.size <= MAX_ARGUMENT_COUNT) {
            "Bootstrap rejected: too many application arguments"
        }

        var totalBytes = 0
        val seenOptionKeys = HashSet<String>()

        args.forEachIndexed { index, rawArgument ->
            // Valid UTF-8 needs at least one byte per UTF-16 code unit. Reject
            // oversized inputs before scanning Unicode or allocating an encoding.
            securityCheck(rawArgument.length <= MAX_ARGUMENT_BYTES) {
                "Bootstrap rejected: application argument at index $index is too large"
            }
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
        val rawKey = if (separatorIndex >= 0) optionBody.substring(0, separatorIndex) else optionBody

        securityCheck(rawKey.isNotBlank()) {
            "Bootstrap rejected: empty option key at index $index"
        }

        val canonicalKey = canonicalizePropertyKey(rawKey)
        securityCheck(canonicalKey.isNotBlank()) {
            "Bootstrap rejected: invalid option key at index $index"
        }

        val comparisonKey = policyKey(canonicalKey)
        val policyRoot = comparisonKey.substringBefore('[')
        if (policyRoot == "springprofilesactive" || policyRoot == "springprofilesinclude") {
            val suppliedValue = if (separatorIndex >= 0) optionBody.substring(separatorIndex + 1) else ""
            rejectForbiddenProfiles(suppliedValue)
        }

        securityCheck(seenOptionKeys.add(comparisonKey)) {
            "Bootstrap rejected: duplicate option key"
        }
        securityCheck(policyRoot !in forbiddenExactFlags) {
            "Bootstrap rejected: diagnostic flag is forbidden"
        }
        securityCheck(policyRoot !in forbiddenCliSourceKeys) {
            "Bootstrap rejected: runtime config-source override is forbidden"
        }
        securityCheck(policyRoot !in serviceModeOverrideKeys) {
            "Bootstrap rejected: service mode is immutable and cannot be overridden"
        }
        securityCheck(!isSensitiveCliProperty(canonicalKey)) {
            "Bootstrap rejected: secret-bearing command-line property is forbidden"
        }

        pinnedSpringPropertiesByCanonicalKey[policyRoot]?.let { pinned ->
            securityCheck(comparisonKey == policyRoot) {
                "Bootstrap rejected: pinned scalar property cannot be indexed"
            }
            val suppliedValue = if (separatorIndex >= 0) optionBody.substring(separatorIndex + 1) else ""
            securityCheck(suppliedValue.equals(pinned.requiredValue, ignoreCase = true)) {
                "Bootstrap rejected: pinned security property cannot be weakened"
            }
        }

        validateHighRiskManagementOption(canonicalKey, optionBody, separatorIndex)
    }

    private fun validateHighRiskManagementOption(
        canonicalKey: String,
        optionBody: String,
        separatorIndex: Int,
    ) {
        val policyRoot = policyKey(canonicalKey).substringBefore('[')
        if (policyRoot != "managementendpointswebexposureinclude" &&
            policyRoot != "managementendpointsjmxexposureinclude"
        ) {
            return
        }

        val value = if (separatorIndex >= 0) optionBody.substring(separatorIndex + 1) else ""
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
        // Ordinary Properties readers/writers use this same monitor. Validate
        // every conflict before applying any pin; a failed validation is read-only.
        // This is not a sandbox against hostile code already inside the JVM.
        synchronized(systemProperties) {
            val systemPropertyNames = systemProperties.stringPropertyNames()
            pinnedSpringProperties.forEach { pinned ->
                val pinnedKey = policyKey(pinned.propertyName)
                systemPropertyNames.asSequence()
                    .filter { policyKey(it).substringBefore('[') == pinnedKey }
                    .forEach { existingName ->
                        securityCheck(
                            policyKey(existingName) == pinnedKey &&
                                systemProperties.getProperty(existingName)
                                    .equals(pinned.requiredValue, ignoreCase = true),
                        ) {
                            "Bootstrap rejected: JVM property conflicts with the pinned security policy"
                        }
                    }
            }
            pinnedSpringProperties.forEach { pinned ->
                systemProperties.setProperty(pinned.propertyName, pinned.requiredValue)
            }
        }
    }

    private fun validateOpaqueHighPrecedenceConfiguration() {
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
        val unindexedKey = canonicalKey.substringBeforeLast('[', canonicalKey)
            .takeIf { canonicalKey.endsWith(']') } ?: canonicalKey
        val terminal = unindexedKey.substringAfterLast('.', unindexedKey)
        return terminal in sensitiveTerminalKeyParts || sensitiveKeySuffixes.any { unindexedKey.endsWith(it) }
    }

    /**
     * Conservative security-policy identity, NOT a Spring property-name parser.
     * Reserved names also match compact/camel/underscore aliases. Keep indices
     * for duplicate detection, but compare their roots for reserved list policy.
     * Original arguments are never rewritten or interpreted as property values.
     */
    private fun policyKey(key: String): String =
        key.filterNot { it == '.' || it == '-' || it == '_' }.lowercase(Locale.ROOT)

    private fun canonicalizePropertyKey(rawKey: String): String {
        val normalized =
            buildString(rawKey.length) {
                var previousWasSeparator = false

                rawKey
                    .trim()
                    .forEachIndexed { index, character ->
                        val separator = character == '.' || character == '-' || character == '_'
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

class WalletBootstrapSecurityException(
    message: String,
) : IllegalStateException(message)
