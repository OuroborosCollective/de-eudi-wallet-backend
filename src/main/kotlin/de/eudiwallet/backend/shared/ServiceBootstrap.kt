package de.eudiwallet.backend.shared

import de.eudiwallet.backend.shared.crypto.BOUNCY_CASTLE_PROVIDER
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent
import org.springframework.boot.runApplication
import org.springframework.context.ApplicationListener
import java.security.Provider
import java.security.Security

private val log = KotlinLogging.logger {}
private val cryptoProviderRegistrationLock = Any()
private const val EXPECTED_BC_PROVIDER_NAME = "BC"
private const val EXPECTED_BC_PROVIDER_CLASS = "org.bouncycastle.jce.provider.BouncyCastleProvider"

fun registerCryptoProviders() {
    synchronized(cryptoProviderRegistrationLock) {
        val bundled = BOUNCY_CASTLE_PROVIDER
        requireTrustedBouncyCastleProvider(bundled)

        val existing = Security.getProvider(EXPECTED_BC_PROVIDER_NAME)
        if (existing !== bundled) {
            if (existing != null) {
                requireEquivalentProvider(existing, bundled)
                Security.removeProvider(EXPECTED_BC_PROVIDER_NAME)
            }
            val position = Security.insertProviderAt(bundled, 1)
            check(position == 1) {
                "Failed to install the verified cryptography provider at position 1"
            }
        }

        val providers = Security.getProviders()
        check(providers.firstOrNull() === bundled) {
            "Required cryptography provider is not the first registered provider"
        }
        check(providers.count { it.name == EXPECTED_BC_PROVIDER_NAME } == 1) {
            "Required cryptography provider is registered more than once"
        }
        check(Security.getProvider(EXPECTED_BC_PROVIDER_NAME) === bundled) {
            "Required cryptography provider identity changed during bootstrap"
        }
    }
}

private fun requireTrustedBouncyCastleProvider(provider: Provider) {
    check(provider.name == EXPECTED_BC_PROVIDER_NAME) {
        "Unexpected cryptographic provider name"
    }
    check(provider.javaClass.name == EXPECTED_BC_PROVIDER_CLASS) {
        "Unexpected cryptographic provider implementation"
    }
    check(provider.services.isNotEmpty()) {
        "Cryptographic provider exposes no services"
    }

    val requiredServices =
        listOf(
            "KeyFactory" to "EC",
            "KeyPairGenerator" to "EC",
            "MessageDigest" to "SHA-256",
            "Mac" to "HMACSHA256",
            "KeyGenerator" to "AES",
        )

    requiredServices.forEach { (type, algorithm) ->
        check(provider.getService(type, algorithm) != null) {
            "Cryptographic provider is missing a required wallet primitive"
        }
    }
}

private fun requireEquivalentProvider(
    existing: Provider,
    bundled: Provider,
) {
    requireTrustedBouncyCastleProvider(existing)
    check(existing.javaClass.classLoader === bundled.javaClass.classLoader) {
        "Refusing to replace a cryptographic provider loaded by a different class loader"
    }
    check(existing.versionStr == bundled.versionStr) {
        "Refusing to replace a cryptographic provider with a different version"
    }

    val existingSource = existing.javaClass.protectionDomain?.codeSource?.location
    val bundledSource = bundled.javaClass.protectionDomain?.codeSource?.location
    check(existingSource == bundledSource) {
        "Refusing to replace a cryptographic provider from a different code source"
    }
}

@Suppress("SpreadOperator")
inline fun <reified T : Any> runWalletService(
    args: Array<String>,
    profile: String,
) {
    val validatedArgs = WalletBootstrapSecurity.validateAndCopy(args, profile)
    registerCryptoProviders()
    logCryptoProviders()
    runApplication<T>(*validatedArgs) {
        setAdditionalProfiles(profile)
        addListeners(
            ApplicationListener<ApplicationEnvironmentPreparedEvent> { event ->
                WalletBootstrapSecurity.validatePreparedEnvironment(
                    activeProfiles = event.environment.activeProfiles,
                    defaultProfiles = event.environment.defaultProfiles,
                    serviceProfile = profile,
                )
            },
        )
    }
}

fun logCryptoProviders() {
    log.info {
        "Cryptography Providers: ${
            Security.getProviders().mapIndexed { index, provider -> "${index + 1}. ${provider.name}" }
        }"
    }
}
