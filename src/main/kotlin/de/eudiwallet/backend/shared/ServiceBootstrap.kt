package de.eudiwallet.backend.shared

import de.eudiwallet.backend.shared.crypto.BOUNCY_CASTLE_PROVIDER
import io.github.oshai.kotlinlogging.KotlinLogging
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.event.ApplicationEnvironmentPreparedEvent
import org.springframework.boot.runApplication
import org.springframework.context.ApplicationListener
import java.security.Security

private val log = KotlinLogging.logger {}
private val cryptoProviderRegistrationLock = Any()

fun registerCryptoProviders() {
    synchronized(cryptoProviderRegistrationLock) {
        val providerName = BOUNCY_CASTLE_PROVIDER.name
        val existing = Security.getProvider(providerName)

        if (existing !== BOUNCY_CASTLE_PROVIDER) {
            if (existing != null) {
                Security.removeProvider(providerName)
            }
            val position = Security.insertProviderAt(BOUNCY_CASTLE_PROVIDER, 1)
            check(position == 1) {
                "Failed to install the required cryptography provider at position 1"
            }
        }

        val providers = Security.getProviders()
        check(providers.firstOrNull() === BOUNCY_CASTLE_PROVIDER) {
            "Required cryptography provider is not the first registered provider"
        }
        check(providers.count { it.name == providerName } == 1) {
            "Required cryptography provider is registered more than once"
        }
        check(Security.getProvider(providerName) === BOUNCY_CASTLE_PROVIDER) {
            "Required cryptography provider identity changed during bootstrap"
        }
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
