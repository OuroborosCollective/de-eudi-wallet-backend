package de.eudiwallet.backend

import de.eudiwallet.backend.shared.runWalletService
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationPropertiesScan

private const val SERVICE_MODE = "combined"

// runWalletService owns the same startup policy for combined and standalone services.
@SpringBootApplication(proxyBeanMethods = false)
@ConfigurationPropertiesScan
@Suppress("UtilityClassWithPublicConstructor")
class WalletBackendApplication

fun main(args: Array<String>) {
    runWalletService<WalletBackendApplication>(args, SERVICE_MODE)
}
