package de.eudiwallet.backend.shared.hsm

import de.eudiwallet.backend.shared.hsm.pkcs11.Ck
import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

private const val MAX_HSM_POOL_SIZE = 256
private const val MAX_HSM_WORKER_COUNT = 256
private const val MAX_ALLOWED_WRAPPING_MECHANISMS = 16

private val DEFAULT_ALLOWED_WRAPPING_MECHANISMS =
    setOf(
        Ck.CKM_AES_KEY_WRAP,
        Ck.CKM_AES_KEY_WRAP_PAD,
    )

@ConfigurationProperties(prefix = "hsm")
@Suppress("MagicNumber")
class HsmConfiguration(
    val moduleLibrary: String,
    val slotLabel: String,
    val slotPin: String,
    val wrappingMechanism: Long = Ck.CKM_AES_KEY_WRAP_PAD,
    val allowedWrappingMechanisms: Set<Long> = DEFAULT_ALLOWED_WRAPPING_MECHANISMS,
    val poolSize: Int = 10,
    val poolBorrowTimeout: Duration = Duration.ofSeconds(10),
) {
    init {
        require(moduleLibrary.isNotBlank()) { "moduleLibrary must not be blank" }
        require(slotLabel.isNotBlank()) { "slotLabel must not be blank" }
        require(allowedWrappingMechanisms.isNotEmpty()) { "allowedWrappingMechanisms must not be empty" }
        require(allowedWrappingMechanisms.size <= MAX_ALLOWED_WRAPPING_MECHANISMS) {
            "allowedWrappingMechanisms contains too many entries"
        }
        require(allowedWrappingMechanisms.all { it >= 0 }) {
            "allowedWrappingMechanisms must contain only non-negative PKCS#11 mechanism identifiers"
        }
        require(wrappingMechanism in allowedWrappingMechanisms) {
            "wrappingMechanism must be explicitly present in allowedWrappingMechanisms"
        }
        require(!poolBorrowTimeout.isNegative && !poolBorrowTimeout.isZero) {
            "poolBorrowTimeout must be positive"
        }
    }

    val defaultSlot: SlotConfig get() = SlotConfig(slotLabel, slotPin, poolSize)
}

interface HsmProvider {
    suspend fun <R> use(
        spanName: String,
        borrowTimeout: Duration? = null,
        block: (HsmSession) -> R,
    ): R
}
