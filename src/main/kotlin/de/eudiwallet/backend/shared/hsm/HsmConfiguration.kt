package de.eudiwallet.backend.shared.hsm

import de.eudiwallet.backend.shared.hsm.pkcs11.Ck
import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

@ConfigurationProperties(prefix = "hsm")
@Suppress("MagicNumber")
class HsmConfiguration(
    val moduleLibrary: String,
    val slotLabel: String,
    val slotPin: String,
    val wrappingMechanism: Long = Ck.CKM_AES_KEY_WRAP_PAD,
    val poolSize: Int = 10,
    val poolBorrowTimeout: Duration = Duration.ofSeconds(10),
) {
    val defaultSlot: SlotConfig get() = SlotConfig(slotLabel, slotPin, poolSize)
}

interface HsmProvider {
    suspend fun <R> use(
        spanName: String,
        borrowTimeout: Duration? = null,
        block: (HsmSession) -> R,
    ): R
}
