package de.eudiwallet.backend.shared.keyrollover

import de.eudiwallet.backend.shared.hsm.HsmKey
import de.eudiwallet.backend.shared.hsm.HsmKeyClass
import de.eudiwallet.backend.shared.hsm.HsmKeyId
import de.eudiwallet.backend.shared.hsm.HsmKeyRef
import de.eudiwallet.backend.shared.hsm.HsmProvider
import de.eudiwallet.backend.shared.hsm.findActiveKeys
import de.eudiwallet.backend.shared.hsm.isActiveAt
import de.eudiwallet.backend.shared.telemetry.MetricsService
import de.eudiwallet.backend.shared.telemetry.runBlockingWithTelemetry
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.coroutines.CoroutineDispatcher
import java.time.Instant
import java.time.LocalDate
import java.util.concurrent.atomic.AtomicReference

data class SymmetricKeySet(
    val validKeys: List<HsmKey>,
    val primaryId: HsmKeyId,
)

class SymmetricKeyLineage<T : HsmKeyRef>(
    override val name: String,
    private val keyPrefix: String,
    private val keyClass: HsmKeyClass<T>,
    private val hsmProvider: HsmProvider,
    private val ioDispatcher: CoroutineDispatcher,
    private val metricsService: MetricsService,
) : RefreshableLineage,
    KeySource<SymmetricKeySet> {
    private val log = KotlinLogging.logger {}
    private val held = AtomicReference<SymmetricKeySet?>(null)

    override fun current(): SymmetricKeySet {
        val keySet = requireNotNull(held.get()) { "$name lineage has no resolved key" }
        val primary =
            keySet.validKeys.find { it.keyId == keySet.primaryId }
                ?: error("$name lineage primary key is not present in its valid-key set")
        check(primary.isActiveAt(Instant.now())) {
            "$name lineage primary key is outside its declared validity window"
        }
        return keySet
    }

    fun initialize() = roll(failFast = true)

    override fun refresh() = roll(failFast = false)

    private fun roll(failFast: Boolean) {
        val keys = scanKeys().findActiveKeys(Instant.now())
        val primary = keys.firstOrNull()
        if (primary == null) {
            check(!failFast) { "$name primary key not found for prefix '$keyPrefix'" }
            logHoldingLastGood()
            return
        }

        val candidate = SymmetricKeySet(keys, primary.keyId)
        val previous = held.getAndSet(candidate)
        metricsService.setPrimaryKeyExpiryDate(name, primary.endDate)
        if (previous != null && previous.primaryId != candidate.primaryId) {
            log.info { "$name: rolled over ${previous.primaryId} -> ${candidate.primaryId}" }
        }
    }

    private fun logHoldingLastGood() {
        val heldSet = held.get()
        val heldPrimary = heldSet?.validKeys?.find { it.keyId == heldSet.primaryId }
        if (heldPrimary != null && !heldPrimary.isActiveAt(Instant.now())) {
            held.compareAndSet(heldSet, null)
            log.error {
                "$name: held primary ${heldSet.primaryId} is outside its declared validity window; no valid primary " +
                    "in HSM scan for prefix '$keyPrefix' — cryptographic use is disabled until a valid key resolves"
            }
        } else {
            log.warn {
                "$name: no valid primary in HSM scan for prefix '$keyPrefix'; holding still-valid " +
                    "${heldSet?.primaryId}"
            }
        }
    }

    private fun scanKeys(): List<HsmKey> =
        runBlockingWithTelemetry(ioDispatcher) {
            hsmProvider.use("Scan $name keys") { hsm ->
                hsm.findKeysByPrefix(keyPrefix, Instant.now(), keyClass)
            }
        }
}

fun stubSymKeySource(): KeySource<SymmetricKeySet> =
    KeySource {
        SymmetricKeySet(
            listOf(HsmKey(HsmKeyId(STUB), STUB, LocalDate.MIN, LocalDate.MAX)),
            HsmKeyId(STUB),
        )
    }
