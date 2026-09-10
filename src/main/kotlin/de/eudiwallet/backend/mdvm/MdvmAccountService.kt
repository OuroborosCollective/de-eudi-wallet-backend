package de.eudiwallet.backend.mdvm

import de.eudiwallet.backend.mdvm.MdvmAccount.Companion.toStorage
import de.eudiwallet.backend.shared.mdvmtoken.MdvmAccountId
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import org.springframework.dao.DuplicateKeyException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.security.interfaces.ECPublicKey
import java.util.UUID

private class NonMonotonicIosAssertionCounter(
    private val previousCounter: Long,
    private val receivedCounter: Long,
) : MdvmException("iOS App Attest assertion counter did not advance") {
    override val internalErrorCode = InternalErrorCode.DCAS_ATTESTATION_COUNTER_INVALID

    override fun diagnosticDetails() =
        mapOf(
            "mdvm.error" to "NonMonotonicIosAssertionCounter",
            "mdvm.previous_assertion_counter" to previousCounter.toString(),
            "mdvm.received_assertion_counter" to receivedCounter.toString(),
        )
}

@Service
class MdvmAccountService(
    private val mdvmAccountRepository: MdvmAccountRepository,
    private val telemetryService: TelemetryService,
    private val mdvmService: MdvmService,
) {
    suspend fun createIosAccount(
        authPubk: ECPublicKey,
        deviceClass: DeviceInfo,
        deviceAttestation: IosDeviceAttestationData?,
        deviceAssertion: IosDeviceAssertionData?,
    ): MdvmAccount =
        telemetryService.withSpan("MdvmAccountService.createIosAccount") {
            val account =
                MdvmAccount(
                    mdvmAccountId = MdvmAccountId(UUID.randomUUID()),
                    authPublicKey = authPubk,
                    deviceType = DeviceType.IOS,
                    deviceClass = deviceClass,
                    iosDeviceAttestation = deviceAttestation?.canonicalAttestation,
                    iosDeviceAssertion = deviceAssertion,
                )
            saveNewAccount(account)
        }

    suspend fun createAndroidAccount(
        authPubk: ECPublicKey,
        deviceClass: DeviceInfo,
        attestationData: AndroidDeviceAttestationData?,
    ): MdvmAccount =
        telemetryService.withSpan("MdvmAccountService.createAndroidAccount") {
            val account =
                MdvmAccount(
                    mdvmAccountId = MdvmAccountId(UUID.randomUUID()),
                    authPublicKey = authPubk,
                    deviceType = DeviceType.ANDROID,
                    deviceClass = deviceClass,
                    androidDeviceAttestation = attestationData?.attestationDetails,
                )
            saveNewAccount(account)
        }

    private suspend fun saveNewAccount(account: MdvmAccount): MdvmAccount =
        try {
            mdvmAccountRepository.save(account.toEntity()).toDomain()
        } catch (ex: DuplicateKeyException) {
            throw KeyAlreadyRegisteredException(ex)
        }

    suspend fun findMdvmAccount(accountId: MdvmAccountId): MdvmAccount =
        telemetryService.withSpan("MdvmAccountService.findMdvmAccount") {
            mdvmAccountRepository.findByMdvmWiId(accountId.id)?.toDomain() ?: throw AccountNotFound(accountId)
        }

    suspend fun revokeByWiHandle(wiHandle: String): MdvmAccountId? =
        telemetryService.withSpan("MdvmAccountService.revokeByWiHandle") {
            mdvmAccountRepository.revokeByWiHandleReturningId(wiHandle)?.let { MdvmAccountId(it) }
        }

    /**
     * Persist mutable device-security state only after re-reading the account under
     * a row lock. Expensive cryptographic attestation verification intentionally
     * remains outside this transaction, but freshness/plausibility decisions that
     * depend on persisted state are repeated here against the locked latest row.
     *
     * Null security evidence means "no new evidence", never "erase the last
     * verified evidence". This keeps the explicitly configured integrity-skip path
     * usable without allowing it to roll security state backwards.
     */
    @Transactional
    suspend fun saveNonRevokedAccount(
        mdvmAccountId: MdvmAccountId,
        deviceClass: DeviceInfo,
        iosDeviceAssertion: IosDeviceAssertionData? = null,
        androidAttestationDetails: AndroidAttestationDetails? = null,
    ) = telemetryService.withSpan("MdvmAccountService.saveNonRevokedAccount") {
        val account =
            mdvmAccountRepository.findByMdvmWiIdWithLockNoWait(mdvmAccountId.id)
                ?.toDomain() ?: throw AccountNotFound(mdvmAccountId)
        account.requireNotRevoked()

        iosDeviceAssertion?.let { assertion ->
            account.verifyDeviceType(DeviceType.IOS)
            val previousCounter = account.iosDeviceAssertion?.counter ?: 0L
            if (assertion.counter <= previousCounter) {
                throw NonMonotonicIosAssertionCounter(previousCounter, assertion.counter)
            }
            account.requireValidNextIosAssertionCounter(assertion.counter)
        }

        androidAttestationDetails?.let { attestation ->
            account.verifyDeviceType(DeviceType.ANDROID)
            mdvmService.verifyAndroidDeviceProperties(attestation, account.androidDeviceAttestation)
        }

        if (account.deviceType == DeviceType.IOS) {
            mdvmService.verifyIosDeviceProperties(deviceClass, account.deviceClass)
        }

        mdvmAccountRepository.updateAccount(
            mdvmWiId = mdvmAccountId.id,
            deviceClass = deviceClass.toStorage(),
            iosDeviceAssertion = (iosDeviceAssertion ?: account.iosDeviceAssertion).toStorage(),
            androidAttestationDetails =
                (androidAttestationDetails ?: account.androidDeviceAttestation).toStorage(),
        )
    }

    suspend fun deleteMdvmAccount(accountId: MdvmAccountId) =
        telemetryService.withSpan("MdvmAccountService.deleteMdvmAccount") {
            mdvmAccountRepository.deleteByMdvmWiId(accountId.id)
        }
}
