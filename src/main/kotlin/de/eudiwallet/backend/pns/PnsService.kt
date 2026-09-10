package de.eudiwallet.backend.pns

import de.eudiwallet.backend.shared.mdvmtoken.MdvmAccountId
import de.eudiwallet.backend.shared.telemetry.TelemetryService
import org.springframework.stereotype.Service
import java.util.UUID

@Service
class PnsService(
    private val repository: PnsRepository,
    private val telemetryService: TelemetryService,
) {
    suspend fun register(
        accountId: MdvmAccountId,
        mppRegistrationToken: String,
    ) = telemetryService.withSpan("PnsService.register") {
        require(mppRegistrationToken.isNotBlank()) {
            "MPP registration token must not be blank"
        }
        require(mppRegistrationToken.length <= MAX_MPP_REGISTRATION_TOKEN_LENGTH) {
            "MPP registration token exceeds the maximum supported length"
        }

        repository.upsertByAccountId(
            id = UUID.randomUUID(),
            accountId = accountId.id,
            mppRegistrationToken = mppRegistrationToken,
        )
    }

    suspend fun delete(accountId: MdvmAccountId) =
        telemetryService.withSpan("PnsService.delete") {
            repository.deleteByAccountId(accountId.id)
        }
}
