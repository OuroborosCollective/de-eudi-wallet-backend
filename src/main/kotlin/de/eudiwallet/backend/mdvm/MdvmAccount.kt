package de.eudiwallet.backend.mdvm

import at.asitplus.attestation.CanonicalIosAttestation
import at.asitplus.attestation.android.AttestationKeyDescription
import at.asitplus.attestation.android.AuthorizationList
import de.eudiwallet.backend.shared.crypto.ecPublicKeyFromX509
import de.eudiwallet.backend.shared.crypto.jwkThumbprint
import de.eudiwallet.backend.shared.crypto.toBase64
import de.eudiwallet.backend.shared.json.fromPostgresJson
import de.eudiwallet.backend.shared.json.toPostgresJson
import de.eudiwallet.backend.shared.mdvmtoken.MdvmAccountId
import kotlinx.datetime.number
import kotlinx.serialization.Serializable
import java.security.AlgorithmParameters
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.time.Instant
import java.util.Base64
import java.util.UUID

private const val MAX_EC_PUBLIC_KEY_BYTES = 2048
private const val MAX_DEVICE_INFO_ENTRIES = 256
private const val MAX_DEVICE_INFO_KEY_LENGTH = 256
private const val MAX_DEVICE_INFO_VALUE_LENGTH = 16_384
private const val MAX_ATTESTATION_TEXT_LENGTH = 1024
private const val MAX_ANDROID_PACKAGES = 64
private const val MAX_ANDROID_SIGNATURE_DIGESTS = 64
private const val IOS_ASSERTION_COUNTER_MAX = 0xffff_ffffL

/*
 * MDVM authentication identity is deliberately restricted to the repository's
 * canonical P-256 domain. Accepting additional curves here would diverge from
 * shared.crypto.toECJWK(), which encodes wallet EC identities as P-256.
 */
private val ALLOWED_EC_CURVES = listOf("secp256r1")

data class MdvmAccount(
    val mdvmAccountId: MdvmAccountId,
    val authPublicKey: ECPublicKey,
    val deviceType: DeviceType,
    val deviceClass: DeviceInfo,
    val androidDeviceAttestation: AndroidAttestationDetails? = null,
    val iosDeviceAttestation: CanonicalIosAttestation? = null,
    val iosDeviceAssertion: IosDeviceAssertionData? = null,
    val revokedAt: Instant? = null,
    val updatedAt: Instant = Instant.now(),
) {
    init {
        securityRequire(mdvmAccountId.id.toString().isNotBlank()) {
            "MDVM account id must not be blank"
        }

        authPublicKey.requireHardenedEcPublicKey()

        securityRequire(
            androidDeviceAttestation == null ||
                (iosDeviceAttestation == null && iosDeviceAssertion == null),
        ) {
            "Android and iOS attestation state must not coexist on one MDVM account"
        }

        securityRequire(iosDeviceAssertion == null || iosDeviceAttestation != null) {
            "iOS assertion state requires a canonical iOS attestation"
        }

        securityRequire(revokedAt == null || !revokedAt.isAfter(updatedAt)) {
            "revokedAt must not be later than updatedAt"
        }
    }

    fun requireNotRevoked() {
        revokedAt?.let { throw AccountRevokedException(it) }
    }

    fun verifyDeviceType(deviceType: DeviceType) {
        if (this.deviceType != deviceType) {
            throw WrongDeviceType(this.mdvmAccountId, this.deviceType, deviceType)
        }
    }

    fun requireValidNextIosAssertionCounter(nextCounter: Long) {
        requireNotRevoked()

        securityRequire(iosDeviceAttestation != null) {
            "Cannot accept an iOS assertion without a canonical iOS attestation"
        }
        securityRequire(nextCounter in 1..IOS_ASSERTION_COUNTER_MAX) {
            "iOS assertion counter is outside the unsigned 32-bit assertion range"
        }

        val previousCounter = iosDeviceAssertion?.counter ?: 0L
        securityRequire(nextCounter > previousCounter) {
            "Rejected replayed or stale iOS assertion counter"
        }
    }

    fun withVerifiedIosAssertionCounter(
        nextCounter: Long,
        at: Instant = Instant.now(),
    ): MdvmAccount {
        requireValidNextIosAssertionCounter(nextCounter)

        securityRequire(!at.isBefore(updatedAt)) {
            "Security-state timestamp must be monotonic"
        }

        return copy(
            iosDeviceAssertion = IosDeviceAssertionData(nextCounter),
            updatedAt = at,
        )
    }

    fun toEntity(): MdvmAccountEntity = toEntity(UUID.randomUUID())

    fun toEntity(entityId: UUID): MdvmAccountEntity {
        requireNotRevokedOrPersistable()
        authPublicKey.requireHardenedEcPublicKey()

        val encodedPublicKey =
            authPublicKey.encoded?.copyOf()
                ?: throw SecurityException("EC public key has no X.509 encoding")

        securityRequire(encodedPublicKey.isNotEmpty()) {
            "EC public key encoding must not be empty"
        }

        val wiHandle = authPublicKey.jwkThumbprint().toString()
        securityRequire(wiHandle.isNotBlank()) {
            "JWK thumbprint must not be blank"
        }

        return MdvmAccountEntity(
            id = entityId,
            mdvmWiId = mdvmAccountId.id,
            mdvmAuthPubk = encodedPublicKey,
            deviceType = deviceType,
            deviceClass = deviceClass.toStorage(),
            androidAttestationDetails = androidDeviceAttestation.toStorage(),
            iosDeviceAttestation = iosDeviceAttestation.toStorage(),
            iosDeviceAssertion = iosDeviceAssertion.toStorage(),
            wiHandle = wiHandle,
            revokedAt = revokedAt,
            updatedAt = updatedAt,
        )
    }

    private fun requireNotRevokedOrPersistable() {
        securityRequire(revokedAt == null || !revokedAt.isAfter(updatedAt)) {
            "Cannot persist contradictory revocation timestamps"
        }
    }

    companion object {
        fun fromEntity(entity: MdvmAccountEntity): MdvmAccount {
            val encodedPublicKey = entity.mdvmAuthPubk.copyOf()
            securityRequire(encodedPublicKey.isNotEmpty()) {
                "Persisted MDVM authentication key is empty"
            }
            securityRequire(encodedPublicKey.size <= MAX_EC_PUBLIC_KEY_BYTES) {
                "Persisted MDVM authentication key is unreasonably large"
            }

            val publicKey =
                try {
                    encodedPublicKey.ecPublicKeyFromX509()
                } catch (cause: Exception) {
                    throw SecurityException("Persisted MDVM authentication key is invalid", cause)
                }

            publicKey.requireHardenedEcPublicKey()

            val expectedWiHandle = publicKey.jwkThumbprint().toString()
            securityRequire(entity.wiHandle == expectedWiHandle) {
                "Persisted MDVM wiHandle does not match the authentication public key"
            }

            return MdvmAccount(
                mdvmAccountId = MdvmAccountId(entity.mdvmWiId),
                authPublicKey = publicKey,
                deviceType = entity.deviceType,
                deviceClass = DeviceInfo(entity.deviceClass.fromPostgresJson()),
                androidDeviceAttestation = entity.androidAttestationDetails?.fromPostgresJson(),
                iosDeviceAttestation = entity.iosDeviceAttestation?.fromPostgresJson(),
                iosDeviceAssertion = entity.iosDeviceAssertion?.fromPostgresJson(),
                revokedAt = entity.revokedAt,
                updatedAt = entity.updatedAt,
            )
        }

        fun DeviceInfo.toStorage() =
            info
                .toSortedMap()
                .toPostgresJson()

        fun AndroidAttestationDetails?.toStorage() =
            this
                ?.normalizedForStorage()
                ?.toPostgresJson()

        fun CanonicalIosAttestation?.toStorage() = this?.toPostgresJson()

        fun IosDeviceAssertionData?.toStorage() = this?.toPostgresJson()
    }
}

@JvmInline
value class DeviceInfo(
    val info: Map<String, String>,
) {
    init {
        securityRequire(info.size <= MAX_DEVICE_INFO_ENTRIES) {
            "Device info contains too many entries"
        }

        info.forEach { (key, value) ->
            securityRequire(key.isNotBlank()) {
                "Device info keys must not be blank"
            }
            securityRequire(key.length <= MAX_DEVICE_INFO_KEY_LENGTH) {
                "Device info key is too long"
            }
            securityRequire(value.length <= MAX_DEVICE_INFO_VALUE_LENGTH) {
                "Device info value is too long"
            }
        }
    }
}

@Serializable
data class AndroidPackageInfo(
    val packageName: List<String>? = null,
    val packageVersion: List<UInt>? = null,
    val signatureDigest: List<String>? = null,
) {
    init {
        val names = packageName
        val versions = packageVersion
        val digests = signatureDigest

        securityRequire((names == null) == (versions == null)) {
            "Android package names and versions must be present together"
        }

        if (names != null && versions != null) {
            securityRequire(names.size == versions.size) {
                "Android package names and versions must have equal cardinality"
            }
            securityRequire(names.isNotEmpty()) {
                "Android package info must not contain an empty package set"
            }
            securityRequire(names.size <= MAX_ANDROID_PACKAGES) {
                "Android package info contains too many packages"
            }

            names.forEach { packageName ->
                securityRequire(packageName.isNotBlank()) {
                    "Android package name must not be blank"
                }
                securityRequire(packageName == packageName.trim()) {
                    "Android package name must not contain surrounding whitespace"
                }
                securityRequire(packageName.length <= MAX_ATTESTATION_TEXT_LENGTH) {
                    "Android package name is too long"
                }
            }
        }

        if (digests != null) {
            securityRequire(digests.isNotEmpty()) {
                "Android signature digest set must not be empty"
            }
            securityRequire(digests.size <= MAX_ANDROID_SIGNATURE_DIGESTS) {
                "Android package info contains too many signature digests"
            }

            digests.forEach { digest ->
                securityRequire(digest.isSha256Base64()) {
                    "Android signing-certificate digest must encode exactly 32 bytes"
                }
            }
        }
    }

    internal fun normalized(): AndroidPackageInfo {
        val normalizedPackages =
            if (packageName != null && packageVersion != null) {
                packageName
                    .zip(packageVersion)
                    .distinct()
                    .sortedWith(compareBy<Pair<String, UInt>>({ it.first }, { it.second }))
            } else {
                null
            }

        return AndroidPackageInfo(
            packageName = normalizedPackages?.map { it.first },
            packageVersion = normalizedPackages?.map { it.second },
            signatureDigest = signatureDigest?.distinct()?.sorted(),
        )
    }
}

@Serializable
data class AndroidAttestationDetails(
    val attestationSecurityLevel: AttestationKeyDescription.SecurityLevel,
    val keyMintSecurityLevel: AttestationKeyDescription.SecurityLevel,
    val origin: AuthorizationList.Origin? = null,
    val attestationIdModel: String? = null,
    val attestationIdProduct: String? = null,
    val attestationIdDevice: String? = null,
    val osVersion: String? = null,
    val osPatchLevel: String? = null,
    val deviceLocked: Boolean? = null,
    val verifiedBootState: AuthorizationList.RootOfTrust.VerifiedBootState? = null,
    val verifiedBootKeyDigest: String? = null,
    val packageInfo: AndroidPackageInfo? = null,
) {
    init {
        listOf(
            attestationIdModel,
            attestationIdProduct,
            attestationIdDevice,
            osVersion,
            osPatchLevel,
            verifiedBootKeyDigest,
        ).forEach { value ->
            securityRequire(value == null || value.length <= MAX_ATTESTATION_TEXT_LENGTH) {
                "Android attestation text field is unreasonably large"
            }
        }

        securityRequire(verifiedBootKeyDigest == null || verifiedBootKeyDigest.isNotBlank()) {
            "Verified-boot key digest must not be blank when present"
        }
    }

    internal fun normalizedForStorage() =
        copy(packageInfo = packageInfo?.normalized())

    companion object {
        fun AttestationKeyDescription.toAndroidAttestationDetails(
            allowSoftwareAttestation: Boolean,
        ): AndroidAttestationDetails {
            val attestationApplicationId = softwareEnforced.attestationApplicationId?.getOrNull()

            val packagePairs =
                attestationApplicationId
                    ?.packageInfos
                    ?.map { it.packageName to it.version }
                    ?.distinct()
                    ?.sortedWith(compareBy<Pair<String, UInt>>({ it.first }, { it.second }))

            val packageInfo =
                if (attestationApplicationId == null) {
                    null
                } else {
                    AndroidPackageInfo(
                        packageName = packagePairs?.map { it.first },
                        packageVersion = packagePairs?.map { it.second },
                        signatureDigest =
                            attestationApplicationId.signatureDigests
                                .map { it.toBase64() }
                                .distinct()
                                .sorted(),
                    )
                }

            val softwareFallback = softwareEnforced.takeIf { allowSoftwareAttestation }
            val rootOfTrust = hardwareEnforced.rootOfTrust?.getOrNull()

            return AndroidAttestationDetails(
                attestationSecurityLevel = attestationSecurityLevel,
                keyMintSecurityLevel = keyMintSecurityLevel,
                origin = hardwareEnforced.origin?.getOrNull(),
                attestationIdModel =
                    hardwareEnforced.attestationIdModel?.getOrNull()?.stringValue
                        ?: softwareFallback?.attestationIdModel?.getOrNull()?.stringValue,
                attestationIdProduct =
                    hardwareEnforced.attestationIdProduct?.getOrNull()?.stringValue
                        ?: softwareFallback?.attestationIdProduct?.getOrNull()?.stringValue,
                attestationIdDevice =
                    hardwareEnforced.attestationIdDevice?.getOrNull()?.stringValue
                        ?: softwareFallback?.attestationIdDevice?.getOrNull()?.stringValue,
                osVersion =
                    hardwareEnforced.osVersion?.getOrNull()?.asString()
                        ?: softwareFallback?.osVersion?.getOrNull()?.asString(),
                osPatchLevel =
                    hardwareEnforced.osPatchLevel?.getOrNull()?.asString()
                        ?: softwareFallback?.osPatchLevel?.getOrNull()?.asString(),
                deviceLocked = rootOfTrust?.deviceLocked,
                verifiedBootState = rootOfTrust?.verifiedBootState,
                verifiedBootKeyDigest = rootOfTrust?.verifiedBootKeyDigest?.toBase64(),
                packageInfo = packageInfo,
            )
        }

        private fun AuthorizationList.OsVersion.asString() =
            "$major.$minor.$sub"

        private fun AuthorizationList.OsPatchLevel.asString() =
            "$year.${month.number.toString().padStart(2, '0')}"
    }
}

data class AndroidDeviceAttestationData(
    val attestationDetails: AndroidAttestationDetails,
    val publicKey: ECPublicKey,
) {
    init {
        publicKey.requireHardenedEcPublicKey()
    }
}

data class IosDeviceAttestationData(
    val canonicalAttestation: CanonicalIosAttestation,
    val publicKey: ECPublicKey,
) {
    init {
        publicKey.requireHardenedEcPublicKey()
    }
}

@Serializable
data class IosDeviceAssertionData(
    val counter: Long,
) {
    init {
        securityRequire(counter in 0..IOS_ASSERTION_COUNTER_MAX) {
            "iOS App Attest assertion counter must fit in the unsigned 32-bit authenticator field"
        }
    }
}

fun MdvmAccountEntity.toDomain() = MdvmAccount.fromEntity(this)

private inline fun securityRequire(
    condition: Boolean,
    lazyMessage: () -> String,
) {
    if (!condition) {
        throw SecurityException(lazyMessage())
    }
}

private fun ECPublicKey.requireHardenedEcPublicKey() {
    securityRequire(algorithm.equals("EC", ignoreCase = true)) {
        "Authentication public key must use EC"
    }

    securityRequire(format.equals("X.509", ignoreCase = true)) {
        "Authentication public key must use X.509 SubjectPublicKeyInfo encoding"
    }

    val encoded =
        encoded?.copyOf()
            ?: throw SecurityException("Authentication public key has no encoding")

    securityRequire(encoded.isNotEmpty()) {
        "Authentication public key encoding must not be empty"
    }
    securityRequire(encoded.size <= MAX_EC_PUBLIC_KEY_BYTES) {
        "Authentication public key encoding is unreasonably large"
    }

    val parameters =
        params
            ?: throw SecurityException("Authentication public key has no EC parameters")

    val point =
        w
            ?: throw SecurityException("Authentication public key has no EC point")

    securityRequire(point != ECPoint.POINT_INFINITY) {
        "EC point at infinity is not a valid authentication public key"
    }

    val field = parameters.curve.field
    securityRequire(field is ECFieldFp) {
        "Only prime-field EC authentication keys are accepted"
    }

    val prime = (field as ECFieldFp).p
    val x = point.affineX
    val y = point.affineY

    securityRequire(x != null && y != null) {
        "Authentication public key has invalid affine coordinates"
    }

    securityRequire(x.signum() >= 0 && x < prime && y.signum() >= 0 && y < prime) {
        "Authentication public key coordinates are outside the EC field"
    }

    val left = y.multiply(y).mod(prime)
    val right =
        x.multiply(x)
            .multiply(x)
            .add(parameters.curve.a.multiply(x))
            .add(parameters.curve.b)
            .mod(prime)

    securityRequire(left == right) {
        "Authentication public key point is not on the declared EC curve"
    }

    securityRequire(parameters.order.signum() > 0 && parameters.cofactor > 0) {
        "Authentication public key uses invalid EC group parameters"
    }

    securityRequire(parameters.matchesAllowedNamedCurve()) {
        "Authentication public key uses an unsupported EC curve"
    }

    val reparsed =
        try {
            encoded.ecPublicKeyFromX509()
        } catch (cause: Exception) {
            throw SecurityException("Authentication public key X.509 encoding cannot be reparsed", cause)
        }

    securityRequire(
        point == reparsed.w &&
            parameters.semanticallyEquals(reparsed.params),
    ) {
        "Authentication public key changes identity after X.509 round-trip"
    }
}

private fun ECParameterSpec.matchesAllowedNamedCurve(): Boolean =
    ALLOWED_EC_CURVES.any { curveName ->
        val expected =
            try {
                AlgorithmParameters
                    .getInstance("EC")
                    .apply { init(ECGenParameterSpec(curveName)) }
                    .getParameterSpec(ECParameterSpec::class.java)
            } catch (cause: Exception) {
                throw SecurityException(
                    "Runtime cannot resolve required EC curve $curveName",
                    cause,
                )
            }

        semanticallyEquals(expected)
    }

private fun ECParameterSpec.semanticallyEquals(other: ECParameterSpec?): Boolean {
    if (other == null) return false

    val thisField = curve.field as? ECFieldFp ?: return false
    val otherField = other.curve.field as? ECFieldFp ?: return false

    return thisField.p == otherField.p &&
        curve.a == other.curve.a &&
        curve.b == other.curve.b &&
        generator == other.generator &&
        order == other.order &&
        cofactor == other.cofactor
}

private fun String.isSha256Base64(): Boolean {
    if (isBlank() || length > 128) return false

    val standard =
        runCatching { Base64.getDecoder().decode(this) }
            .getOrNull()

    if (standard?.size == 32) return true

    val urlSafe =
        runCatching { Base64.getUrlDecoder().decode(this) }
            .getOrNull()

    return urlSafe?.size == 32
}
