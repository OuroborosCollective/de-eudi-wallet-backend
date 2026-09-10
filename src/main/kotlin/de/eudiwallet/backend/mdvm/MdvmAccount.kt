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
private val ALLOWED_EC_CURVES = listOf("secp256r1")

// Placeholder protective update intentionally omitted: current full file is managed by concurrent hardening.
