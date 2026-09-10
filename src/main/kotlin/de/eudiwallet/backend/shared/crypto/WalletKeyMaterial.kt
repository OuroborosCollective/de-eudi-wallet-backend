package de.eudiwallet.backend.shared.crypto

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.InvalidKeySpecException
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * Input boundary shared by the public functions in Key.kt.
 *
 * It validates key material, not ownership, attestation, user consent, or
 * authorization. No provider is installed/reordered here. Limits apply before
 * ASN.1/PEM parsing and are deliberately independent of HTTP request limits.
 */
internal object WalletKeyMaterial {
    internal const val MAX_PUBLIC_KEY_BYTES = 2048
    internal const val MAX_PRIVATE_KEY_BYTES = 16 * 1024
    internal const val MAX_PEM_BYTES = 64 * 1024
    internal const val MAX_CERTIFICATE_BYTES = 64 * 1024

    private val p256: ECParameterSpec =
        AlgorithmParameters.getInstance("EC", BOUNCY_CASTLE_PROVIDER).run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }

    @Suppress("TooGenericExceptionCaught")
    fun decodePublicKey(encoded: ByteArray): ECPublicKey =
        try {
            require(encoded.size in 1..MAX_PUBLIC_KEY_BYTES) { "Invalid wallet public-key size" }
            val parsed =
                KeyFactory.getInstance("EC", BOUNCY_CASTLE_PROVIDER)
                    .generatePublic(X509EncodedKeySpec(encoded)) as ECPublicKey
            canonicalP256(parsed)
        } catch (ex: InvalidKeySpecException) {
            throw ex
        } catch (ex: Exception) {
            throw InvalidKeySpecException("Invalid wallet EC public key", ex)
        }

    fun canonicalP256(key: ECPublicKey): ECPublicKey {
        // Compare the entire trusted domain BEFORE doing arithmetic on the point.
        // Matching the curve equation alone must not silently replace G, n, or h.
        val parameters = requireNotNull(key.params) { "Missing wallet EC parameters" }
        val point = requireNotNull(key.w) { "Missing wallet EC point" }
        require(
            parameters.curve == p256.curve &&
                parameters.generator == p256.generator &&
                parameters.order == p256.order &&
                parameters.cofactor == p256.cofactor,
        ) { "Wallet public key must use the complete P-256 domain" }
        require(point != ECPoint.POINT_INFINITY) { "Invalid wallet EC point" }
        val prime = (p256.curve.field as ECFieldFp).p
        val x = requireNotNull(point.affineX) { "Missing wallet EC coordinate" }
        val y = requireNotNull(point.affineY) { "Missing wallet EC coordinate" }
        require(x.signum() >= 0 && x < prime && y.signum() >= 0 && y < prime) {
            "Wallet EC coordinates are outside the field"
        }
        require(
            y.multiply(y).mod(prime) ==
                x.multiply(x).multiply(x).add(p256.curve.a.multiply(x)).add(p256.curve.b).mod(prime),
        ) { "Wallet public key is not on P-256" }
        // P-256 has prime order and cofactor one; every finite on-curve point
        // belongs to the intended subgroup. This checks public data, not secrets.
        return KeyFactory.getInstance("EC", BOUNCY_CASTLE_PROVIDER)
            .generatePublic(ECPublicKeySpec(point, p256)) as ECPublicKey
    }

    fun decodePrivateKey(encoded: ByteArray): ECPrivateKey {
        if (encoded.size !in 1..MAX_PRIVATE_KEY_BYTES) {
            throw InvalidKeySpecException("Invalid EC private-key size")
        }
        return KeyFactory.getInstance("EC", BOUNCY_CASTLE_PROVIDER)
            .generatePrivate(PKCS8EncodedKeySpec(encoded)) as ECPrivateKey
    }

    /** Supports unencrypted PKCS#8 and the existing SEC1/PEMKeyPair format. */
    fun readPrivateKey(input: InputStream): ECPrivateKey =
        input.use { stream ->
            val pemBytes = stream.readNBytes(MAX_PEM_BYTES + 1)
            try {
                if (pemBytes.size !in 1..MAX_PEM_BYTES) {
                    throw InvalidKeySpecException("Invalid EC private-key PEM size")
                }
                PEMParser(InputStreamReader(ByteArrayInputStream(pemBytes), StandardCharsets.US_ASCII)).use { parser ->
                    val privateKeyInfo =
                        when (val parsed = parser.readObject()) {
                            is PrivateKeyInfo -> parsed
                            is PEMKeyPair -> parsed.privateKeyInfo
                            else -> throw InvalidKeySpecException("Expected an unencrypted EC private key")
                        }
                    if (parser.readObject() != null) {
                        throw InvalidKeySpecException("Expected exactly one EC private-key PEM object")
                    }
                    val der = privateKeyInfo.encoded
                    try {
                        decodePrivateKey(der)
                    } finally {
                        der.fill(0)
                    }
                }
            } finally {
                // Best effort only: provider/parser objects can retain copies.
                pemBytes.fill(0)
            }
        }

    /** Owns and closes the Resource's stream, including malformed-input paths. */
    fun readCertificate(input: InputStream): X509Certificate =
        input.use { stream ->
            val encoded = stream.readNBytes(MAX_CERTIFICATE_BYTES + 1)
            require(encoded.size in 1..MAX_CERTIFICATE_BYTES) { "Invalid certificate resource size" }
            // Per-call factory avoids relying on unspecified shared-instance safety.
            CertificateFactory.getInstance("X.509", BOUNCY_CASTLE_PROVIDER)
                .generateCertificate(ByteArrayInputStream(encoded)) as X509Certificate
        }
}
