package de.eudiwallet.backend.shared.hsm

import java.math.BigInteger

/** Public-shape checks for the wallet's ES256/HS256/A256GCM contract. */
internal object HsmOperationChecks {
    private const val SHA256_BYTES = 32
    private const val P256_SIGNATURE_BYTES = 64
    private const val GCM_IV_BYTES = 12
    private const val GCM_TAG_BYTES = 16
    private val p256Order = BigInteger(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16,
    )

    fun requireSha256Digest(digest: ByteArray) {
        if (digest.size != SHA256_BYTES) {
            throw HsmException.SigningFailedException(IllegalArgumentException("Expected a SHA-256 digest"))
        }
    }

    // Shape/range validation is not a replacement for signature verification.
    // High-S signatures remain allowed; changing that would change the protocol.
    fun requireP256Signature(signature: ByteArray) {
        if (signature.size != P256_SIGNATURE_BYTES) {
            throw HsmException.SigningFailedException(IllegalStateException("Invalid P-256 signature length"))
        }
        val r = BigInteger(1, signature.copyOfRange(0, SHA256_BYTES))
        val s = BigInteger(1, signature.copyOfRange(SHA256_BYTES, P256_SIGNATURE_BYTES))
        if (r.signum() <= 0 || r >= p256Order || s.signum() <= 0 || s >= p256Order) {
            throw HsmException.SigningFailedException(IllegalStateException("Invalid P-256 signature scalar"))
        }
    }

    fun requireSha256Mac(mac: ByteArray) {
        if (!isSha256Mac(mac)) {
            throw HsmException.SigningFailedException(IllegalStateException("Invalid HMAC-SHA-256 length"))
        }
    }

    fun isSha256Mac(mac: ByteArray): Boolean = mac.size == SHA256_BYTES

    fun requireGcmDecryptionShape(iv: ByteArray, tag: ByteArray, cipherTextLength: Int) {
        if (iv.size != GCM_IV_BYTES || tag.size != GCM_TAG_BYTES ||
            cipherTextLength !in 0..(Int.MAX_VALUE - GCM_TAG_BYTES)
        ) {
            throw HsmException.DecryptionFailedException(IllegalArgumentException("Invalid wallet AES-GCM shape"))
        }
    }

    fun requireGcmEncryptionResult(iv: ByteArray, resultLength: Int, plainTextLength: Int) {
        if (iv.size != GCM_IV_BYTES || plainTextLength < 0 ||
            resultLength.toLong() != plainTextLength.toLong() + GCM_TAG_BYTES
        ) {
            throw HsmException.EncryptionFailedException(IllegalStateException("Invalid wallet AES-GCM result"))
        }
    }
}
