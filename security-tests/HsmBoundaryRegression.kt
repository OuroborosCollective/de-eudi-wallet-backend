package de.eudiwallet.backend.shared.hsm

import de.eudiwallet.backend.shared.hsm.pkcs11.withUtf8Pin
import java.math.BigInteger
import java.nio.charset.CharacterCodingException
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

private var checks = 0
private fun verify(ok: Boolean, name: String) {
    check(ok) { name }
    checks++
}

private inline fun <reified T : Throwable> rejects(name: String, block: () -> Unit) {
    try {
        block()
    } catch (failure: Throwable) {
        verify(failure is T, "$name: wrong exception type")
        return
    }
    error("$name: accepted invalid input")
}

private fun slotConfiguration() {
    val pin = "test-only-sensitive-pin"
    val label = "test-only-sensitive-label"
    val config = SlotConfig(label, pin, 4, 2)
    verify(!config.toString().contains(pin), "SlotConfig must redact PIN")
    verify(!config.toString().contains(label), "SlotConfig must redact label")
    verify(config.toString().contains("pin=[REDACTED]"), "Redaction must be explicit")
    verify(config.workerCount == 2, "Explicit worker count")
    verify(config.copy(threadCount = null).workerCount == 4, "Default worker count")
    verify(config.copy(pin = "different-test-pin").toString() == config.toString(), "PIN-independent diagnostics")
    val (actualLabel, actualPin, poolSize, threadCount) = config
    verify(actualLabel == label && actualPin == pin && poolSize == 4 && threadCount == 2, "Binding compatibility")
    rejects<IllegalArgumentException>("zero pool") { SlotConfig(label, pin, 0) }
    rejects<IllegalArgumentException>("negative pool") { SlotConfig(label, pin, -1) }
    rejects<IllegalArgumentException>("zero workers") { SlotConfig(label, pin, 1, 0) }
    rejects<IllegalArgumentException>("negative workers") { SlotConfig(label, pin, 1, -1) }
}

private fun pinLifecycle() {
    val samples = listOf("", "012345", "äöü", "漢字", "\u0000a\n", "\uD83D\uDE00", "x".repeat(4096))
    for (sample in samples) {
        val input = sample.toCharArray()
        val before = input.copyOf()
        var retained: ByteArray? = null
        val answer = withUtf8Pin(input) { encoded ->
            retained = encoded
            verify(encoded.contentEquals(sample.toByteArray(StandardCharsets.UTF_8)), "UTF-8 roundtrip")
            42
        }
        verify(answer == 42, "Callback result preserved")
        verify(retained != null && retained!!.all { it == 0.toByte() }, "PIN bytes cleared on success")
        verify(input.contentEquals(before), "Encoder must not mutate borrowed chars")
        input.fill('\u0000')
        before.fill('\u0000')
    }
    var retained: ByteArray? = null
    val marker = IllegalStateException("deliberate-test-failure")
    try {
        withUtf8Pin("failure-path-pin".toCharArray()) { bytes ->
            retained = bytes
            throw marker
        }
    } catch (failure: IllegalStateException) {
        verify(failure === marker, "Exception identity preserved")
    }
    verify(retained != null && retained!!.all { it == 0.toByte() }, "PIN bytes cleared on failure")
    for (invalid in listOf(charArrayOf('\uD800'), charArrayOf('\uDC00'), charArrayOf('a', '\uD800', 'b'))) {
        var called = false
        rejects<CharacterCodingException>("malformed UTF-16") {
            withUtf8Pin(invalid) { called = true }
        }
        verify(!called, "Malformed PIN must not reach callback")
    }
}

private val order = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
private fun scalar(value: BigInteger): ByteArray {
    val bytes = value.toByteArray()
    val out = ByteArray(32)
    val count = minOf(32, bytes.size)
    System.arraycopy(bytes, bytes.size - count, out, 32 - count, count)
    return out
}

private fun cryptographicShapes() {
    for (length in 0..128) {
        val bytes = ByteArray(length)
        if (length == 32) {
            HsmOperationChecks.requireSha256Digest(bytes)
            HsmOperationChecks.requireSha256Mac(bytes)
            verify(HsmOperationChecks.isSha256Mac(bytes), "HS256 length accepted")
        } else {
            rejects<HsmException.SigningFailedException>("digest length") { HsmOperationChecks.requireSha256Digest(bytes) }
            rejects<HsmException.SigningFailedException>("MAC output length") { HsmOperationChecks.requireSha256Mac(bytes) }
            verify(!HsmOperationChecks.isSha256Mac(bytes), "HS256 length rejected")
        }
        if (length != 64) rejects<HsmException.SigningFailedException>("ECDSA length") {
            HsmOperationChecks.requireP256Signature(bytes)
        }
    }
    for (r in listOf(BigInteger.ZERO, BigInteger.ONE, order - BigInteger.ONE, order, order + BigInteger.ONE)) {
        for (s in listOf(BigInteger.ZERO, BigInteger.ONE, order - BigInteger.ONE, order, order + BigInteger.ONE)) {
            val signature = scalar(r) + scalar(s)
            if (r.signum() > 0 && r < order && s.signum() > 0 && s < order) {
                HsmOperationChecks.requireP256Signature(signature)
                verify(true, "Valid scalar boundary")
            } else rejects<HsmException.SigningFailedException>("ECDSA scalar boundary") {
                HsmOperationChecks.requireP256Signature(signature)
            }
        }
    }
    // Finite public-input fuzzing, not randomness used for production keys.
    val random = java.util.Random(20260910L)
    repeat(10000) {
        val signature = ByteArray(random.nextInt(130)).also(random::nextBytes)
        val expected = signature.size == 64 &&
            BigInteger(1, signature.copyOfRange(0, 32)).let { it.signum() > 0 && it < order } &&
            BigInteger(1, signature.copyOfRange(32, 64)).let { it.signum() > 0 && it < order }
        val accepted = try {
            HsmOperationChecks.requireP256Signature(signature)
            true
        } catch (_: HsmException.SigningFailedException) { false }
        verify(accepted == expected, "ECDSA public-input fuzz oracle")
    }
}

private fun realJcaSignatures() {
    val generator = KeyPairGenerator.getInstance("EC")
    generator.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
    val keyPair = generator.generateKeyPair()
    repeat(32) { sequence ->
        val message = "wallet-boundary-regression-$sequence".toByteArray()
        val signer = Signature.getInstance("SHA256withECDSAinP1363Format")
        signer.initSign(keyPair.private)
        signer.update(message)
        val signature = signer.sign()
        HsmOperationChecks.requireP256Signature(signature)
        val verifier = Signature.getInstance("SHA256withECDSAinP1363Format")
        verifier.initVerify(keyPair.public)
        verifier.update(message)
        verify(verifier.verify(signature), "Real JCA signature verifies")
        val r = BigInteger(1, signature.copyOfRange(0, 32))
        val s = BigInteger(1, signature.copyOfRange(32, 64))
        val alternate = scalar(r) + scalar(order - s)
        HsmOperationChecks.requireP256Signature(alternate)
        verifier.initVerify(keyPair.public)
        verifier.update(message)
        verify(verifier.verify(alternate), "Both valid S forms remain supported")
        verifier.initVerify(keyPair.public)
        verifier.update(message + byteArrayOf(1))
        verify(!verifier.verify(signature), "Actual verifier rejects changed message")
    }
}

private fun gcmContracts() {
    for (ivLength in 0..20) for (tagLength in 0..24) {
        val iv = ByteArray(ivLength)
        val tag = ByteArray(tagLength)
        if (ivLength == 12 && tagLength == 16) {
            HsmOperationChecks.requireGcmDecryptionShape(iv, tag, 0)
            verify(true, "Empty plaintext remains supported")
        } else rejects<HsmException.DecryptionFailedException>("GCM iv/tag shape") {
            HsmOperationChecks.requireGcmDecryptionShape(iv, tag, 0)
        }
    }
    val iv = ByteArray(12)
    val tag = ByteArray(16)
    HsmOperationChecks.requireGcmDecryptionShape(iv, tag, Int.MAX_VALUE - 16)
    verify(true, "Largest non-overflowing concatenation")
    for (length in listOf(-1, Int.MAX_VALUE - 15, Int.MAX_VALUE)) rejects<HsmException.DecryptionFailedException>("concat overflow") {
        HsmOperationChecks.requireGcmDecryptionShape(iv, tag, length)
    }
    rejects<HsmException.EncryptionFailedException>("cipher length mismatch") {
        HsmOperationChecks.requireGcmEncryptionResult(iv, 16, 1)
    }
    rejects<HsmException.EncryptionFailedException>("cipher length overflow") {
        HsmOperationChecks.requireGcmEncryptionResult(iv, Int.MIN_VALUE + 15, Int.MAX_VALUE)
    }
    rejects<HsmException.EncryptionFailedException>("bad encryption IV") {
        HsmOperationChecks.requireGcmEncryptionResult(ByteArray(11), 16, 0)
    }
    rejects<HsmException.EncryptionFailedException>("negative plaintext length") {
        HsmOperationChecks.requireGcmEncryptionResult(iv, 15, -1)
    }
    val generator = KeyGenerator.getInstance("AES")
    generator.init(256)
    val key = generator.generateKey()
    val rng = SecureRandom()
    for (length in listOf(0, 1, 16, 31, 4096)) {
        val nonce = ByteArray(12).also(rng::nextBytes)
        val plaintext = ByteArray(length).also(rng::nextBytes)
        val aad = "bound-context".toByteArray()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        val result = cipher.doFinal(plaintext)
        HsmOperationChecks.requireGcmEncryptionResult(nonce, result.size, plaintext.size)
        HsmOperationChecks.requireGcmDecryptionShape(nonce, result.takeLast(16).toByteArray(), result.size - 16)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        verify(cipher.doFinal(result).contentEquals(plaintext), "Real AES-GCM roundtrip")
        result[result.lastIndex] = (result.last().toInt() xor 1).toByte()
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        rejects<AEADBadTagException>("Actual AEAD rejects changed tag") { cipher.doFinal(result) }
    }
}

fun main() {
    slotConfiguration()
    pinLifecycle()
    cryptographicShapes()
    realJcaSignatures()
    gcmContracts()
    println("HSM_BOUNDARY_TESTS_PASS checks=$checks fuzzCases=10000 jcaEcdsaCases=32 jcaGcmCases=5")
}
