package de.eudiwallet.backend.shared.crypto

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.IOException
import java.io.InputStream
import java.io.StringReader
import java.io.StringWriter
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Security
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.Base64
import java.util.Date
import java.util.Random
import java.util.concurrent.Callable
import java.util.concurrent.Executors

private var checks = 0
private fun checkCase(name: String, block: () -> Unit) {
    block()
    checks++
    println("PASS $name")
}

private fun rejects(block: () -> Unit) {
    val failure = runCatching(block).exceptionOrNull()
    check(failure is Exception) { "Expected input rejection, not acceptance or a VM error" }
}

private class ObservedStream(private val data: ByteArray, private val failRead: Boolean = false) : InputStream() {
    var closed = false
    var consumed = 0
    override fun read(): Int {
        if (failRead) throw IOException("Deliberate regression-test read failure")
        return if (consumed == data.size) -1 else data[consumed++].toInt() and 255
    }
    override fun close() { closed = true }
}

// Deliberately malformed public inputs, not mocked cryptographic verification.
private class AdversarialPublicKey(
    private val parameters: ECParameterSpec,
    private val point: ECPoint,
) : ECPublicKey {
    override fun getParams() = parameters
    override fun getW() = point
    override fun getAlgorithm() = "EC"
    override fun getFormat() = "X.509"
    override fun getEncoded(): ByteArray = error("The validator must rebuild validated public data")
}

private fun pem(label: String, bytes: ByteArray): ByteArray =
    ("-----BEGIN $label-----\n" + Base64.getMimeEncoder(64, byteArrayOf(10)).encodeToString(bytes) +
        "\n-----END $label-----\n").toByteArray(Charsets.US_ASCII)

fun main() {
    val providersBefore = Security.getProviders().toList()
    val generator = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
    val pair = generator.generateKeyPair()
    val publicKey = pair.public as ECPublicKey
    val parameters = publicKey.params
    val privateDer = pair.private.encoded
    val pkcs8 = pem("PRIVATE KEY", privateDer)
    val sec1 = StringWriter().also { writer -> JcaPEMWriter(writer).use { it.writeObject(KeyFactory.getInstance("EC", BOUNCY_CASTLE_PROVIDER).generatePrivate(PKCS8EncodedKeySpec(privateDer))) } }
        .toString().toByteArray(Charsets.US_ASCII)
    val message = "wallet-key-boundary-regression".toByteArray()
    val signed = Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(message); sign() }

    checkCase("PKCS8 legacy cast incompatibility is reproducible with real parser") {
        PEMParser(StringReader(pkcs8.toString(Charsets.US_ASCII))).use { parser ->
            val parsed = parser.readObject()
            check(parsed is PrivateKeyInfo)
            rejects { parsed as PEMKeyPair }
        }
    }
    checkCase("P256 public DER preserves signature identity") {
        val decoded = WalletKeyMaterial.decodePublicKey(publicKey.encoded)
        check(decoded.w == publicKey.w)
        check(Signature.getInstance("SHA256withECDSA").run { initVerify(decoded); update(message); verify(signed) })
        check(!Signature.getInstance("SHA256withECDSA").run {
            initVerify(decoded); update("different-action".toByteArray()); verify(signed)
        })
    }
    checkCase("explicit P256 and repeated canonicalization preserve point and bytes") {
        val explicit = KeyFactory.getInstance("EC", BOUNCY_CASTLE_PROVIDER)
            .generatePublic(ECPublicKeySpec(publicKey.w, ECParameterSpec(parameters.curve, parameters.generator, parameters.order, parameters.cofactor))) as ECPublicKey
        val canonical = WalletKeyMaterial.canonicalP256(explicit)
        check(WalletKeyMaterial.decodePublicKey(explicit.encoded).w == publicKey.w)
        check(WalletKeyMaterial.canonicalP256(canonical).encoded.contentEquals(canonical.encoded))
    }
    for (curve in listOf("secp384r1", "secp521r1", "secp256k1")) {
        checkCase("reject non-wallet domain $curve") {
            val key = KeyPairGenerator.getInstance("EC", BOUNCY_CASTLE_PROVIDER)
                .apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair().public as ECPublicKey
            rejects { WalletKeyMaterial.decodePublicKey(key.encoded) }
            rejects { WalletKeyMaterial.canonicalP256(key) }
        }
    }
    for ((name, bad) in listOf(
        "order" to ECParameterSpec(parameters.curve, parameters.generator, parameters.order.subtract(BigInteger.ONE), 1),
        "cofactor" to ECParameterSpec(parameters.curve, parameters.generator, parameters.order, 2),
        "generator" to ECParameterSpec(parameters.curve, publicKey.w, parameters.order, 1),
    )) {
        checkCase("reject altered $name despite identical curve equation") {
            rejects { WalletKeyMaterial.canonicalP256(AdversarialPublicKey(bad, publicKey.w)) }
        }
    }
    val prime = (parameters.curve.field as java.security.spec.ECFieldFp).p
    for ((name, point) in listOf(
        "infinity" to ECPoint.POINT_INFINITY,
        "off-curve" to ECPoint(BigInteger.ONE, BigInteger.ONE),
        "negative-x" to ECPoint(BigInteger.valueOf(-1), publicKey.w.affineY),
        "x-equals-p" to ECPoint(prime, publicKey.w.affineY),
        "y-equals-p" to ECPoint(publicKey.w.affineX, prime),
        "oversized-coordinate" to ECPoint(BigInteger.ONE.shiftLeft(200_000), BigInteger.ONE),
    )) {
        checkCase("reject $name before unbounded curve arithmetic") {
            rejects { WalletKeyMaterial.canonicalP256(AdversarialPublicKey(parameters, point)) }
        }
    }
    checkCase("empty oversized truncated and non-EC public encodings fail closed") {
        rejects { WalletKeyMaterial.decodePublicKey(byteArrayOf()) }
        rejects { WalletKeyMaterial.decodePublicKey(ByteArray(WalletKeyMaterial.MAX_PUBLIC_KEY_BYTES + 1)) }
        for (length in publicKey.encoded.indices) {
            rejects { WalletKeyMaterial.decodePublicKey(publicKey.encoded.copyOf(length)) }
        }
        val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        rejects { WalletKeyMaterial.decodePublicKey(rsa.public.encoded) }
        rejects { WalletKeyMaterial.decodePrivateKey(rsa.private.encoded) }
    }
    checkCase("unencrypted PKCS8 and legacy SEC1 private keys remain functional") {
        for (encoded in listOf(pkcs8, sec1)) {
            val stream = ObservedStream(encoded)
            val key = WalletKeyMaterial.readPrivateKey(stream)
            check(stream.closed)
            val signature = Signature.getInstance("SHA256withECDSA").run { initSign(key); update(message); sign() }
            check(Signature.getInstance("SHA256withECDSA").run { initVerify(publicKey); update(message); verify(signature) })
        }
        check(WalletKeyMaterial.decodePrivateKey(privateDer).s == (pair.private as java.security.interfaces.ECPrivateKey).s)
    }
    checkCase("reject empty public malformed and multiple private PEM objects and close streams") {
        for (encoded in listOf(byteArrayOf(), pem("PUBLIC KEY", publicKey.encoded), "not a key".toByteArray(), pkcs8 + pkcs8)) {
            val stream = ObservedStream(encoded)
            rejects { WalletKeyMaterial.readPrivateKey(stream) }
            check(stream.closed)
        }
        rejects { WalletKeyMaterial.decodePrivateKey(byteArrayOf()) }
        rejects { WalletKeyMaterial.decodePrivateKey(ByteArray(WalletKeyMaterial.MAX_PRIVATE_KEY_BYTES + 1)) }
    }
    checkCase("private PEM bound enforced before parsing and input is closed") {
        val stream = ObservedStream(ByteArray(WalletKeyMaterial.MAX_PEM_BYTES * 2))
        rejects { WalletKeyMaterial.readPrivateKey(stream) }
        check(stream.closed && stream.consumed == WalletKeyMaterial.MAX_PEM_BYTES + 1)
    }
    val name = X500Name("CN=ephemeral-regression-only")
    val certificate = JcaX509v3CertificateBuilder(
        name, BigInteger.ONE, Date.from(Instant.parse("2026-01-01T00:00:00Z")),
        Date.from(Instant.parse("2027-01-01T00:00:00Z")), name, pair.public,
    ).build(JcaContentSignerBuilder("SHA256withECDSA").setProvider(BOUNCY_CASTLE_PROVIDER).build(pair.private))
    checkCase("valid DER and PEM X509 certificate resources are closed") {
        for (encoded in listOf(certificate.encoded, pem("CERTIFICATE", certificate.encoded))) {
            val stream = ObservedStream(encoded)
            check(WalletKeyMaterial.readCertificate(stream).encoded.contentEquals(certificate.encoded))
            check(stream.closed)
        }
    }
    checkCase("malformed oversized and failed-read resources are closed") {
        for (stream in listOf(ObservedStream(byteArrayOf(1, 2, 3)), ObservedStream(byteArrayOf(), true))) {
            rejects { WalletKeyMaterial.readCertificate(stream) }; check(stream.closed)
        }
        val stream = ObservedStream(ByteArray(WalletKeyMaterial.MAX_CERTIFICATE_BYTES * 2))
        rejects { WalletKeyMaterial.readCertificate(stream) }
        check(stream.closed && stream.consumed == WalletKeyMaterial.MAX_CERTIFICATE_BYTES + 1)
        val failedPrivate = ObservedStream(byteArrayOf(), true)
        rejects { WalletKeyMaterial.readPrivateKey(failedPrivate) }; check(failedPrivate.closed)
    }
    checkCase("deterministic malformed DER corpus: 1000 inputs") {
        val random = Random(702_411)
        repeat(1000) {
            val malformed = ByteArray(random.nextInt(512) + 1).also(random::nextBytes)
            malformed[0] = 0 // never a DER SubjectPublicKeyInfo SEQUENCE
            rejects { WalletKeyMaterial.decodePublicKey(malformed) }
        }
    }
    checkCase("64 independently generated valid key and signature roundtrips") {
        repeat(64) {
            val next = generator.generateKeyPair()
            val decoded = WalletKeyMaterial.decodePublicKey(next.public.encoded)
            check(decoded.w == (next.public as ECPublicKey).w)
            val signature = Signature.getInstance("SHA256withECDSA").run { initSign(next.private); update(message); sign() }
            check(Signature.getInstance("SHA256withECDSA").run { initVerify(decoded); update(message); verify(signature) })
        }
    }
    checkCase("parallel parser and canonicalization isolation: 256 operations") {
        val pool = Executors.newFixedThreadPool(4)
        try {
            val jobs = List(256) { Callable {
                val decoded = WalletKeyMaterial.decodePublicKey(publicKey.encoded)
                check(decoded.w == publicKey.w)
                val stream = ObservedStream(certificate.encoded)
                WalletKeyMaterial.readCertificate(stream)
                check(stream.closed)
            } }
            pool.invokeAll(jobs).forEach { it.get() }
        } finally { pool.shutdownNow() }
    }
    checkCase("no global provider mutation") { check(Security.getProviders().toList() == providersBefore) }
    println("WALLET_KEY_MATERIAL_REGRESSION_PASS groups=$checks random_key_roundtrips=64 malformed_der=1000 concurrent_operations=256 provider=${BOUNCY_CASTLE_PROVIDER.name}/${BOUNCY_CASTLE_PROVIDER.versionStr} java=${System.getProperty("java.version")}")
}
