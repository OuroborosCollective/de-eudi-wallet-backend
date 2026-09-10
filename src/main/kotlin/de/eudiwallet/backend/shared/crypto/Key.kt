package de.eudiwallet.backend.shared.crypto

import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import org.springframework.core.io.Resource
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyGenerator

val RECOMMENDED_EC_CURVE: Curve = Curve.P_256
const val ALGORITHM_EC = "EC"
const val ALGORITHM_HMAC_SHA256 = "HmacSHA256"
const val ALGORITHM_AES = "AES"
private const val RECOMMENDED_HMAC_SHA256_KEYSIZE = 256
private const val RECOMMENDED_AES_KEYSIZE = 256
private const val CERTIFICATE_FACTORY_X509 = "X.509"
private const val PEM_CHUNK_SIZE = 64

fun ByteArray.ecPublicKeyFromX509(): ECPublicKey = WalletKeyMaterial.decodePublicKey(this)

fun ByteArray.ecPrivateKeyFromPkcs8(): ECPrivateKey = WalletKeyMaterial.decodePrivateKey(this)

fun ECPublicKey.toECJWK(): ECKey = ECKey.Builder(RECOMMENDED_EC_CURVE, toCanonicalP256()).build()

fun ECPublicKey.toCanonicalP256(): ECPublicKey = WalletKeyMaterial.canonicalP256(this)

fun ECPublicKey.jwkThumbprint(): Base64URL = toECJWK().computeThumbprint()

data class ECKeyPair(
    val private: ECPrivateKey,
    val public: ECPublicKey,
)

fun KeyPair.toECKeyPair() = ECKeyPair(private as ECPrivateKey, public as ECPublicKey)

val x509CertificateFactory: CertificateFactory =
    CertificateFactory.getInstance(
        CERTIFICATE_FACTORY_X509,
        BOUNCY_CASTLE_PROVIDER,
    )

val softwareEcdsaKeyGenerator: KeyPairGenerator =
    KeyPairGenerator.getInstance(ALGORITHM_EC, BOUNCY_CASTLE_PROVIDER).apply {
        initialize(ECGenParameterSpec(RECOMMENDED_EC_CURVE.name))
    }

val softwareHmacKeyGenerator: KeyGenerator =
    KeyGenerator.getInstance(ALGORITHM_HMAC_SHA256, BOUNCY_CASTLE_PROVIDER).apply {
        init(RECOMMENDED_HMAC_SHA256_KEYSIZE)
    }

val softwareAesKeyGenerator: KeyGenerator =
    KeyGenerator.getInstance(ALGORITHM_AES, BOUNCY_CASTLE_PROVIDER).apply {
        init(RECOMMENDED_AES_KEYSIZE)
    }

fun readPKCS8ECPrivateKey(pemPath: Resource): ECPrivateKey = WalletKeyMaterial.readPrivateKey(pemPath.inputStream)

fun readX509Cert(certificateResource: Resource): X509Certificate =
    WalletKeyMaterial.readCertificate(certificateResource.inputStream)

fun List<String>.toPemChain(): String =
    joinToString(separator = "\n") { base64Der ->
        val lines = base64Der.chunked(PEM_CHUNK_SIZE).joinToString("\n")
        "-----BEGIN CERTIFICATE-----\n$lines\n-----END CERTIFICATE-----"
    }
