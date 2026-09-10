package de.eudiwallet.backend.shared.hsm.pkcs11

import de.eudiwallet.backend.shared.hsm.HsmOperationChecks
import java.security.AlgorithmParameters
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec

/** Runs only against the disposable SoftHSM token created by this CI job. */
fun main(args: Array<String>) {
    require(args.size == 1 && args[0].contains("softhsm")) { "Expected the disposable SoftHSM library" }
    val pkcs11 = Pkcs11Ffm.load(args[0])
    val matches = pkcs11.slotList().filter { pkcs11.tokenLabel(it) == "hsm-boundary-regression" }
    check(matches.size == 1) { "Expected exactly one disposable test token" }
    val session = pkcs11.openSession(matches.single())
    try {
        val incorrect = "invalid-test-pin".toCharArray()
        try {
            try {
                pkcs11.login(session, incorrect)
                error("Incorrect PIN was accepted")
            } catch (failure: Pkcs11Exception) {
                check(failure.rv == 0xa0L) { "Expected CKR_PIN_INCORRECT" }
            }
        } finally { incorrect.fill('\u0000') }
        // Test-only credential, never a PIN from any deployment.
        val pin = "12345678".toCharArray()
        try {
            pkcs11.login(session, pin)
            pkcs11.login(session, pin)
        } finally { pin.fill('\u0000') }
        val params = AlgorithmParameters.getInstance("EC")
        params.init(ECGenParameterSpec("secp256r1"))
        val publicTemplate = listOf(
            Attr(Ck.CKA_CLASS, Ck.CKO_PUBLIC_KEY), Attr(Ck.CKA_KEY_TYPE, Ck.CKK_EC),
            Attr(Ck.CKA_TOKEN, false), Attr(Ck.CKA_VERIFY, true), Attr(Ck.CKA_EC_PARAMS, params.encoded),
        )
        val privateTemplate = listOf(
            Attr(Ck.CKA_CLASS, Ck.CKO_PRIVATE_KEY), Attr(Ck.CKA_KEY_TYPE, Ck.CKK_EC),
            Attr(Ck.CKA_TOKEN, false), Attr(Ck.CKA_SIGN, true),
            Attr(Ck.CKA_SENSITIVE, true), Attr(Ck.CKA_EXTRACTABLE, false),
        )
        val (publicKey, privateKey) = pkcs11.generateKeyPair(session, Mechanism.EcKeyPairGen, publicTemplate, privateTemplate)
        try {
            val digest = MessageDigest.getInstance("SHA-256").digest("native-wallet-test".toByteArray())
            HsmOperationChecks.requireSha256Digest(digest)
            val signature = pkcs11.sign(session, Mechanism.Ecdsa, privateKey, digest)
            HsmOperationChecks.requireP256Signature(signature)
            pkcs11.verify(session, Mechanism.Ecdsa, publicKey, digest, signature)
            digest[0] = (digest[0].toInt() xor 1).toByte()
            try {
                pkcs11.verify(session, Mechanism.Ecdsa, publicKey, digest, signature)
                error("Modified digest was accepted")
            } catch (failure: Pkcs11Exception) {
                check(failure.rv == Ck.CKR_SIGNATURE_INVALID) { "Expected signature rejection" }
            }
        } finally {
            try { pkcs11.destroyObject(session, privateKey) }
            finally { pkcs11.destroyObject(session, publicKey) }
        }
        pkcs11.logout(session)
        println("PKCS11_SOFTHSM_PASS incorrectPinRejected=true login=true repeatLogin=true nativeEcdsa=true tamperRejected=true")
    } finally { pkcs11.closeSession(session) }
}
