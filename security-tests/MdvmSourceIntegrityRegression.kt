package securitytests

import com.intellij.openapi.util.Disposer
import com.intellij.psi.PsiErrorElement
import com.intellij.psi.util.PsiTreeUtil
import org.jetbrains.kotlin.cli.jvm.compiler.EnvironmentConfigFiles
import org.jetbrains.kotlin.cli.jvm.compiler.KotlinCoreEnvironment
import org.jetbrains.kotlin.config.CompilerConfiguration
import org.jetbrains.kotlin.psi.KtClass
import org.jetbrains.kotlin.psi.KtNamedFunction
import org.jetbrains.kotlin.psi.KtProperty
import org.jetbrains.kotlin.psi.KtPsiFactory
import java.io.File

/** Uses the real Kotlin parser; syntax and declarations only, not type resolution or MDVM runtime. */
object MdvmSourceIntegrityRegression {
    @JvmStatic
    fun main(args: Array<String>) {
        require(args.size == 1) { "Expected path to MdvmAccount.kt" }
        val disposable = Disposer.newDisposable()
        try {
            val environment = KotlinCoreEnvironment.createForProduction(
                disposable, CompilerConfiguration(), EnvironmentConfigFiles.JVM_CONFIG_FILES,
            )
            val factory = KtPsiFactory(environment.project, false)
            val source = File(args.single()).readText(Charsets.UTF_8)
            verify(factory, source)
            // Missing types cannot be supplied by a placeholder comment.
            rejects { verify(factory, "package de.eudiwallet.backend.mdvm\n// data class MdvmAccount\n") }
            rejects { verify(factory, source.replace("data class MdvmAccount(", "data class RemovedAccount(")) }
            rejects { verify(factory, source.replace("listOf(\"secp256r1\")", "listOf(\"secp256r1\", \"secp384r1\")")) }
            rejects { verify(factory, source + "\nclass Broken(\n") }
            println("MDVM_SOURCE_PARSE_RESULT=PASS positive=1 negative=4")
            println("SCOPE=Kotlin_syntax_and_declaration_integrity_only; NOT_typecheck; NOT_MDVM_runtime; NOT_crypto_proof")
        } finally {
            Disposer.dispose(disposable)
        }
    }

    private fun verify(factory: KtPsiFactory, source: String) {
        val file = factory.createFile("MdvmAccount.kt", source)
        check(PsiTreeUtil.collectElementsOfType(file, PsiErrorElement::class.java).isEmpty()) { "MDVM syntax error" }
        check(file.packageFqName.asString() == "de.eudiwallet.backend.mdvm") { "MDVM package changed" }
        val classes = file.declarations.filterIsInstance<KtClass>().associateBy { it.name }
        val required = setOf("MdvmAccount", "DeviceInfo", "AndroidPackageInfo", "AndroidAttestationDetails",
            "AndroidDeviceAttestationData", "IosDeviceAttestationData", "IosDeviceAssertionData")
        check(classes.keys.containsAll(required)) { "MDVM domain declarations missing" }
        val accountMethods = classes.getValue("MdvmAccount").declarations.filterIsInstance<KtNamedFunction>().map { it.name }.toSet()
        check(accountMethods.containsAll(setOf("requireNotRevoked", "verifyDeviceType", "toEntity", "requireValidNextIosAssertionCounter"))) {
            "MDVM domain methods missing"
        }
        check(file.declarations.filterIsInstance<KtNamedFunction>().any { it.name == "toDomain" }) { "MDVM entity mapper missing" }
        val policy = file.declarations.filterIsInstance<KtProperty>().single { it.name == "ALLOWED_EC_CURVES" }
        check(policy.initializer?.text == "listOf(\"secp256r1\")") { "MDVM curve policy must be P-256-only" }
    }

    private fun rejects(action: () -> Unit) {
        try { action() } catch (_: IllegalStateException) { return }
        error("Expected source-integrity rejection")
    }
}
