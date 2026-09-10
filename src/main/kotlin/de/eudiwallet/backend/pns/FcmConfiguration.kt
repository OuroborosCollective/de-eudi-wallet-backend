package de.eudiwallet.backend.pns

import com.google.auth.oauth2.GoogleCredentials
import kotlinx.serialization.json.Json
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.reactive.function.client.WebClient
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path

private const val FCM_HOST = "fcm.googleapis.com"
private const val FCM_BASE_URL = "https://$FCM_HOST"
private val GOOGLE_PROJECT_ID = Regex("[a-z][a-z0-9-]{4,28}[a-z0-9]")

@ConfigurationProperties(prefix = "pns.fcm")
class FcmConfiguration(
    val projectId: String = "",
    val serviceAccountKeyPath: String = "",
    val baseUrl: String = FCM_BASE_URL,
)

@Configuration
@ConditionalOnProperty(prefix = "pns.fcm", name = ["enabled"], havingValue = "true")
class FcmClientConfiguration {
    @Bean
    fun fcmCredentials(config: FcmConfiguration): GoogleCredentials {
        require(config.serviceAccountKeyPath.isNotBlank()) {
            "pns.fcm.service-account-key-path must be set when pns.fcm.enabled=true"
        }
        return Files.newInputStream(Path.of(config.serviceAccountKeyPath)).use { GoogleCredentials.fromStream(it) }
    }

    @Bean
    fun mppPushClient(
        config: FcmConfiguration,
        credentials: GoogleCredentials,
        json: Json,
        webClientBuilder: WebClient.Builder,
    ): MppPushClient {
        require(GOOGLE_PROJECT_ID.matches(config.projectId)) {
            "pns.fcm.project-id must be a canonical Google Cloud project ID"
        }
        val baseUri = requireCanonicalFcmOrigin(config.baseUrl)
        return FcmPushClient(credentials, config.projectId, baseUri.toASCIIString(), json, webClientBuilder)
    }

    private fun requireCanonicalFcmOrigin(rawBaseUrl: String): URI {
        val uri =
            runCatching { URI(rawBaseUrl) }
                .getOrElse { throw IllegalArgumentException("pns.fcm.base-url must be a valid URI", it) }

        require(uri.scheme.equals("https", ignoreCase = true)) {
            "pns.fcm.base-url must use HTTPS"
        }
        require(uri.host.equals(FCM_HOST, ignoreCase = true)) {
            "pns.fcm.base-url must point at the canonical FCM host"
        }
        require(uri.rawUserInfo == null) {
            "pns.fcm.base-url must not contain user-info"
        }
        require(uri.port == -1 || uri.port == 443) {
            "pns.fcm.base-url must use the default HTTPS port"
        }
        require(uri.rawQuery == null && uri.rawFragment == null) {
            "pns.fcm.base-url must not contain query or fragment components"
        }
        require(uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") {
            "pns.fcm.base-url must not contain a path prefix"
        }

        return URI("https", null, FCM_HOST, -1, null, null, null)
    }
}
