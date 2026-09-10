package de.eudiwallet.backend.shared.crypto

import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * Bundled provider instance used explicitly by wallet cryptographic operations.
 *
 * Global provider registration and ordering are deliberately owned by
 * ServiceBootstrap. Loading this file must never mutate process-wide JCA state.
 */
val BOUNCY_CASTLE_PROVIDER = BouncyCastleProvider()
