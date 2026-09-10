package de.eudiwallet.backend.shared.hsm

@Suppress("MagicNumber")
data class SlotConfig(
    val label: String,
    val pin: String,
    val poolSize: Int = 10,
    val threadCount: Int? = null,
) {
    val workerCount: Int get() = threadCount ?: poolSize

    // Configuration values are not safe diagnostics. Keep PIN and label out of
    // implicit logging; copy/component APIs remain compatible with the binder.
    override fun toString(): String =
        "SlotConfig(label=[REDACTED], pin=[REDACTED], poolSize=$poolSize, threadCount=$threadCount)"

    init {
        require(poolSize >= 1) { "poolSize must be at least 1" }
        require(workerCount >= 1) { "threadCount must be at least 1" }
    }
}
