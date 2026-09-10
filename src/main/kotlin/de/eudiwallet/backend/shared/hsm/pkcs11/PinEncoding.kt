package de.eudiwallet.backend.shared.hsm.pkcs11

import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

/**
 * Encodes a borrowed PIN without creating an immutable String or a spread-copy.
 * The callback must consume the bytes synchronously and must not retain them.
 * Temporary byte arrays are cleared on success and failure. The caller owns and
 * clears the input CharArray; an upstream configuration String cannot be erased.
 * This reduces copies, not a claim of JVM-wide or physical-memory zeroisation.
 */
internal fun <T> withUtf8Pin(pin: CharArray, block: (ByteArray) -> T): T {
    // At most three UTF-8 bytes per UTF-16 code unit, including surrogate pairs.
    val capacity = Math.multiplyExact(pin.size, 3)
    val scratch = ByteArray(capacity)
    try {
        val output = ByteBuffer.wrap(scratch)
        val encoder = StandardCharsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
        val encoded = encoder.encode(CharBuffer.wrap(pin), output, true)
        if (encoded.isError) encoded.throwException()
        check(encoded.isUnderflow) { "PIN encoding exceeded its buffer" }
        val flushed = encoder.flush(output)
        if (flushed.isError) flushed.throwException()
        check(flushed.isUnderflow) { "PIN encoding exceeded its buffer" }
        val bytes = scratch.copyOf(output.position())
        try {
            return block(bytes)
        } finally {
            bytes.fill(0)
        }
    } finally {
        scratch.fill(0)
    }
}
