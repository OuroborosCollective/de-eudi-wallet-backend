package de.eudiwallet.backend.statuslist

import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.Collections
import java.util.zip.DataFormatException
import java.util.zip.Deflater
import java.util.zip.Inflater

@Suppress("TooManyFunctions")
object StatusListCodec {
    private const val BYTE_MASK = 0xFF
    private const val CHUNK = 8192

    /** Output-byte budget, not a bound on total JVM heap usage. */
    const val DEFAULT_MAX_INFLATED_BYTES = 16 * 1024 * 1024
    const val DEFAULT_MAX_COMPRESSED_BYTES = 32 * 1024 * 1024

    private val base64Url = Base64.getUrlEncoder().withoutPadding()
    private val base64UrlDecoder = Base64.getUrlDecoder()

    @Suppress("MagicNumber")
    val ALLOWED_BITS: Set<Int> = Collections.unmodifiableSet(setOf(1, 2, 4, 8))

    fun byteSize(
        size: Int,
        bitsPerEntry: Int,
    ): Int {
        require(size > 0) { "size must be positive" }
        valueMask(bitsPerEntry)
        val bitCount = size.toLong() * bitsPerEntry
        require(bitCount % Byte.SIZE_BITS == 0L) {
            "size*bitsPerEntry must be a whole number of bytes"
        }
        return (bitCount / Byte.SIZE_BITS).toInt()
    }

    fun pack(
        bitsPerEntry: Int,
        values: IntArray,
    ): ByteArray {
        val data = ByteArray(byteSize(values.size, bitsPerEntry))
        values.forEachIndexed { idx, value -> setStatus(data, bitsPerEntry, idx, value) }
        return data
    }

    fun position(
        idx: Int,
        bitsPerEntry: Int,
    ): BitPosition {
        require(idx >= 0) { "status index must not be negative" }
        valueMask(bitsPerEntry)
        val bitOffset = idx.toLong() * bitsPerEntry
        return BitPosition((bitOffset / Byte.SIZE_BITS).toInt(), (bitOffset % Byte.SIZE_BITS).toInt())
    }

    fun clearMask(
        idx: Int,
        bitsPerEntry: Int,
    ): Int = (valueMask(bitsPerEntry) shl position(idx, bitsPerEntry).shift).inv() and BYTE_MASK

    fun setBits(
        idx: Int,
        bitsPerEntry: Int,
        value: Int,
    ): Int {
        requireValue(value, valueMask(bitsPerEntry))
        return value shl position(idx, bitsPerEntry).shift
    }

    fun setStatus(
        data: ByteArray,
        bitsPerEntry: Int,
        idx: Int,
        value: Int,
    ) {
        val mask = valueMask(bitsPerEntry)
        requireValue(value, mask)
        val pos = checkedPosition(data, idx, bitsPerEntry)
        // Validate everything before mutating. Never truncate an invalid status to zero.
        val cleared = data[pos.byteIndex].toInt() and ((mask shl pos.shift).inv() and BYTE_MASK)
        data[pos.byteIndex] = (cleared or (value shl pos.shift)).toByte()
    }

    fun getStatus(
        data: ByteArray,
        bitsPerEntry: Int,
        idx: Int,
    ): Int {
        val pos = checkedPosition(data, idx, bitsPerEntry)
        return (data[pos.byteIndex].toInt() ushr pos.shift) and valueMask(bitsPerEntry)
    }

    fun encodeLst(data: ByteArray): String = base64Url.encodeToString(deflate(data))

    fun deflate(data: ByteArray): ByteArray {
        val deflater = Deflater(Deflater.BEST_COMPRESSION)
        try {
            deflater.setInput(data)
            deflater.finish()
            val chunk = ByteArray(CHUNK)
            val out = ByteArrayOutputStream()
            while (!deflater.finished()) {
                val n = deflater.deflate(chunk)
                check(n > 0 || deflater.finished()) { "Status list compression made no progress" }
                out.write(chunk, 0, n)
            }
            return out.toByteArray()
        } finally {
            deflater.end()
        }
    }

    fun decodeLst(lst: String): ByteArray =
        decodeLst(lst, DEFAULT_MAX_INFLATED_BYTES, DEFAULT_MAX_COMPRESSED_BYTES)

    /** Explicit budgets permit larger legitimate lists without an unbounded decoder. */
    fun decodeLst(
        lst: String,
        maxOutputBytes: Int,
        maxInputBytes: Int = DEFAULT_MAX_COMPRESSED_BYTES,
    ): ByteArray {
        requireBudgets(maxOutputBytes, maxInputBytes)
        // Bound allocation before Base64 decoding. Long arithmetic avoids overflow.
        val maxEncodedChars = ((maxInputBytes.toLong() + 2) / 3) * 4
        require(lst.length.toLong() <= maxEncodedChars) { "Encoded status list exceeds input budget" }
        return inflate(base64UrlDecoder.decode(lst), maxOutputBytes, maxInputBytes)
    }

    fun inflate(compressed: ByteArray): ByteArray =
        inflate(compressed, DEFAULT_MAX_INFLATED_BYTES, DEFAULT_MAX_COMPRESSED_BYTES)

    /**
     * Accept exactly one complete zlib stream. Truncation, dictionary requirements,
     * checksum errors, trailing data and expansion beyond the budget fail closed.
     * This parses data; it does not authenticate a status-list token or its issuer.
     */
    fun inflate(
        compressed: ByteArray,
        maxOutputBytes: Int,
        maxInputBytes: Int = DEFAULT_MAX_COMPRESSED_BYTES,
    ): ByteArray {
        requireBudgets(maxOutputBytes, maxInputBytes)
        require(compressed.isNotEmpty()) { "Compressed status list is empty" }
        require(compressed.size <= maxInputBytes) { "Compressed status list exceeds input budget" }
        val inflater = Inflater()
        try {
            inflater.setInput(compressed)
            val chunk = ByteArray(CHUNK)
            val out = ByteArrayOutputStream(minOf(CHUNK, maxOutputBytes))
            while (!inflater.finished()) {
                val n = inflater.inflate(chunk)
                if (n > 0) {
                    require(n <= maxOutputBytes - out.size()) { "Status list exceeds output budget" }
                    out.write(chunk, 0, n)
                } else if (!inflater.finished()) {
                    require(!inflater.needsDictionary()) { "Status list requires an unsupported dictionary" }
                    require(!inflater.needsInput()) { "Compressed status list is truncated" }
                    throw IllegalArgumentException("Status list decompression made no progress")
                }
            }
            require(inflater.remaining == 0) { "Compressed status list contains trailing data" }
            return out.toByteArray()
        } catch (ex: DataFormatException) {
            throw IllegalArgumentException("Malformed compressed status list", ex)
        } finally {
            inflater.end()
        }
    }

    private fun checkedPosition(
        data: ByteArray,
        idx: Int,
        bitsPerEntry: Int,
    ): BitPosition = position(idx, bitsPerEntry).also {
        require(it.byteIndex in data.indices) { "Status index exceeds data bounds" }
    }

    private fun valueMask(bitsPerEntry: Int): Int {
        require(bitsPerEntry in ALLOWED_BITS) { "bitsPerEntry must be one of $ALLOWED_BITS" }
        return (1 shl bitsPerEntry) - 1
    }

    private fun requireValue(value: Int, mask: Int) {
        require(value in 0..mask) { "Status value does not fit bitsPerEntry" }
    }

    private fun requireBudgets(maxOutputBytes: Int, maxInputBytes: Int) {
        require(maxOutputBytes >= 0) { "Output budget must not be negative" }
        require(maxInputBytes > 0) { "Input budget must be positive" }
    }
}

data class BitPosition(
    val byteIndex: Int,
    val shift: Int,
)
