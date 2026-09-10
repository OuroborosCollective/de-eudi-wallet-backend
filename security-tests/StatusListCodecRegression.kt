package securitytests

import de.eudiwallet.backend.statuslist.StatusListCodec as Codec
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.Random
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.zip.Deflater

/** Runs the real production Kotlin codec. No Spring stubs, copied implementation or mock codec. */
object StatusListCodecRegression {
    private var passed = 0

    @JvmStatic
    fun main(args: Array<String>) {
        val raw = ByteArray(128) { (it % 7).toByte() }
        val compressed = Codec.deflate(raw)
        test("truncated_stream_rejected_at_every_prefix") {
            for (length in 0 until compressed.size) {
                rejected { Codec.inflate(compressed.copyOf(length)) }
            }
        }
        test("trailing_bytes_rejected") { rejected { Codec.inflate(compressed + byteArrayOf(0)) } }
        test("concatenated_streams_rejected") { rejected { Codec.inflate(compressed + compressed) } }
        test("missing_input_rejected") { rejected { Codec.inflate(byteArrayOf()) } }
        test("dictionary_requirement_rejected") { rejected { Codec.inflate(withDictionary(raw)) } }
        test("checksum_failure_rejected") {
            val bad = compressed.copyOf()
            bad[bad.lastIndex] = (bad.last().toInt() xor 1).toByte()
            rejected { Codec.inflate(bad) }
        }
        test("output_budget_exact_boundary") { check(Codec.inflate(compressed, raw.size).contentEquals(raw)) }
        test("output_budget_overrun_rejected") { rejected { Codec.inflate(compressed, raw.size - 1) } }
        test("input_budget_exact_boundary") {
            check(Codec.inflate(compressed, raw.size, compressed.size).contentEquals(raw))
        }
        test("input_budget_overrun_rejected") {
            rejected { Codec.inflate(compressed, raw.size, compressed.size - 1) }
        }
        test("empty_payload_valid_zlib") {
            check(Codec.inflate(Codec.deflate(byteArrayOf()), 0).isEmpty())
        }
        test("invalid_budgets_rejected") {
            rejected { Codec.inflate(compressed, -1) }
            rejected { Codec.inflate(compressed, 128, 0) }
            rejected { Codec.decodeLst("", -1) }
            rejected { Codec.decodeLst("", 0, -1) }
        }
        test("base64_budget_before_decode") {
            rejected { Codec.decodeLst("A".repeat(128), 128, 1) }
        }
        test("base64_decoded_budget_rechecked") {
            // One byte budget permits four Base64 characters, but these decode to three bytes.
            rejected { Codec.decodeLst("AAAA", 128, 1) }
        }
        test("invalid_base64_rejected") { rejected { Codec.decodeLst("**not_base64**") } }
        test("base64_padded_compatibility") {
            val padded = Base64.getUrlEncoder().encodeToString(compressed)
            check(Codec.decodeLst(padded).contentEquals(raw))
        }
        test("default_expansion_budget_enforced") {
            val large = Codec.deflate(ByteArray(Codec.DEFAULT_MAX_INFLATED_BYTES + 1))
            rejected { Codec.inflate(large) }
        }
        test("invalid_widths_rejected_on_public_surfaces") {
            for (bits in listOf(Int.MIN_VALUE, -1, 0, 3, 5, 7, 9, 31, 32, Int.MAX_VALUE)) {
                rejected { Codec.byteSize(8, bits) }
                rejected { Codec.position(0, bits) }
                rejected { Codec.clearMask(0, bits) }
                rejected { Codec.setBits(0, bits, 0) }
                rejected { Codec.getStatus(byteArrayOf(0), bits, 0) }
                rejected { Codec.setStatus(byteArrayOf(0), bits, 0, 0) }
            }
        }
        test("negative_and_out_of_bounds_indices_rejected") {
            for (bits in Codec.ALLOWED_BITS) {
                rejected { Codec.position(-1, bits) }
                rejected { Codec.getStatus(byteArrayOf(0), bits, -1) }
                rejected { Codec.getStatus(byteArrayOf(0), bits, 8 / bits) }
                rejected { Codec.setStatus(byteArrayOf(0), bits, Int.MAX_VALUE, 0) }
                rejected { Codec.getStatus(byteArrayOf(), bits, 0) }
            }
        }
        test("invalid_values_never_truncated_or_mutated") {
            for (bits in Codec.ALLOWED_BITS) {
                for (value in listOf(Int.MIN_VALUE, -1, 1 shl bits, Int.MAX_VALUE)) {
                    val data = byteArrayOf(0x5a)
                    rejected { Codec.setStatus(data, bits, 0, value) }
                    check(data.contentEquals(byteArrayOf(0x5a)))
                    rejected { Codec.setBits(0, bits, value) }
                    rejected { Codec.pack(bits, IntArray(8 / bits) { value }) }
                }
            }
        }
        test("byte_size_bounds_without_allocation") {
            rejected { Codec.byteSize(0, 1) }
            rejected { Codec.byteSize(-1, 8) }
            rejected { Codec.byteSize(1, 1) }
            check(Codec.byteSize(Int.MAX_VALUE, 8) == Int.MAX_VALUE)
            check(Codec.position(Int.MAX_VALUE, 8).byteIndex == Int.MAX_VALUE)
        }
        test("immutable_width_allowlist") {
            try {
                (Codec.ALLOWED_BITS as MutableSet<Int>).add(3)
                error("Mutable security allowlist")
            } catch (_: UnsupportedOperationException) {
                check(Codec.ALLOWED_BITS == setOf(1, 2, 4, 8))
            }
        }
        test("all_81920_single_byte_update_vectors") {
            var vectors = 0
            for (bits in listOf(1, 2, 4, 8)) {
                val mask = (1 shl bits) - 1
                for (old in 0..255) for (slot in 0 until 8 / bits) for (value in 0..mask) {
                    val data = byteArrayOf(old.toByte())
                    Codec.setStatus(data, bits, slot, value)
                    check(Codec.getStatus(data, bits, slot) == value)
                    val fieldMask = mask shl (slot * bits)
                    check((data[0].toInt() and fieldMask.inv() and 255) == (old and fieldMask.inv() and 255))
                    check(Codec.clearMask(slot, bits) == (fieldMask.inv() and 255))
                    check(Codec.setBits(slot, bits, value) == value shl (slot * bits))
                    vectors++
                }
            }
            check(vectors == 81920)
        }
        test("pack_roundtrip_all_widths") {
            for (bits in Codec.ALLOWED_BITS) {
                val values = IntArray(1024) { it % (1 shl bits) }
                val packed = Codec.pack(bits, values)
                values.forEachIndexed { idx, value -> check(Codec.getStatus(packed, bits, idx) == value) }
            }
        }
        test("1000_seeded_valid_compression_roundtrips") { roundTrips(721395L, 1000) }
        test("1000_seeded_malformed_input_probes") {
            val random = Random(983241L)
            repeat(1000) {
                val data = ByteArray(random.nextInt(128))
                random.nextBytes(data)
                try {
                    check(Codec.inflate(data, 4096, 128).size <= 4096)
                } catch (_: IllegalArgumentException) {
                    // The only expected rejection category. Other failures fail the test.
                }
            }
        }
        test("4000_parallel_roundtrips_eight_workers") {
            val executor = Executors.newFixedThreadPool(8)
            try {
                val tasks = (0..7).map { worker -> Callable { roundTrips(555000L + worker, 500) } }
                executor.invokeAll(tasks, 60, TimeUnit.SECONDS).forEach { it.get() }
            } finally {
                executor.shutdownNow()
                check(executor.awaitTermination(5, TimeUnit.SECONDS))
            }
        }
        println("CODEC_REGRESSION_RESULT=PASS groups=$passed bit_vectors=81920 roundtrips=5000 malformed_probes=1000")
        println("SCOPE=production_codec_only; NOT_full_backend; NOT_timing_attack_proof; NOT_zero_vulnerabilities")
    }

    private fun roundTrips(seed: Long, count: Int) {
        val random = Random(seed)
        repeat(count) {
            val data = ByteArray(random.nextInt(2049))
            random.nextBytes(data)
            check(Codec.decodeLst(Codec.encodeLst(data), data.size).contentEquals(data))
        }
    }

    private fun withDictionary(raw: ByteArray): ByteArray {
        val deflater = Deflater()
        try {
            deflater.setDictionary("dictionary".toByteArray())
            deflater.setInput(raw)
            deflater.finish()
            val out = ByteArrayOutputStream()
            val buffer = ByteArray(1024)
            while (!deflater.finished()) {
                val count = deflater.deflate(buffer)
                check(count > 0 || deflater.finished())
                out.write(buffer, 0, count)
            }
            return out.toByteArray()
        } finally {
            deflater.end()
        }
    }

    private fun rejected(action: () -> Unit) {
        try {
            action()
        } catch (_: IllegalArgumentException) {
            return
        }
        error("Expected fail-closed rejection")
    }

    private fun test(name: String, action: () -> Unit) {
        action()
        passed++
        println("PASS $name")
    }
}
