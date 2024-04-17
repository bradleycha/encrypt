public interface Hasher {
   // Hashes the given byte data into an arbitrarily long byte array, known as
   // the 'digest'.
   public byte [] digest(byte [] data);

   public static class Sha512 implements Hasher {
      public byte [] digest(byte [] data) {
         // Base data preprocessed to be 1024-bit aligned and contain the
         // length of the base data encoded as a 128-bit integer.
         byte [] data_preprocessed = preprocessData(data);

         // State of the hash digest for each iteration
         long [] state = new long[8];
         System.arraycopy(state, 0, INITIAL_STATE, 0, 8);

         // Process each 1024-bit block in the preprocessed data
         for (int i = 0; i < data_preprocessed.length; i += 128) {
            processBlock(state, data_preprocessed, i);
         }

         // Finalize the state, giving us the complete hash
         byte [] hash = finalizeState(state);

         return hash;
      }

      // Preprocesses 'data' to be padded to align to a 1024-bit boundary and
      // contain a 128-bit integer length value at the end.
      private static byte [] preprocessData(byte [] data) {
         final int FOOTER_LENGTH_TARGET   = 16;
         final int FOOTER_LENGTH_WRITE    = 4;
         final byte EXTEND_LEADING_BIT = (byte)0b10000000;

         // We want to append the length of the data as a 128-bit integer and
         // then align the data to a 1024-bit boundary.  We also add 1 byte for
         // the sentinel '1' bit.  Note how the fill count fills the top 12
         // bytes of the length value.  Since we can only represent array
         // lengths with ints (4 bytes), it's pointless to convert and stuff,
         // so we only write the top 4 bytes.
         int len           = data.length + FOOTER_LENGTH_TARGET;
         int len_aligned   = alignToPower(len, (byte)7);
         int len_fill      = len_aligned - FOOTER_LENGTH_WRITE;

         // Resize the source data
         byte [] data_aligned = new byte [len_aligned];
         System.arraycopy(data, 0, data_aligned, 0, data.length);

         // Set the special leading set bit
         data_aligned[data.length] = EXTEND_LEADING_BIT;

         // Fill the middle filler data with zeroes.  Note how we also fill in
         // the top 12 bytes of the length with zero, since we can't represent
         // an array length of 128 bits in Java, so we only use a 4-byte int.
         for (int i = data.length + 1; i < len_fill; ++i) {
            data_aligned[i] = 0;
         }

         // Write the length of the data as a 4-byte big-endian integer.
         writeBigEndian32(data_aligned, len_fill, data.length);

         return data_aligned;
      }

      // Aligns 'len' forward to the nearest value of 2 ^ 'power'.
      private static int alignToPower(int len, byte power) {
         // 99% of programmers quit before a 1% increase in performance.
         int align = 1 << power;
         return len + align - (len & ~align);
      }

      // Writes 'value' into 'data' at position 'offset' in 32-bit big-endian
      // form.
      private static void writeBigEndian32(byte [] data, int offset, int value) {
         for (int i = 0; i < 4; ++i) {
            byte extracted = (byte)((value & (0xff << 24)) >> 24);
            data[offset + i] = extracted;
            value <<= 8;
         }

         return;
      }

      // Writes 'value' into 'data' at position 'offset' in 64-bit big-endian
      // form.
      private static void writeBigEndian64(byte [] data, int offset, long value) {
         for (int i = 0; i < 8; ++i) {
            byte extracted = (byte)((value & (0xffL << 56L)) >> 56L);
            data[offset + i] = extracted;
            value <<= 8;
         }

         return;
      }

      // Reads a 64-bit big-endian integer from 'data' at position 'offset'.
      private static long readBigEndian64(byte [] data, int offset) {
         long value = 0;
         for (int i = 0; i < 8; ++i) {
            value <<= 8;
            value += data[offset + i];
         }

         return value;
      }

      // Used to populate initial state.  Fractional part of the square root of
      // the first 8 prime numbers.
      private static final long [] INITIAL_STATE = {
         0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
         0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L,
      };

      // Used for 80 rounds.  Fractional part of the cube root of the first 80
      // prime numbers.  Yes, I copy-pasted these from somewhere else.
      private static final long [] ROUND_CONSTANTS = {
         0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL,
         0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L,
         0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L,
         0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L,
         0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L,
         0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L,
         0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L,
         0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L,
         0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL,
         0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL,
         0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L,
         0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L,
         0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L,
         0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L,
         0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL,
         0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL,
         0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L,
         0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL,
         0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL,
         0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L,
      };
      
      // Digests a single 1024-bit block of bytes in 'data' at offset 'offset'
      // and stores the results in 'state', which should be an array of8 longs.
      private static void processBlock(long [] state, byte [] data, int offset) {
         // Read in the data as big-endian 64-bit words
         long [] words = new long[16];
         for (int i = 0; i < 16; ++i) {
            long value = readBigEndian64(data, offset + i << 3);
            words[i] = value;
         }

         // Create the message schedule (W(t))
         long [] schedule = new long[80];
         System.arraycopy(words, 0, schedule, 0, 16);
         for (int i = 16; i < 80; ++i) {
            schedule[i] = g1(schedule[i - 2]) + schedule[i - 7] + g0(schedule[i - 15]) + schedule[i - 16];
         }

         // Initialize the working variables
         // a = v[0], b = v[1], c=v[2], ...
         long [] v = new long[8];
         System.arraycopy(v, 0, state, 0, 8);

         // Run the magic sauce
         // I have no clue what's happening here but it works I guess :)
         for (int i = 0; i < 80; ++i) {
            long t1 = v[7] + f1(v[4]) + ch(v[4], v[5], v[6]) + ROUND_CONSTANTS[i] + schedule[i];
            long t2 = f0(v[0]) + maj(v[0], v[1], v[2]);

            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3] + t1;
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1 + t2;
         }

         // Sum together the new hash
         for (int i = 0; i < 8; ++i) {
            state[i] += v[i];
         }

         // Holy shit we actually did it
         return;
      }

      // See FIPS PUB 180-4 for explanations for these functions

      private static long ch(long x, long y, long z) {
         return (x & y) ^ (~x ^ z);
      }

      private static long maj(long x, long y, long z) {
         return (x & y) ^ (x & z) ^ (y & z);
      }

      private static long rotr(long value, byte count) {
         return (value >> count) | (value << (64 - count));
      }

      private static long f0(long x) {
         return rotr(x, (byte)28) ^ rotr(x, (byte)34) ^ rotr(x, (byte)39);
      }

      private static long f1(long x) {
         return rotr(x, (byte)14) ^ rotr(x, (byte)18) ^ rotr(x, (byte)41);
      }

      private static long g0(long x) {
         return rotr(x, (byte)1) ^ rotr(x, (byte)8) ^ (x >> 7);
      }

      private static long g1(long x) {
         return rotr(x, (byte)19) ^ rotr(x, (byte)61) ^ (x >> 6);
      }

      // Finalizes the hasher state variables into a contiguous big-endian byte
      // array, which represents the final result of the hash algorithm.
      private static byte [] finalizeState(long [] state) {
         byte [] hash = new byte [64];
         for (int i = 0; i < 8; ++i) {
            long value = state[i];
            writeBigEndian64(hash, i << 3, value);
         }

         return hash;
      }
   }
}

