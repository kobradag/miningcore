using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using Miningcore.Contracts;
using Miningcore.Crypto;
using Miningcore.Extensions;
using Miningcore.Stratum;
using Miningcore.Util;
using Miningcore.Crypto.Hashing.Algorithms;
using NBitcoin;
using System.Collections.Generic;
using System.Diagnostics;
using NLog;

namespace Miningcore.Blockchain.Kaspa.Custom.Kobra
{
    public static class KobraConstants
    {
        public static readonly string Diff1bHex = "00000001fffe0000000000000000000000000000000000000000000000000000";
        
        public static readonly float DefaultDifficulty = 0.5f;
        
        public static readonly bool AcceptAllShares = false;
        
        public static readonly bool EnableDetailedLogs = true;
    }

    public class KobraJob : KaspaJob
    {
        private static readonly ILogger logger = LogManager.GetCurrentClassLogger();
        
        internal static ushort[] sinusoidalValues = new ushort[256];
        
        static KobraJob()
        {
            InitializeSinusoidalValues();
        }
        
        private static void InitializeSinusoidalValues()
        {
            for (int j = 0; j < 256; j++)
            {
            double angle = (double)j; 
            sinusoidalValues[j] = (ushort)(Math.Abs(Math.Sin(angle)) * 1000.0);
            }
            
            if (KobraConstants.EnableDetailedLogs)
            {
                logger.Debug("KOBRA: Initialized sinusoidal values table");
            }
        }

        public KobraJob(IHashAlgorithm customBlockHeaderHasher, IHashAlgorithm customCoinbaseHasher, IHashAlgorithm customShareHasher)
            : base(customBlockHeaderHasher, customCoinbaseHasher, customShareHasher) 
        { 

        }

        private static BigInteger UInt256ToBigInteger(uint256 value)
        {
            var bytes = value.ToBytes(); // Convert uint256 to byte array
            return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        }

        protected override Share ProcessShareInternal(StratumConnection worker, string nonceHex)
        {
            var context = worker.ContextAs<KaspaWorkerContext>();

            // Convert nonce from hex string to ulong
            ulong nonce = Convert.ToUInt64(nonceHex, 16);
            logger.Debug($"KOBRA: ProcessShareInternal -> Nonce = {nonce:X}");

            // Prepare the State object
            var prePowHashSpan = SerializeHeader(BlockTemplate.Header, true);
            byte[] prePowHashBytes = prePowHashSpan.ToArray();
            logger.Debug($"KOBRA: ProcessShareInternal -> PrePowHash = {prePowHashBytes.ToHexString()}");

            float difficulty = context.Difficulty > 0 ? (float)context.Difficulty : KobraConstants.DefaultDifficulty;

            string shareTargetHex = CalculateShareTarget(difficulty);
            
            logger.Debug($"KOBRA: ProcessShareInternal -> Share Target Hex = 0x{shareTargetHex}");
            logger.Debug($"KOBRA: ProcessShareInternal -> Difficulty = {difficulty}");

            var state = new KobraState(prePowHashBytes, BlockTemplate.Header.Timestamp, shareTargetHex);

            // Calculate and verify PoW
            var (isValid, powHex) = state.CheckPow(nonce);
            logger.Info($"KOBRA: ProcessShareInternal -> PoW Hex = 0x{powHex}, IsValid = {isValid}");

            if (KobraConstants.AcceptAllShares)
            {
                isValid = true;
                logger.Info($"KOBRA: ProcessShareInternal -> Forcing acceptance of all shares (debug mode)");
            }

            if (!isValid)
            {
              logger.Warn($"KOBRA: Invalid share from worker {worker.ConnectionId} - Nonce: {nonce}, PoW: 0x{powHex}");

              return new Share
            {
                 BlockHeight = (long)BlockTemplate.Header.DaaScore,
                 NetworkDifficulty = Difficulty,
                 Difficulty = difficulty,
                 IsBlockCandidate = false
                 };
            }

            BigInteger pow = BigInteger.Zero;
            try
            {
                pow = HexToBigInteger(powHex);
                logger.Debug($"KOBRA: ProcessShareInternal -> PoW as BigInteger = {pow}");
            }
            catch (Exception ex)
            {
                logger.Error($"KOBRA: ProcessShareInternal -> Error converting powHex to BigInteger: {ex.Message}");
            }

            var blockTargetValue = new Target(KaspaUtils.CompactToBig(BlockTemplate.Header.Bits)).ToUInt256();
            var blockTargetBigInteger = UInt256ToBigInteger(blockTargetValue);
            var blockTargetHex = blockTargetBigInteger.ToString("X").PadLeft(64, '0');
            
            logger.Info($"KOBRA: ProcessShareInternal -> Share Target = 0x{shareTargetHex}");
            logger.Info($"KOBRA: ProcessShareInternal -> Block Target = 0x{blockTargetHex}");
            
            var isBlockCandidate = IsBlockCandidate(powHex, blockTargetHex);
            logger.Info($"KOBRA: ProcessShareInternal -> IsBlockCandidate = {isBlockCandidate}");

            var result = new Share
            {
                BlockHeight = (long)BlockTemplate.Header.DaaScore,
                NetworkDifficulty = Difficulty,
                Difficulty = difficulty,
                IsBlockCandidate = isBlockCandidate
            };

            if (isBlockCandidate)
            {
                var hashBytesSpan = SerializeHeader(BlockTemplate.Header, false);
                var hashBytes = hashBytesSpan.ToArray();
                result.BlockHash = hashBytes.ToHexString();
                logger.Debug($"KOBRA: ProcessShareInternal -> BlockHash = {result.BlockHash}");
            }

            return result;
        }
        
        private string CalculateShareTarget(float difficulty)
        {
            try
            {
                var diff1 = BigInteger.Parse("00" + KobraConstants.Diff1bHex, System.Globalization.NumberStyles.HexNumber);
                
                var multiplier = new BigInteger((float)(65536.0 * difficulty));
                if (multiplier <= 0)
                    multiplier = BigInteger.One;
                
                var shareTarget = BigInteger.Divide(diff1, multiplier);
                
                return shareTarget.ToString("X").PadLeft(64, '0');
            }
            catch (Exception ex)
            {
                logger.Error($"KOBRA: CalculateShareTarget -> Error: {ex.Message}");
                return "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
            }
        }
        
        private static bool IsBlockCandidate(string powHex, string targetHex)
        {
          try
          {
          var pow = HexToBigInteger(powHex);
          var target = HexToBigInteger(targetHex);
          return pow <= target;
        }
        catch (Exception ex)
        {
             logger.Error($"KOBRA: IsBlockCandidate -> Error: {ex.Message}");
             return false;
           }
        }

       
        
        private static BigInteger HexToBigInteger(string hex)
        {
            if (string.IsNullOrEmpty(hex)) 
                return BigInteger.Zero;
            
            hex = hex.Replace("0x", "");
            
            if ((hex.Length % 2) != 0)
                hex = "0" + hex;
                
            try
            {
                byte[] bytes = Enumerable.Range(0, hex.Length)
                    .Where(x => x % 2 == 0)
                    .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                    .Reverse()                     .ToArray();
                
                return new BigInteger(bytes.Concat(new byte[] { 0 }).ToArray()); // ???? ??? ??? ???? ?????? ??? ?????
            }
            catch (Exception ex)
            {
                logger.Error($"KOBRA: HexToBigInteger -> Error: {ex.Message}");
                return BigInteger.Zero;
            }
        }

        private class KobraState
        {
           private readonly KobraXoShiRo256PlusPlus.Matrix matrix;
           private readonly string targetHex;
           private readonly KobraXoShiRo256PlusPlus.PowHash hasher;

           public KobraState(byte[] prePowHash, long timestamp, string targetHex)
           {
              this.targetHex = targetHex;

               // Initialize the hasher with prePowHash and timestamp
               this.hasher = new KobraXoShiRo256PlusPlus.PowHash(prePowHash, timestamp);
               logger.Debug($"KOBRA: KobraState -> Hasher initialized with PrePowHash and Timestamp = {timestamp}");
 
               // Generate the matrix
               this.matrix = KobraXoShiRo256PlusPlus.Matrix.Generate(prePowHash);
               logger.Debug($"KOBRA: KobraState -> Matrix generated successfully");
          }

          public (bool, string) CheckPow(ulong nonce)
          {
              var hash = hasher.FinalizeWithNonce(nonce);
              logger.Info($"KOBRA: CheckPow -> Hash after adding nonce = {hash.ToHexString()}");

              var heavyHash = matrix.HeavyHash(hash);
              logger.Info($"KOBRA: CheckPow -> HeavyHash = {heavyHash.ToHexString()}");

              string powHex = heavyHash.ToHexString();
              logger.Info($"KOBRA: CheckPow -> PoW Hex = 0x{powHex}");
              logger.Info($"KOBRA: CheckPow -> Target Hex = 0x{targetHex}");

              bool isValid = IsBlockCandidate(powHex, targetHex);
              logger.Info($"KOBRA: CheckPow -> Is valid share: {isValid}");

              return (isValid, powHex);
          }
       }

    }
    
    public class KobraXoShiRo256PlusPlus
    {
        private ulong[] s = new ulong[4];

        public KobraXoShiRo256PlusPlus(Span<byte> prePowHash)
        {
            if (prePowHash.Length < 32)
                throw new ArgumentException("PrePowHash must be at least 32 bytes", nameof(prePowHash));

            for (int i = 0; i < 4; i++)
            {
                s[i] = BitConverter.ToUInt64(prePowHash.Slice(i * 8, 8));
            }
        }

        public ulong NextU64()
        {
            ulong result = RotateLeft64(s[0] + s[3], 23) + s[0];

            ulong t = s[1] << 17;

            s[2] ^= s[0];
            s[3] ^= s[1];
            s[1] ^= s[2];
            s[0] ^= s[3];

            s[2] ^= t;
            s[3] = RotateLeft64(s[3], 45);

            return result;
        }

        private static ulong RotateLeft64(ulong value, int shift)
        {
            return (value << shift) | (value >> (64 - shift));
        }

        public class Matrix
        {
        private readonly ushort[,] matrix;
        private static readonly ILogger logger = LogManager.GetCurrentClassLogger();

        private Matrix(ushort[,] matrix)
        {
            this.matrix = matrix;
        }

        public static Matrix Generate(byte[] hash)
        {
            var generator = new KobraXoShiRo256PlusPlus(hash);
            while (true)
            {
                var mat = RandMatrixNoRankCheck(generator);
                if (mat.ComputeRank() == 64)
                {
                    return mat;
                }
            }
        }

        private static Matrix RandMatrixNoRankCheck(KobraXoShiRo256PlusPlus generator)
        {
            ushort[,] mat = new ushort[64, 64];
            for (int i = 0; i < 64; i++)
            {
                ulong val = 0;
                for (int j = 0; j < 64; j++)
                {
                    int shift = j % 16;
                    if (shift == 0)
                    {
                        val = generator.NextU64();
                    }
                    mat[i, j] = (ushort)((val >> (4 * shift)) & 0x0F);
                }
            }
            return new Matrix(mat);
        }

        private double[,] ConvertToFloat()
        {
            var result = new double[64, 64];
            for (int i = 0; i < 64; i++)
            {
                for (int j = 0; j < 64; j++)
                {
                    result[i, j] = matrix[i, j];
                }
            }
            return result;
        }

        public int ComputeRank()
        {
            const double EPS = 1e-9;
            var matFloat = ConvertToFloat();
            bool[] rowSelected = new bool[64];
            int rank = 0;

            for (int i = 0; i < 64; i++)
            {
                int j = 0;
                while (j < 64 && (rowSelected[j] || Math.Abs(matFloat[j, i]) <= EPS))
                {
                    j++;
                }

                if (j < 64)
                {
                    rank++;
                    rowSelected[j] = true;
                    for (int p = i + 1; p < 64; p++)
                    {
                        matFloat[j, p] /= matFloat[j, i];
                    }

                    for (int k = 0; k < 64; k++)
                    {
                        if (k != j && Math.Abs(matFloat[k, i]) > EPS)
                        {
                            for (int p = i + 1; p < 64; p++)
                            {
                                matFloat[k, p] -= matFloat[j, p] * matFloat[k, i];
                            }
                        }
                    }
                }
            }

            return rank;
        }

        public byte[] HeavyHash(byte[] hash)
        {
            logger.Info($"KOBRA Matrix: Starting HeavyHash with input: {BitConverter.ToString(hash).Replace("-", "")}");

            try
            {
                byte[] blake2Hash = ComputeBlake2b(hash);
                logger.Info($"KOBRA Matrix: 1. Blake2b: {BitConverter.ToString(blake2Hash).Replace("-", "")}");

                byte[] skeinHash = ComputeSkein256(blake2Hash);
                logger.Info($"KOBRA Matrix: 2. Skein: {BitConverter.ToString(skeinHash).Replace("-", "")}");

                byte[] sha3Hash = ComputeSHA3_256(skeinHash);
                logger.Info($"KOBRA Matrix: 3. SHA3: {BitConverter.ToString(sha3Hash).Replace("-", "")}");

                byte[] result = ApplyHeavyKodaMatrix(sha3Hash);
                logger.Info($"KOBRA Matrix: 4. Final HeavyKodaHash: {BitConverter.ToString(result).Replace("-", "")}");

                return result;
            }
            catch (Exception ex)
            {
                logger.Error($"KOBRA Matrix: ERROR in HeavyHash: {ex.Message}");
                
                return FallbackHeavyHash(hash);
            }
        }

        private byte[] FallbackHeavyHash(byte[] hash)
        {
            try
            {
                // 1. SHA-256 ????? BLAKE2b
                byte[] blake2Hash;
                using (var hasher = SHA256.Create())
                {
                    blake2Hash = hasher.ComputeHash(hash);
                }
                logger.Debug($"KOBRA Matrix: 1. Fallback SHA256 instead of Blake2b: {BitConverter.ToString(blake2Hash).Replace("-", "")}");

                byte[] skeinHash;
                using (var hasher = SHA256.Create())
                {
                    skeinHash = hasher.ComputeHash(blake2Hash);
                }
                logger.Debug($"KOBRA Matrix: 2. Fallback SHA256 instead of Skein: {BitConverter.ToString(skeinHash).Replace("-", "")}");

                byte[] sha3Hash;
                using (var hasher = SHA256.Create())
                {
                    sha3Hash = hasher.ComputeHash(skeinHash);
                }
                logger.Debug($"KOBRA Matrix: 3. Fallback SHA256 instead of SHA3: {BitConverter.ToString(sha3Hash).Replace("-", "")}");

                byte[] result = ApplyHeavyKodaMatrix(sha3Hash);
                logger.Debug($"KOBRA Matrix: 4. Fallback Final HeavyKodaHash: {BitConverter.ToString(result).Replace("-", "")}");

                return result;
            }
            catch (Exception ex)
            {
                logger.Error($"KOBRA Matrix: ERROR even in FallbackHeavyHash: {ex.Message}");
                
                return hash;
            }
        }

        private byte[] ComputeBlake2b(byte[] input)
        {
            try
            {
                var hasher = new Blake2b();
                Span<byte> output = stackalloc byte[32];
                hasher.Digest(input, output);
                return output.ToArray();
            }
            catch (Exception ex)
            {
                logger.Error($"KOBRA Matrix: Error in Blake2b: {ex.Message}");
                
                using (var sha = SHA256.Create())
                {
                    return sha.ComputeHash(input);
                }
            }
        }

        private byte[] ComputeSkein256(byte[] input)
        {
            try
            {
                var hasher = new Skein();
                Span<byte> output = stackalloc byte[32];
                hasher.Digest(input, output);
                return output.ToArray();
            }
            catch (Exception ex)
            {
                logger.Error($"KOBRA Matrix: Error in Skein: {ex.Message}");
                
                using (var sha = SHA256.Create())
                {
                    return sha.ComputeHash(input);
                }
            }
        }

        private byte[] ComputeSHA3_256(byte[] input)
        {
            try
            {
                var hasher = new Sha3_256();
                Span<byte> output = stackalloc byte[32];
                hasher.Digest(input, output);
                return output.ToArray();
            }
            catch (Exception ex)
            {
                logger.Error($"KOBRA Matrix: Error in SHA3: {ex.Message}");
                
                using (var sha = SHA256.Create())
                {
                    return sha.ComputeHash(input);
                }
            }
        }

        private byte[] ApplyHeavyKodaMatrix(byte[] hash)
        {
            
            byte[] vec = new byte[64];
            for (int i = 0; i < 32; i++)
            {
                vec[2 * i] = (byte)(hash[i] >> 4);
                vec[2 * i + 1] = (byte)(hash[i] & 0x0F);
            }

            ushort[] sinusoidalValues = new ushort[64];
            for (int j = 0; j < 64; j++)
            {
                sinusoidalValues[j] = KobraJob.sinusoidalValues[vec[j]];
            }

            byte[] product = new byte[64];
            for (int i = 0; i < 64; i++)
            {
                ushort sum = 0;
                for (int j = 0; j < 64; j++)
                {
                    ushort sinusoidalValue = sinusoidalValues[j];
                    sum = (ushort)(sum + (ushort)(matrix[i, j] * sinusoidalValue));
                }
                product[i] = (byte)((sum & 0xF) ^ ((sum >> 4) & 0xF) ^ ((sum >> 8) & 0xF));
            }

            byte[] result = new byte[32];
            for (int i = 0; i < 32; i++)
            {
                byte shiftValue = (byte)(product[2 * i] << 4);
                
                byte exponentValue = (byte)Math.Pow(2, product[2 * i + 1]);
                
                if (exponentValue == 0xff)
                {
                    exponentValue = 0;
                }
                
                result[i] = (byte)(hash[i] ^ (shiftValue | exponentValue));
            }

            for (int i = 0; i < 32; i++)
            {
                result[i] ^= hash[i];
            }

            return result;
        }
    }

    public class PowHash
    {
        private readonly byte[] prePowHash;
        private readonly long timestamp;
        private static readonly ILogger logger = LogManager.GetCurrentClassLogger();

        public PowHash(byte[] prePowHash, long timestamp)
        {
            this.prePowHash = prePowHash;
            this.timestamp = timestamp;
        }

        public byte[] FinalizeWithNonce(ulong nonce)
        {
            using (var stream = new MemoryStream())
            {
                stream.Write(prePowHash, 0, prePowHash.Length);
                
                byte[] timestampBytes = BitConverter.GetBytes(timestamp);
                stream.Write(timestampBytes, 0, 8);
                
                stream.Write(new byte[32], 0, 32);
                
                byte[] nonceBytes = BitConverter.GetBytes(nonce);
                stream.Write(nonceBytes, 0, 8);

                return stream.ToArray();
            }
        }
    }
}
}
