using System;
using System.Numerics;
using Miningcore.Crypto;
using Miningcore.Crypto.Hashing.Algorithms;
using Miningcore.Extensions;
using Miningcore.Stratum;
using Miningcore.Util;
using NBitcoin;

namespace Miningcore.Blockchain.Kaspa.Custom.Kobra;

public class KobraJob : KaspaJob
{
    protected Blake3 blake3Hasher;
    protected Sha3_256 sha3_256Hasher;
    protected Skein skeinHasher;

    public KobraJob(IHashAlgorithm customBlockHeaderHasher, IHashAlgorithm customCoinbaseHasher, IHashAlgorithm customShareHasher) 
        : base(customBlockHeaderHasher, customCoinbaseHasher, customShareHasher)
    {
        this.blake3Hasher = new Blake3();
        this.sha3_256Hasher = new Sha3_256();
        this.skeinHasher = new Skein();
    }

    protected override Share ProcessShareInternal(StratumConnection worker, string nonce)
    {
        var context = worker.ContextAs<KaspaWorkerContext>();

        BlockTemplate.Header.Nonce = Convert.ToUInt64(nonce, 16);

        var prePowHashBytes = SerializeHeader(BlockTemplate.Header, true);
        var coinbaseBytes = SerializeCoinbase(prePowHashBytes, BlockTemplate.Header.Timestamp, BlockTemplate.Header.Nonce);

        Span<byte> blake3Bytes = stackalloc byte[32];
        blake3Hasher.Digest(coinbaseBytes, blake3Bytes);

        Span<byte> sha3_256Bytes = stackalloc byte[32];
        sha3_256Hasher.Digest(blake3Bytes, sha3_256Bytes);
        
        Span<byte> skeinBytes = stackalloc byte[32];
        skeinHasher.Digest(sha3_256Bytes, skeinBytes);

        Span<byte> hashCoinbaseBytes = stackalloc byte[32];
        shareHasher.Digest(ComputeCoinbase(prePowHashBytes, skeinBytes), hashCoinbaseBytes);

        var targetHashCoinbaseBytes = new Target(new BigInteger(hashCoinbaseBytes.ToNewReverseArray(), true, true));
        var hashCoinbaseBytesValue = targetHashCoinbaseBytes.ToUInt256();

        var shareDiff = (double) new BigRational(KaspaConstants.Diff1b, targetHashCoinbaseBytes.ToBigInteger()) * shareMultiplier;

        var stratumDifficulty = context.Difficulty;
        var ratio = shareDiff / stratumDifficulty;

        var isBlockCandidate = hashCoinbaseBytesValue <= blockTargetValue;

        if (!isBlockCandidate && ratio < 0.99)
        {
            if (context.VarDiff?.LastUpdate != null && context.PreviousDifficulty.HasValue)
            {
                ratio = shareDiff / context.PreviousDifficulty.Value;

                if (ratio < 0.99)
                    throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");

                stratumDifficulty = context.PreviousDifficulty.Value;
            }
            else
                throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");
        }

        var result = new Share
        {
            BlockHeight = (long) BlockTemplate.Header.DaaScore,
            NetworkDifficulty = Difficulty,
            Difficulty = context.Difficulty / shareMultiplier
        };

        if (isBlockCandidate)
        {
            var hashBytes = SerializeHeader(BlockTemplate.Header, false);

            result.IsBlockCandidate = true;
            result.BlockHash = hashBytes.ToHexString();
        }

        return result;
    }
}
