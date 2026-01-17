// SPDX-FileCopyrightText: 2025 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using System;
using System.Buffers.Binary;
using Autofac.Features.AttributeFilters;
using Nethermind.Core;
using Nethermind.Core.Crypto;
using Nethermind.Db;
using Nethermind.Logging;
using Nethermind.State.Flat.Persistence.BloomFilter;
using Nethermind.Trie;

namespace Nethermind.State.Flat.Persistence;

public class ShortenedRocksdbPersistence : IPersistence, IPersistenceWithConcurrentTrie
{
    private readonly IColumnsDb<FlatDbColumns> _db;
    private static byte[] CurrentStateKey = Keccak.Compute("CurrentState").BytesToArray();

    private readonly SegmentedBloom _bloomFilter;
    private readonly ILogger _logger;

    public ShortenedRocksdbPersistence(
        IColumnsDb<FlatDbColumns> db,
        [KeyFilter(DbNames.Flat)] SegmentedBloom bloomFilter,
        ILogManager logManager)
    {
        _db = db;
        _bloomFilter = bloomFilter;
        _logger = logManager.GetClassLogger<RocksdbPersistence>();
    }

    internal static StateId ReadCurrentState(IReadOnlyKeyValueStore kv)
    {
        byte[]? bytes = kv.Get(CurrentStateKey);
        if (bytes is null || bytes.Length == 0)
        {
            return new StateId(-1, Keccak.EmptyTreeHash);
        }

        long blockNumber = BinaryPrimitives.ReadInt64BigEndian(bytes);
        Hash256 stateHash = new Hash256(bytes[8..]);
        return new StateId(blockNumber, stateHash);
    }

    internal static void SetCurrentState(IWriteOnlyKeyValueStore kv, StateId stateId)
    {
        Span<byte> bytes = stackalloc byte[8 + 32];
        BinaryPrimitives.WriteInt64BigEndian(bytes[..8], stateId.blockNumber);
        stateId.stateRoot.BytesAsSpan.CopyTo(bytes[8..]);

        kv.PutSpan(CurrentStateKey, bytes);
    }

    public IPersistence.IPersistenceReader CreateReader()
    {
        var snapshot = _db.CreateSnapshot();
        var trieReader = new ShortTriePersistence.Reader(
            snapshot.GetColumn(FlatDbColumns.StateTopNodes),
            snapshot.GetColumn(FlatDbColumns.StateNodes),
            snapshot.GetColumn(FlatDbColumns.StorageNodes),
            snapshot.GetColumn(FlatDbColumns.FallbackNodes)
        );

        var currentState = ReadCurrentState(snapshot.GetColumn(FlatDbColumns.Metadata));

        IReadOnlyKeyValueStore state = snapshot.GetColumn(FlatDbColumns.Account);
        IReadOnlyKeyValueStore storage = snapshot.GetColumn(FlatDbColumns.Storage);

        if (_bloomFilter.IsEnabled)
        {
            return new BasePersistence.Reader<BasePersistence.ToHashedFlatReader<BloomFlatWrapper.BloomInterceptor<BaseFlatPersistence.Reader>>, ShortTriePersistence.Reader>(
                new BasePersistence.ToHashedFlatReader<BloomFlatWrapper.BloomInterceptor<BaseFlatPersistence.Reader>>(
                    new BloomFlatWrapper.BloomInterceptor<BaseFlatPersistence.Reader>(
                        new BaseFlatPersistence.Reader(
                            state,
                            storage,
                            useShortPrefix: true
                        ),
                        _bloomFilter
                    )
                ),
                trieReader,
                currentState,
                new Reactive.AnonymousDisposable(() =>
                {
                    snapshot.Dispose();
                })
            );
        }

        return new BasePersistence.Reader<BasePersistence.ToHashedFlatReader<BaseFlatPersistence.Reader>, ShortTriePersistence.Reader>(
            new BasePersistence.ToHashedFlatReader<BaseFlatPersistence.Reader>(
                new BaseFlatPersistence.Reader(
                    state,
                    storage,
                    useShortPrefix: true
                )
            ),
            trieReader,
            currentState,
            new Reactive.AnonymousDisposable(() =>
            {
                snapshot.Dispose();
            })
        );
    }

    public IPersistence.IWriteBatch CreateWriteBatch(StateId from, StateId to, WriteFlags flags)
    {
        var dbSnap = _db.CreateSnapshot();
        var currentState = ReadCurrentState(dbSnap.GetColumn(FlatDbColumns.Metadata));
        if (currentState != from)
        {
            dbSnap.Dispose();
            throw new InvalidOperationException(
                $"Attempted to apply snapshot on top of wrong state. Snapshot from: {from}, Db state: {currentState}");
        }

        IColumnsWriteBatch<FlatDbColumns> batch = _db.StartWriteBatch();
        IWriteOnlyKeyValueStore state = batch.GetColumnBatch(FlatDbColumns.Account);
        IWriteOnlyKeyValueStore storage = batch.GetColumnBatch(FlatDbColumns.Storage);

        var trieWriteBatch = new ShortTriePersistence.WriteBatch(
            (ISortedKeyValueStore)dbSnap.GetColumn(FlatDbColumns.StorageNodes),
            batch.GetColumnBatch(FlatDbColumns.StateTopNodes),
            batch.GetColumnBatch(FlatDbColumns.StateNodes),
            batch.GetColumnBatch(FlatDbColumns.StorageNodes),
            batch.GetColumnBatch(FlatDbColumns.FallbackNodes),
            flags);

        if (_bloomFilter.IsEnabled)
        {
            return new BasePersistence.WriteBatch<BasePersistence.ToHashedWriteBatch<BloomFlatWrapper.BloomWriter<BaseFlatPersistence.WriteBatch>>, ShortTriePersistence.WriteBatch>(
                new BasePersistence.ToHashedWriteBatch<BloomFlatWrapper.BloomWriter<BaseFlatPersistence.WriteBatch>>(
                    new BloomFlatWrapper.BloomWriter<BaseFlatPersistence.WriteBatch>(
                        new BaseFlatPersistence.WriteBatch(
                            ((ISortedKeyValueStore)dbSnap.GetColumn(FlatDbColumns.Storage)),
                            state,
                            storage,
                            flags,
                            useShortPrefix: true
                        ),
                        _bloomFilter,
                        (flags & WriteFlags.DisableWAL) != 0
                    )
                ),
                trieWriteBatch,
                new Reactive.AnonymousDisposable(() =>
                {
                    SetCurrentState(batch.GetColumnBatch(FlatDbColumns.Metadata), to);
                    batch.Dispose();
                    dbSnap.Dispose();
                    if (!flags.HasFlag(WriteFlags.DisableWAL))
                    {
                        _bloomFilter.Flush();
                    }
                    else
                    {
                        _db.Flush(onlyWal: true);
                    }
                })
            );
        }

        return new BasePersistence.WriteBatch<BasePersistence.ToHashedWriteBatch<BaseFlatPersistence.WriteBatch>, ShortTriePersistence.WriteBatch>(
            new BasePersistence.ToHashedWriteBatch<BaseFlatPersistence.WriteBatch>(
                new BaseFlatPersistence.WriteBatch(
                    ((ISortedKeyValueStore)dbSnap.GetColumn(FlatDbColumns.Storage)),
                    state,
                    storage,
                    flags,
                    useShortPrefix: true
                )
            ),
            trieWriteBatch,
            new Reactive.AnonymousDisposable(() =>
            {
                SetCurrentState(batch.GetColumnBatch(FlatDbColumns.Metadata), to);
                batch.Dispose();
                dbSnap.Dispose();
                if (!flags.HasFlag(WriteFlags.DisableWAL))
                {
                    _bloomFilter.Flush();
                }
                else
                {
                    _db.Flush(onlyWal: true);
                }
            })
        );
    }

    public bool WarmUpWhole(CancellationToken cancellation)
    {
        _logger.Warn("Warming up storage...");
        var storageDb = (ISortedKeyValueStore) _db.GetColumnDb(FlatDbColumns.Storage);
        ShardedParallelWarmup(storageDb, cancellation);

        if (cancellation.IsCancellationRequested) return false;
        _logger.Warn("Warming up account...");
        var accountDb = (ISortedKeyValueStore) _db.GetColumnDb(FlatDbColumns.Account);
        ShardedParallelWarmup(accountDb, cancellation);

        _logger.Warn("Warmup complete");
        return true;
    }

    private void ShardedParallelWarmup(ISortedKeyValueStore kvStore, CancellationToken cancellation)
    {
        long num = 0;
        Parallel.For(0, 255, idx =>
        {
            if (cancellation.IsCancellationRequested) return;
            byte[] firstKey = [(byte)idx];
            byte[] secondKey = [];
            if (idx == 255)
            {
                secondKey = [(byte)idx, (byte)idx];
            }
            else
            {
                secondKey = [(byte)(idx + 1)];
            }

            long localCount = 0;
            using (var view = kvStore.GetViewBetween(firstKey, secondKey))
            {
                while (view.MoveNext())
                {
                    localCount++;
                    if (localCount % 1000 == 0)
                    {
                        // Check every 1000 key only, in case its heavy
                        if (cancellation.IsCancellationRequested) return;
                    }

                    long cur = Interlocked.Increment(ref num);
                    if (cur % 1_000_000 == 0)
                    {
                        if (cancellation.IsCancellationRequested) return;
                        _logger.Warn($"{cur:N0} keys");
                    }
                }
            }
        });
    }

    public IPersistenceWithConcurrentTrie.IWriteBatch CreateTrieWriteBatch(WriteFlags flags = WriteFlags.None)
    {
        var dbSnap = _db.CreateSnapshot();
        IColumnsWriteBatch<FlatDbColumns> batch = _db.StartWriteBatch();
        var trieWriteBatch = new ShortTriePersistence.WriteBatch(
            (ISortedKeyValueStore)dbSnap.GetColumn(FlatDbColumns.StorageNodes),
            batch.GetColumnBatch(FlatDbColumns.StateTopNodes),
            batch.GetColumnBatch(FlatDbColumns.StateNodes),
            batch.GetColumnBatch(FlatDbColumns.StorageNodes),
            batch.GetColumnBatch(FlatDbColumns.FallbackNodes),
            flags);

        return new ConcurrentTrieWriter(trieWriteBatch, dbSnap, batch);
    }

    private class ConcurrentTrieWriter(ShortTriePersistence.WriteBatch trieWriteBatch, IColumnDbSnapshot<FlatDbColumns> dbSnap, IColumnsWriteBatch<FlatDbColumns> batch) : IPersistenceWithConcurrentTrie.IWriteBatch
    {
        public void Dispose()
        {
            dbSnap.Dispose();
            batch.Dispose();
        }

        public void SetTrieNodes(Hash256? address, in TreePath path, TrieNode tnValue)
        {
            trieWriteBatch.SetTrieNodes(address, path, tnValue);
        }
    }
}
