// SPDX-FileCopyrightText: 2025 Demerzel Solutions Limited
// SPDX-License-Identifier: LGPL-3.0-only

using Nethermind.Core;
using Nethermind.Core.Crypto;
using Nethermind.Core.Extensions;
using Nethermind.Trie;

namespace Nethermind.State.Flat.Persistence;

/// <summary>
/// Common persistence logic for Trie. The trie is encoded with 4 different database (column db). This implementation
/// exploit the fact that a vast majority of the key's TreePath have a length less than 15.
/// This can be encoded with only 8 byte. The average length of the TreePath only increase by 1 if the num of key
/// increase by 16x.
///
/// To handle case where path length is greater than 15, a separate fallback column is used which add both state and storage nodes,
/// with a prefix partition key to separate them.
///
/// For storage, only 20 byte of the hashed address prefix is used. The first 4 byte is put in front while the remaining
/// 16 byte is put at the end. This make rocksdb's index smaller due to shortened index key.
///
/// StateNodesTop
/// <3-byte-path>
///
/// StateNodes
/// <8-byte-path-with-length-in-last-nib>
///
/// StorageNodes
/// <4-byte-addr-prefix><8-byte-path-with-length
///
///
/// For storage, this can be lowered even further to 11 and 6 byte key
/// </summary>
public static class BaseTriePersistence
{
    private const int StorageHashPrefixLength = 20; // Store prefix of the 32 byte of the storage. Reduces index size.
    private const int FullPathLength = 32;
    private const int PathLengthLength = 1;

    private const int ShortenedStatePathThreshold = 15; // Must be odd
    private const int ShortenedStatePathLength = 8;

    private const int ShortenedStoragePathThreshold = 15;
    private const int ShortenedStoragePathLength = 8;

    // Note to self: Splitting the storage tree have been shown to not improve block cache hit rate
    private const int StateNodesTopThreshold = 5;
    private const int StateNodesTopPathLength = 3;
    private const int StateNodesTopKeyLength = StateNodesTopPathLength;

    private const int FullStateNodesKeyLength = 1 + FullPathLength + PathLengthLength;

    private const int StoragePrefixPortion = 4;
    private const int ShortenedStorageNodesKeyLength = StoragePrefixPortion + ShortenedStoragePathLength + (StorageHashPrefixLength - StoragePrefixPortion);
    private const int FullStorageNodesKeyLength = 1 + StorageHashPrefixLength + FullPathLength + PathLengthLength;

    private static ReadOnlySpan<byte> EncodeStateTopNodeKey(Span<byte> buffer, in TreePath path)
    {
        // Looks like this <3-byte-path>
        // Last 4 bit of the path is the length

        path.Path.Bytes[0..StateNodesTopPathLength].CopyTo(buffer);
        // Pack length into lower 4 bits of last byte (upper 4 bits contain path data)
        byte lengthAsByte = (byte)path.Length;
        buffer[StateNodesTopPathLength - 1] = (byte)((buffer[StateNodesTopPathLength - 1] & 0xf0) | (lengthAsByte & 0x0f));
        return buffer[..StateNodesTopKeyLength];
    }

    private static ReadOnlySpan<byte> EncodeShortenedStateNodeKey(Span<byte> buffer, in TreePath path)
    {
        // Looks like this <8-byte-path>
        // Last 4 bit of the path is the length

        path.EncodeWith8Byte(buffer);
        return buffer[..ShortenedStatePathLength];
    }

    private static ReadOnlySpan<byte> EncodeFullStateNodeKey(Span<byte> buffer, in TreePath path)
    {
        // Looks like this <0-constant><32-byte-path><1-byte-length>
        buffer[0] = 0;
        path.Path.Bytes.CopyTo(buffer[1..]);
        buffer[(1 + FullPathLength)] = (byte)path.Length;
        return buffer[..FullStateNodesKeyLength];
    }

    internal static ReadOnlySpan<byte> EncodeShortenedStorageNodeKey(Span<byte> buffer, Hash256 addr, in TreePath path)
    {
        // Looks like this <4-byte-address-prefix><6-byte-path-portion><16-byte-remaining-address>
        addr.Bytes[..StoragePrefixPortion].CopyTo(buffer);
        path.EncodeWith6Byte(buffer[StoragePrefixPortion..]);
        addr.Bytes[StoragePrefixPortion..StorageHashPrefixLength].CopyTo(buffer[(StoragePrefixPortion + ShortenedStoragePathLength)..]);
        return buffer[..ShortenedStorageNodesKeyLength];
    }

    private static ReadOnlySpan<byte> EncodeFullStorageNodeKey(Span<byte> buffer, Hash256 address, in TreePath path)
    {
        // Looks like this <1-constant><4-byte-address-prefix><32-byte-path><1-byte-length><16-byte-remaining-address>
        buffer[0] = 1;
        address.Bytes[..StoragePrefixPortion].CopyTo(buffer[1..]);
        path.Path.Bytes.CopyTo(buffer[(1 + StoragePrefixPortion)..]);
        buffer[(1 + StoragePrefixPortion + FullPathLength)] = (byte)path.Length;
        address.Bytes[StoragePrefixPortion..StorageHashPrefixLength].CopyTo(buffer[(1 + StoragePrefixPortion + FullPathLength + PathLengthLength)..]);
        return buffer[..FullStorageNodesKeyLength];
    }

    public readonly struct WriteBatch(
        ISortedKeyValueStore storageNodesSnap,
        ISortedKeyValueStore fallbackNodesSnap,
        IWriteOnlyKeyValueStore stateTopNodes,
        IWriteOnlyKeyValueStore stateNodes,
        IWriteOnlyKeyValueStore storageNodes,
        IWriteOnlyKeyValueStore fallbackNodes,
        WriteFlags flags
    ) : BasePersistence.ITrieWriteBatch
    {

        public void SelfDestruct(in ValueHash256 accountPath)
        {
            // Technically, this is kinda not needed for nodes as its always traversed so orphaned trie just get skipped.
            {
                Span<byte> firstKey = stackalloc byte[StoragePrefixPortion];
                Span<byte> lastKey = stackalloc byte[ShortenedStorageNodesKeyLength + 1];
                firstKey.Fill(0x00);
                lastKey.Fill(0xff);
                accountPath.Bytes[..StoragePrefixPortion].CopyTo(firstKey);
                accountPath.Bytes[..StoragePrefixPortion].CopyTo(lastKey);

                using (ISortedView storageNodeReader = storageNodesSnap.GetViewBetween(firstKey, lastKey))
                {
                    var storageNodeWriter = storageNodes;
                    while (storageNodeReader.MoveNext())
                    {
                        // Double check the end portion
                        if (Bytes.AreEqual(storageNodeReader.CurrentKey[(StoragePrefixPortion + ShortenedStoragePathLength)..], accountPath.Bytes[StoragePrefixPortion..(StorageHashPrefixLength)]))
                        {
                            storageNodeWriter.Remove(storageNodeReader.CurrentKey);
                        }
                    }
                }
            }

            {
                // Do the same for the fallback nodes, except that the key must be prefixed `1` also
                Span<byte> firstKey = stackalloc byte[1 + StoragePrefixPortion];
                Span<byte> lastKey = stackalloc byte[1 + ShortenedStorageNodesKeyLength + 1];
                firstKey.Fill(0x00);
                lastKey.Fill(0xff);
                firstKey[0] = 1;
                lastKey[0] = 1;
                accountPath.Bytes[..StoragePrefixPortion].CopyTo(firstKey[1..]);
                accountPath.Bytes[..StoragePrefixPortion].CopyTo(lastKey[1..]);
                using (ISortedView storageNodeReader = fallbackNodesSnap.GetViewBetween(firstKey, lastKey))
                {
                    var storageNodeWriter = storageNodes;
                    while (storageNodeReader.MoveNext())
                    {
                        // Double check the end portion
                        if (Bytes.AreEqual(storageNodeReader.CurrentKey[(1 + StoragePrefixPortion + FullPathLength)..], accountPath.Bytes[StoragePrefixPortion..(StorageHashPrefixLength)]))
                        {
                            storageNodeWriter.Remove(storageNodeReader.CurrentKey);
                        }
                    }
                }
            }
        }

        public void SetTrieNodes(Hash256? address, TreePath path, TrieNode tn)
        {
            if (address is null)
            {
                if (path.Length <= StateNodesTopThreshold)
                {
                    stateTopNodes.PutSpan(EncodeStateTopNodeKey(stackalloc byte[StateNodesTopKeyLength], path), tn.FullRlp.Span, flags);
                }
                else if (path.Length <= ShortenedStatePathThreshold)
                {
                    stateNodes.PutSpan(EncodeShortenedStateNodeKey(stackalloc byte[ShortenedStatePathLength], path), tn.FullRlp.Span, flags);
                }
                else
                {
                    fallbackNodes.PutSpan(EncodeFullStateNodeKey(stackalloc byte[FullStateNodesKeyLength], in path), tn.FullRlp.Span, flags);
                }
            }
            else
            {
                if (path.Length <= ShortenedStoragePathThreshold)
                {
                    storageNodes.PutSpan(EncodeShortenedStorageNodeKey(stackalloc byte[ShortenedStorageNodesKeyLength], address, path), tn.FullRlp.Span, flags);
                }
                else
                {
                    fallbackNodes.PutSpan(EncodeFullStorageNodeKey(stackalloc byte[FullStorageNodesKeyLength], address, in path), tn.FullRlp.Span, flags);
                }
            }
        }
    }


    public readonly struct Reader(
        IReadOnlyKeyValueStore stateTopNodes,
        IReadOnlyKeyValueStore stateNodes,
        IReadOnlyKeyValueStore storageNodes,
        IReadOnlyKeyValueStore fallbackNodes
    ) : BasePersistence.ITrieReader
    {
        public byte[]? TryLoadRlp(Hash256? address, in TreePath path, ReadFlags flags)
        {
            if (address is null)
            {
                if (path.Length <= StateNodesTopThreshold)
                {
                    return stateTopNodes.Get(EncodeStateTopNodeKey(stackalloc byte[StateNodesTopKeyLength], in path));
                }
                else if (path.Length <= ShortenedStatePathThreshold)
                {
                    return stateNodes.Get(EncodeShortenedStateNodeKey(stackalloc byte[ShortenedStatePathLength], in path));
                }
                else
                {
                    return fallbackNodes.Get(EncodeFullStateNodeKey(stackalloc byte[FullStateNodesKeyLength], in path));
                }
            }
            else
            {
                if (path.Length <= ShortenedStoragePathThreshold)
                {
                    return storageNodes.Get(EncodeShortenedStorageNodeKey(stackalloc byte[ShortenedStorageNodesKeyLength], address, in path));
                }
                else
                {
                    return fallbackNodes.Get(EncodeFullStorageNodeKey(stackalloc byte[FullStorageNodesKeyLength], address, in path));
                }
            }
        }
    }
}
