using System.Buffers.Binary;
using System.Text;

namespace AgentGuard.Onnx.Tests;

/// <summary>
/// A tiny unigram SentencePiece model laid out like the DeBERTa v3 vocabularies - <c>[PAD]</c> 0,
/// <c>[CLS]</c> 1 (also the BOS id), <c>[SEP]</c> 2 (also the EOS id), <c>[UNK]</c> 3 - with two words,
/// written as the protobuf the tokenizer reads, so tokenizer behaviour can be tested without
/// downloading a model.
/// </summary>
internal static class SentencePieceTestModel
{
    public const int ClsId = 1;
    public const int SepId = 2;
    public const int HelloId = 4;
    public const int WorldId = 5;

    // piece types from sentencepiece_model.proto
    private const int Normal = 1;
    private const int Unknown = 2;
    private const int Control = 3;

    // protobuf wire types
    private const int Varint = 0;
    private const int LengthDelimited = 2;
    private const int Fixed32 = 5;

    /// <summary>Writes the model to a temporary file and returns its path; the caller deletes it.</summary>
    public static string WriteToTempFile()
    {
        var path = Path.Combine(Path.GetTempPath(), $"agentguard-spm-{Guid.NewGuid():N}.model");
        File.WriteAllBytes(path, Build());
        return path;
    }

    /// <summary>The serialized model.</summary>
    public static byte[] Build()
    {
        using var model = new MemoryStream();

        (string Piece, float Score, int Type)[] pieces =
        [
            ("[PAD]", 0f, Control), ("[CLS]", 0f, Control), ("[SEP]", 0f, Control), ("[UNK]", 0f, Unknown),
            ("▁hello", -1f, Normal), ("▁world", -1f, Normal), ("▁", -2f, Normal),
            ("h", -5f, Normal), ("e", -5f, Normal), ("l", -5f, Normal), ("o", -5f, Normal),
            ("w", -5f, Normal), ("r", -5f, Normal), ("d", -5f, Normal),
        ];

        foreach (var (piece, score, type) in pieces)
        {
            WriteMessage(model, 1, message =>
            {
                WriteString(message, 1, piece);
                WriteFloat(message, 2, score);
                WriteInt(message, 3, type);
            });
        }

        // trainer spec: unigram, with the special ids and pieces of the DeBERTa v3 vocabularies
        WriteMessage(model, 2, trainer =>
        {
            WriteInt(trainer, 3, 1);
            WriteInt(trainer, 40, 3);
            WriteInt(trainer, 41, ClsId);
            WriteInt(trainer, 42, SepId);
            WriteInt(trainer, 43, 0);
            WriteString(trainer, 45, "[UNK]");
            WriteString(trainer, 46, "[CLS]");
            WriteString(trainer, 47, "[SEP]");
            WriteString(trainer, 48, "[PAD]");
        });

        // normalizer spec: no character map, dummy prefix, whitespace collapsed and escaped
        WriteMessage(model, 3, normalizer =>
        {
            WriteString(normalizer, 1, "identity");
            WriteInt(normalizer, 3, 1);
            WriteInt(normalizer, 4, 1);
            WriteInt(normalizer, 5, 1);
        });

        return model.ToArray();
    }

    private static void WriteMessage(Stream stream, int field, Action<Stream> write)
    {
        using var message = new MemoryStream();
        write(message);
        WriteTag(stream, field, LengthDelimited);
        WriteVarint(stream, (ulong)message.Length);
        message.WriteTo(stream);
    }

    private static void WriteString(Stream stream, int field, string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        WriteTag(stream, field, LengthDelimited);
        WriteVarint(stream, (ulong)bytes.Length);
        stream.Write(bytes);
    }

    private static void WriteFloat(Stream stream, int field, float value)
    {
        Span<byte> bytes = stackalloc byte[4];
        BinaryPrimitives.WriteSingleLittleEndian(bytes, value);
        WriteTag(stream, field, Fixed32);
        stream.Write(bytes);
    }

    private static void WriteInt(Stream stream, int field, int value)
    {
        WriteTag(stream, field, Varint);
        WriteVarint(stream, (ulong)value);
    }

    private static void WriteTag(Stream stream, int field, int wireType) =>
        WriteVarint(stream, (uint)((field << 3) | wireType));

    private static void WriteVarint(Stream stream, ulong value)
    {
        while (value >= 0x80UL)
        {
            stream.WriteByte((byte)((value & 0x7FUL) | 0x80UL));
            value >>= 7;
        }

        stream.WriteByte((byte)value);
    }
}
