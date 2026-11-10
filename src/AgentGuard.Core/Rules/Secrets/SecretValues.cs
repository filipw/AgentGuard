using System.Buffers;

namespace AgentGuard.Core.Rules.Secrets;

/// <summary>
/// Heuristics shared by the secret patterns and the generic high-entropy check: whether a value is
/// a placeholder rather than a credential, whether a token reads as words, and how random it is.
/// </summary>
/// <remarks>
/// Every check is ordinal and culture-invariant, and linear in the length of the value.
/// </remarks>
internal static class SecretValues
{
    // values that stand in for a credential in docs, samples and templates, compared after
    // lowercasing and dropping everything but letters and digits
    private static readonly HashSet<string> PlaceholderWords = new(StringComparer.Ordinal)
    {
        "password", "passwd", "pwd", "secret", "token", "apikey", "key", "changeme", "changeit",
        "redacted", "masked", "hidden", "removed", "example", "sample", "placeholder", "dummy",
        "none", "null", "nil", "undefined", "empty", "string", "required", "optional", "true",
        "false", "default", "value", "notset",
    };

    private static readonly HashSet<string>.AlternateLookup<ReadOnlySpan<char>> PlaceholderLookup =
        PlaceholderWords.GetAlternateLookup<ReadOnlySpan<char>>();

    private static readonly string[] PlaceholderPrefixes =
        ["your", "example", "sample", "dummy", "placeholder", "insert", "replace", "enter"];

    // the words a placeholder is written with after one of the prefixes: "your-api-key-goes-here",
    // "ENTER_YOUR_PASSWORD", "replace_with_real_token"
    private static readonly string[] PlaceholderVocabulary =
    [
        "your", "example", "sample", "dummy", "placeholder", "insert", "replace", "enter", "change",
        "password", "passwd", "passphrase", "pass", "pwd", "secret", "token", "api", "key", "access",
        "client", "auth", "bearer", "credential", "credentials", "connection", "string", "value",
        "here", "goes", "with", "real", "actual", "own", "the", "this", "that", "for", "and", "name",
        "user", "username", "account", "database", "id", "it", "me", "my", "a", "an", "to", "of", "in",
        "db", "test", "demo", "fake", "todo", "xxx",
    ];

    private static readonly SearchValues<char> HexDigits = SearchValues.Create("0123456789abcdefABCDEF");

    /// <summary>
    /// Whether <paramref name="value"/> stands in for a credential rather than being one: a template
    /// reference (<c>${VAR}</c>, <c>{{var}}</c>, <c>&lt;password&gt;</c>, <c>%VAR%</c>), a mask
    /// (<c>****</c>, <c>xxxx</c>), a single repeated character, or a placeholder word such as
    /// <c>password</c>, <c>changeme</c> or <c>your_api_key</c>.
    /// </summary>
    internal static bool IsPlaceholder(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty || IsTemplateReference(value))
            return true;

        var masked = true;
        var repeated = true;
        foreach (var c in value)
        {
            masked &= c is '*' or 'x' or 'X' or '\u2022' or '.' or '#' or '-' or '_' or '?';
            repeated &= c == value[0];
        }

        if (masked || repeated)
            return true;

        // the words and prefixes are short, so only the first 64 letters and digits matter
        Span<char> normalized = stackalloc char[64];
        var length = 0;
        var total = 0;
        foreach (var c in value)
        {
            if (!char.IsAsciiLetterOrDigit(c))
                continue;

            if (length < normalized.Length)
                normalized[length++] = char.ToLowerInvariant(c);
            total++;
        }

        normalized = normalized[..length];
        if (normalized.IsEmpty)
            return false;

        if (total == length && PlaceholderLookup.Contains(normalized))
            return true;

        // a placeholder phrase: one of the prefixes, then nothing but placeholder words and digits.
        // "your-api-key-here" and "ENTER_PASSWORD" are; "Enterprise2024!" and "Yourkshire#1987" only
        // start like one.
        foreach (var prefix in PlaceholderPrefixes)
        {
            if (normalized.StartsWith(prefix, StringComparison.Ordinal))
                return IsPlaceholderWords(normalized[prefix.Length..]);
        }

        return false;
    }

    /// <summary>
    /// Whether <paramref name="value"/> stands for a value filled in elsewhere: a variable or template
    /// reference (<c>${DB_PASSWORD}</c>, <c>$DB_PASSWORD</c>, <c>{{ secrets.key }}</c>,
    /// <c>%PASSWORD%</c>, <c>%(password)s</c>) or a bracketed description (<c>&lt;your-password&gt;</c>,
    /// <c>[password]</c>).
    /// </summary>
    /// <remarks>
    /// The whole value has to have that shape. A password that merely starts with one of the
    /// characters - <c>$uperS3cret!9</c>, <c>(Tr0ub4dor&amp;3)</c>, <c>%40dm1n</c> - is a password.
    /// </remarks>
    internal static bool IsTemplateReference(ReadOnlySpan<char> value)
    {
        if (value.Length < 2)
            return false;

        var first = value[0];
        var last = value[^1];

        switch (first)
        {
            case '$':
                // ${NAME}, $(NAME) or a shell-style variable name
                if (value[1] is '{' or '(')
                    return last is '}' or ')';
                return IsVariableName(value[1..]);

            case '%':
                // %NAME%, or a printf-style %(name)s / %s
                if (last == '%')
                    return IsDescription(value[1..^1]);
                return value[1] == '(' ? value.IndexOf(')') == value.Length - 2 : value.Length == 2 && char.IsAsciiLetter(value[1]);

            case '{':
                return last == '}';

            case '<':
                return last == '>' && IsDescription(value[1..^1]);

            case '[':
                return last == ']' && IsDescription(value[1..^1]);

            case '(':
                return last == ')' && IsDescription(value[1..^1]);

            default:
                return false;
        }
    }

    // a variable name as scripts write them: one case throughout, or camelCase without digits. Mixed
    // case together with digits ("$ecretPa55") is what a password looks like.
    private static bool IsVariableName(ReadOnlySpan<char> name)
    {
        if (name.IsEmpty || !(char.IsAsciiLetter(name[0]) || name[0] == '_'))
            return false;

        bool upper = false, lower = false, digit = false;
        foreach (var c in name)
        {
            if (char.IsAsciiLetterUpper(c)) upper = true;
            else if (char.IsAsciiLetterLower(c)) lower = true;
            else if (char.IsAsciiDigit(c)) digit = true;
            else if (c != '_') return false;
        }

        return !(upper && lower && digit);
    }

    // what stands between the brackets of a described placeholder: words, not punctuation
    private static bool IsDescription(ReadOnlySpan<char> inner)
    {
        if (inner.IsEmpty)
            return false;

        foreach (var c in inner)
        {
            if (!(char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or ' ' or '.' or ':'))
                return false;
        }

        return true;
    }

    // whether lower-case letters and digits can be read as placeholder words in a row, digits allowed anywhere
    private static bool IsPlaceholderWords(ReadOnlySpan<char> text)
    {
        while (!text.IsEmpty && char.IsAsciiDigit(text[0]))
            text = text[1..];

        if (text.IsEmpty)
            return true;

        foreach (var word in PlaceholderVocabulary)
        {
            if (text.StartsWith(word, StringComparison.Ordinal) && IsPlaceholderWords(text[word.Length..]))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Whether <paramref name="value"/> starts like a file path: <c>/</c>, <c>~/</c>, <c>./</c>,
    /// <c>../</c> or a drive letter.
    /// </summary>
    internal static bool LooksLikePath(ReadOnlySpan<char> value) =>
        value.StartsWith("/", StringComparison.Ordinal)
        || value.StartsWith("~/", StringComparison.Ordinal)
        || value.StartsWith("./", StringComparison.Ordinal)
        || value.StartsWith("../", StringComparison.Ordinal)
        || (value.Length >= 3 && char.IsAsciiLetter(value[0]) && value[1] == ':' && value[2] is '\\' or '/');

    /// <summary>Whether <paramref name="value"/> is a UUID in its 8-4-4-4-12 hex form.</summary>
    internal static bool IsUuid(ReadOnlySpan<char> value)
    {
        if (value.Length != 36)
            return false;

        for (var i = 0; i < value.Length; i++)
        {
            var valid = i is 8 or 13 or 18 or 23 ? value[i] == '-' : char.IsAsciiHexDigit(value[i]);
            if (!valid)
                return false;
        }

        return true;
    }

    /// <summary>Whether <paramref name="value"/> is non-empty and made of hex digits only.</summary>
    internal static bool IsHex(ReadOnlySpan<char> value) =>
        !value.IsEmpty && !value.ContainsAnyExcept(HexDigits);

    /// <summary>
    /// Whether <paramref name="token"/> reads as words - an ordinary word, a camelCase, PascalCase or
    /// snake_case identifier, a path of word segments - rather than a random string.
    /// </summary>
    /// <remarks>
    /// The letters are split into chunks at non-letters and at case changes (<c>getUserName</c> is
    /// get, User, Name; <c>XMLHttp</c> is XML, Http). Words have chunks of three or more letters on
    /// average, at least one vowel in four letters, and no run of more than four consonants within
    /// a chunk; random strings miss at least one of these.
    /// </remarks>
    internal static bool IsWordLike(ReadOnlySpan<char> token)
    {
        var letters = 0;
        var chunks = 0;
        var vowels = 0;
        var consonantRun = 0;
        var longestConsonantRun = 0;

        for (var i = 0; i < token.Length; i++)
        {
            var c = token[i];
            if (!char.IsAsciiLetter(c))
                continue;

            var previous = i > 0 ? token[i - 1] : '\0';
            var next = i + 1 < token.Length ? token[i + 1] : '\0';
            var startsChunk = !char.IsAsciiLetter(previous)
                || (char.IsAsciiLetterLower(previous) && char.IsAsciiLetterUpper(c))
                || (char.IsAsciiLetterUpper(previous) && char.IsAsciiLetterUpper(c) && char.IsAsciiLetterLower(next));

            if (startsChunk)
            {
                chunks++;
                consonantRun = 0;
            }

            letters++;
            if (c is 'a' or 'e' or 'i' or 'o' or 'u' or 'A' or 'E' or 'I' or 'O' or 'U')
            {
                vowels++;
                consonantRun = 0;
            }
            else
            {
                longestConsonantRun = Math.Max(longestConsonantRun, ++consonantRun);
            }
        }

        return letters > 0
            && letters * 2 >= token.Length
            && letters >= chunks * 3
            && vowels * 4 >= letters
            && longestConsonantRun <= 4;
    }

    /// <summary>The Shannon entropy of <paramref name="value"/>, in bits per character.</summary>
    internal static double ShannonEntropy(ReadOnlySpan<char> value)
    {
        if (value.IsEmpty)
            return 0;

        Span<int> ascii = stackalloc int[128];
        Dictionary<char, int>? other = null;
        foreach (var c in value)
        {
            if (c < 128)
            {
                ascii[c]++;
            }
            else
            {
                other ??= [];
                other[c] = other.GetValueOrDefault(c) + 1;
            }
        }

        double length = value.Length;
        var entropy = 0.0;
        foreach (var count in ascii)
        {
            if (count > 0)
                entropy -= count / length * Math.Log2(count / length);
        }

        if (other is not null)
        {
            foreach (var count in other.Values)
                entropy -= count / length * Math.Log2(count / length);
        }

        return entropy;
    }

    /// <summary>
    /// The entropy a random string of <paramref name="value"/>'s length and character set typically
    /// reaches: the log of the number of distinct symbols such a string is expected to contain.
    /// </summary>
    /// <remarks>
    /// The character set is the narrowest of hex (16 symbols), single-case alphanumeric (36), the
    /// base64 alphabet (64) and printable ASCII (94) that fits the value, so a hex string is
    /// measured against what random hex reaches, not against base64, and a short token against
    /// what a random string of its length can reach.
    /// </remarks>
    internal static double ExpectedRandomEntropy(ReadOnlySpan<char> value)
    {
        var symbols = (double)CharacterSetSize(value);
        var distinct = symbols * (1 - Math.Pow(1 - 1 / symbols, value.Length));
        return Math.Log2(Math.Max(distinct, 1));
    }

    private static int CharacterSetSize(ReadOnlySpan<char> value)
    {
        if (IsHex(value) && (!value.ContainsAnyInRange('a', 'f') || !value.ContainsAnyInRange('A', 'F')))
            return 16;

        var lower = false;
        var upper = false;
        var base64Symbol = false;
        foreach (var c in value)
        {
            if (char.IsAsciiLetterLower(c))
                lower = true;
            else if (char.IsAsciiLetterUpper(c))
                upper = true;
            else if (c is '+' or '/' or '=')
                base64Symbol = true;
            else if (!char.IsAsciiDigit(c) && c is not ('-' or '_'))
                return 94;
        }

        return (lower && upper) || base64Symbol ? 64 : 36;
    }
}
