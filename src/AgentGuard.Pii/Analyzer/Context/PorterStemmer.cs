namespace AgentGuard.Pii.Analyzer.Context;

/// <summary>
/// A compact, dependency-free implementation of the classic Porter stemming algorithm (1980), a
/// public-domain suffix-stripping stemmer for English. Used as an offline approximation of dictionary
/// lemmatization for context matching.
/// </summary>
internal static class PorterStemmer
{
    /// <summary>Returns the Porter stem of <paramref name="word"/> (assumed already lowercased).</summary>
    public static string Stem(string word)
    {
        if (word.Length <= 2)
        {
            return word;
        }

        var b = word.ToCharArray();
        var k = b.Length - 1;

        k = Step1Ab(b, k);
        k = Step1C(b, k);
        k = Step2(b, k);
        k = Step3(b, k);
        k = Step4(b, k);
        k = Step5(b, k);

        return new string(b, 0, k + 1);
    }

    // a consonant is a letter that is not a vowel, with 'y' being a consonant unless preceded by a consonant
    private static bool IsConsonant(char[] b, int i)
    {
        switch (b[i])
        {
            case 'a' or 'e' or 'i' or 'o' or 'u':
                return false;
            case 'y':
                return i == 0 || !IsConsonant(b, i - 1);
            default:
                return true;
        }
    }

    // measure: the number of consonant sequences between 0 and j
    private static int Measure(char[] b, int j)
    {
        var n = 0;
        var i = 0;
        while (true)
        {
            if (i > j)
            {
                return n;
            }

            if (!IsConsonant(b, i))
            {
                break;
            }

            i++;
        }

        i++;
        while (true)
        {
            while (true)
            {
                if (i > j)
                {
                    return n;
                }

                if (IsConsonant(b, i))
                {
                    break;
                }

                i++;
            }

            i++;
            n++;
            while (true)
            {
                if (i > j)
                {
                    return n;
                }

                if (!IsConsonant(b, i))
                {
                    break;
                }

                i++;
            }

            i++;
        }
    }

    // true if 0..j contains a vowel
    private static bool VowelInStem(char[] b, int j)
    {
        for (var i = 0; i <= j; i++)
        {
            if (!IsConsonant(b, i))
            {
                return true;
            }
        }

        return false;
    }

    // true if j and j-1 are the same consonant (double consonant)
    private static bool DoubleConsonant(char[] b, int j) =>
        j >= 1 && b[j] == b[j - 1] && IsConsonant(b, j);

    // true if i-2,i-1,i is consonant-vowel-consonant and the final consonant is not w, x or y
    private static bool Cvc(char[] b, int i)
    {
        if (i < 2 || !IsConsonant(b, i) || IsConsonant(b, i - 1) || !IsConsonant(b, i - 2))
        {
            return false;
        }

        var ch = b[i];
        return ch is not ('w' or 'x' or 'y');
    }

    private static bool EndsWith(char[] b, int k, string s)
    {
        var len = s.Length;
        if (len > k + 1)
        {
            return false;
        }

        for (var i = 0; i < len; i++)
        {
            if (b[k - len + 1 + i] != s[i])
            {
                return false;
            }
        }

        return true;
    }

    // replace the suffix ending at k with s; returns the new end index
    private static int SetTo(char[] b, ref int k, int stemEnd, string s)
    {
        for (var i = 0; i < s.Length; i++)
        {
            b[stemEnd + 1 + i] = s[i];
        }

        k = stemEnd + s.Length;
        return k;
    }

    private static int Step1Ab(char[] b, int k)
    {
        if (b[k] == 's')
        {
            if (EndsWith(b, k, "sses"))
            {
                k -= 2;
            }
            else if (EndsWith(b, k, "ies"))
            {
                k -= 2;
            }
            else if (b[k - 1] != 's')
            {
                k -= 1;
            }
        }

        if (EndsWith(b, k, "eed"))
        {
            if (Measure(b, k - 3) > 0)
            {
                k -= 1;
            }
        }
        else if ((EndsWith(b, k, "ed") && VowelInStem(b, k - 2)) ||
                 (EndsWith(b, k, "ing") && VowelInStem(b, k - 3)))
        {
            // strip the "ed"/"ing" suffix, then patch the stem back into a canonical form
            k = EndsWith(b, k, "ed") ? k - 2 : k - 3;
            if (EndsWith(b, k, "at") || EndsWith(b, k, "bl") || EndsWith(b, k, "iz"))
            {
                // "at" -> "ate", "bl" -> "ble", "iz" -> "ize" (append an 'e')
                SetTo(b, ref k, k, "e");
            }
            else if (DoubleConsonant(b, k))
            {
                var ch = b[k];
                if (ch is not ('l' or 's' or 'z'))
                {
                    k -= 1;
                }
            }
            else if (Measure(b, k) == 1 && Cvc(b, k))
            {
                k += 1;
                b[k] = 'e';
            }
        }

        return k;
    }

    private static int Step1C(char[] b, int k)
    {
        if (EndsWith(b, k, "y") && VowelInStem(b, k - 1))
        {
            b[k] = 'i';
        }

        return k;
    }

    private static int Step2(char[] b, int k)
    {
        if (k <= 0)
        {
            return k;
        }

        switch (b[k - 1])
        {
            case 'a':
                k = TryReplace(b, k, "ational", "ate");
                k = TryReplace(b, k, "tional", "tion");
                break;
            case 'c':
                k = TryReplace(b, k, "enci", "ence");
                k = TryReplace(b, k, "anci", "ance");
                break;
            case 'e':
                k = TryReplace(b, k, "izer", "ize");
                break;
            case 'l':
                k = TryReplace(b, k, "bli", "ble");
                k = TryReplace(b, k, "alli", "al");
                k = TryReplace(b, k, "entli", "ent");
                k = TryReplace(b, k, "eli", "e");
                k = TryReplace(b, k, "ousli", "ous");
                break;
            case 'o':
                k = TryReplace(b, k, "ization", "ize");
                k = TryReplace(b, k, "ation", "ate");
                k = TryReplace(b, k, "ator", "ate");
                break;
            case 's':
                k = TryReplace(b, k, "alism", "al");
                k = TryReplace(b, k, "iveness", "ive");
                k = TryReplace(b, k, "fulness", "ful");
                k = TryReplace(b, k, "ousness", "ous");
                break;
            case 't':
                k = TryReplace(b, k, "aliti", "al");
                k = TryReplace(b, k, "iviti", "ive");
                k = TryReplace(b, k, "biliti", "ble");
                break;
            case 'g':
                k = TryReplace(b, k, "logi", "log");
                break;
        }

        return k;
    }

    private static int Step3(char[] b, int k)
    {
        switch (b[k])
        {
            case 'e':
                k = TryReplace(b, k, "icate", "ic");
                k = TryReplace(b, k, "ative", "");
                k = TryReplace(b, k, "alize", "al");
                break;
            case 'i':
                k = TryReplace(b, k, "iciti", "ic");
                break;
            case 'l':
                k = TryReplace(b, k, "ical", "ic");
                k = TryReplace(b, k, "ful", "");
                break;
            case 's':
                k = TryReplace(b, k, "ness", "");
                break;
        }

        return k;
    }

    private static int Step4(char[] b, int k)
    {
        if (k <= 0)
        {
            return k;
        }

        switch (b[k - 1])
        {
            case 'a':
                k = TryRemove(b, k, "al");
                break;
            case 'c':
                k = TryRemove(b, k, "ance");
                k = TryRemove(b, k, "ence");
                break;
            case 'e':
                k = TryRemove(b, k, "er");
                break;
            case 'i':
                k = TryRemove(b, k, "ic");
                break;
            case 'l':
                k = TryRemove(b, k, "able");
                k = TryRemove(b, k, "ible");
                break;
            case 'n':
                k = TryRemove(b, k, "ant");
                k = TryRemove(b, k, "ement");
                k = TryRemove(b, k, "ment");
                k = TryRemove(b, k, "ent");
                break;
            case 'o':
                if (EndsWith(b, k, "ion") && k >= 3 && (b[k - 3] == 's' || b[k - 3] == 't') && Measure(b, k - 3) > 1)
                {
                    k -= 3;
                }

                k = TryRemove(b, k, "ou");
                break;
            case 's':
                k = TryRemove(b, k, "ism");
                break;
            case 't':
                k = TryRemove(b, k, "ate");
                k = TryRemove(b, k, "iti");
                break;
            case 'u':
                k = TryRemove(b, k, "ous");
                break;
            case 'v':
                k = TryRemove(b, k, "ive");
                break;
            case 'z':
                k = TryRemove(b, k, "ize");
                break;
        }

        return k;
    }

    private static int Step5(char[] b, int k)
    {
        if (b[k] == 'e')
        {
            var a = Measure(b, k - 1);
            if (a > 1 || (a == 1 && !Cvc(b, k - 1)))
            {
                k -= 1;
            }
        }

        if (b[k] == 'l' && DoubleConsonant(b, k) && Measure(b, k) > 1)
        {
            k -= 1;
        }

        return k;
    }

    // step 2/3 helper: when the word ends with suffix and the stem has measure > 0, replace it
    private static int TryReplace(char[] b, int k, string suffix, string replacement)
    {
        if (!EndsWith(b, k, suffix))
        {
            return k;
        }

        var stemEnd = k - suffix.Length;
        if (Measure(b, stemEnd) > 0)
        {
            SetTo(b, ref k, stemEnd, replacement);
        }

        return k;
    }

    // step 4 helper: remove the suffix when the stem has measure > 1
    private static int TryRemove(char[] b, int k, string suffix)
    {
        if (!EndsWith(b, k, suffix))
        {
            return k;
        }

        var stemEnd = k - suffix.Length;
        if (Measure(b, stemEnd) > 1)
        {
            k = stemEnd;
        }

        return k;
    }
}
