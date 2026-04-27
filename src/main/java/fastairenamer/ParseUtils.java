package fastairenamer;

public class ParseUtils {

    public static String extractBetween(String original, String left, String right) {
        int leftIdx = original.indexOf(left);
        if (leftIdx == -1) return "";
        int start = leftIdx + left.length();
        int end = original.indexOf(right, start);
        if (end == -1) return "";
        return original.substring(start, end);
    }

    // Strips a markdown code fence language tag (e.g. "csv" from ```csv\n...).
    // If the first line contains no comma it's treated as a language tag and dropped.
    public static String stripCodeFenceLanguageTag(String text) {
        int nl = text.indexOf('\n');
        if (nl > 0 && !text.substring(0, nl).contains(",")) {
            return text.substring(nl + 1);
        }
        return text;
    }
}
