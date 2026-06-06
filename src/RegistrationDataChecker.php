<?php

namespace JarirAhmed\RegistrationDataChecker;

class RegistrationDataChecker
{
    /** @var array<string,bool>|null cached lowercase country names */
    private static $countryCache = null;
    /** @var array<string,bool>|null cached lowercase language names */
    private static $languageCache = null;

    private const IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff', 'svg', 'ico', 'heif', 'heic'];
    private const DOCUMENT_EXTENSIONS = [
        'pdf', 'rtf', 'doc', 'docx', 'txt', 'odt', 'wps', 'dot', 'dotx', 'xml',
        'xls', 'xlsx', 'ppt', 'pptx', 'csv', 'epub', 'md', 'pages',
    ];
    /** MIME types that must never be accepted as an "upload", whatever the extension claims. */
    private const DANGEROUS_MIMES = [
        'text/x-php', 'application/x-php', 'application/x-httpd-php',
        'text/x-python', 'text/x-perl', 'text/x-shellscript', 'application/x-sh',
        'application/x-dosexec', 'application/x-executable', 'application/x-mach-binary',
        'application/x-msdownload', 'application/java-archive', 'application/x-bytecode.python',
    ];

    public static function isValidEmail(string $email): bool
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    public static function isValidPassword(string $password): bool
    {
        return strlen($password) >= 8;
    }

    public static function isValidPhoneNumber(string $phoneNumber): bool
    {
        return preg_match('/^\+\d{1,3}\s?\d{4,14}$/', $phoneNumber) === 1;
    }

    /**
     * True when the date of birth is in the past and the age is at least 18.
     * Invalid or future dates return false.
     */
    public static function isAgeValid(string $dateOfBirth): bool
    {
        try {
            $dob = new \DateTime($dateOfBirth);
        } catch (\Exception $e) {
            return false;
        }
        $today = new \DateTime('today');
        if ($dob > $today) {
            return false; // a future "birth" date is never valid
        }
        return $today->diff($dob)->y >= 18;
    }

    // --- file uploads -------------------------------------------------------

    /**
     * Validate an uploaded image by extension, size AND real content — a file renamed
     * to .jpg that is actually a script is rejected.
     */
    public static function isValidImage(string $filePath, int $maxSize = 2 * 1024 * 1024): bool
    {
        if (!self::isUploadCandidate($filePath, self::IMAGE_EXTENSIONS, $maxSize)) {
            return false;
        }
        $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        if ($ext === 'svg') {
            // getimagesize() can't read SVG; verify it actually looks like SVG markup.
            $head = (string) file_get_contents($filePath, false, null, 0, 1024);
            return stripos($head, '<svg') !== false;
        }
        $info = @getimagesize($filePath);
        return $info !== false; // genuine raster image
    }

    /**
     * Validate an uploaded document by extension, size and a MIME denylist
     * (so executables/scripts disguised with a document extension are rejected).
     */
    public static function isValidDocument(string $filePath, int $maxSize = 5 * 1024 * 1024): bool
    {
        if (!self::isUploadCandidate($filePath, self::DOCUMENT_EXTENSIONS, $maxSize)) {
            return false;
        }
        $mime = self::mimeOf($filePath);
        if ($mime !== null && in_array($mime, self::DANGEROUS_MIMES, true)) {
            return false;
        }
        // Fail closed when MIME is unknown (e.g. no fileinfo ext): a script disguised
        // with a document extension must still be rejected.
        return !self::looksLikeScript($filePath);
    }

    public static function isValidCustomExtension(string $filePath, array $allowedExtensions): bool
    {
        $allowed = array_map('strtolower', $allowedExtensions);
        $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        return in_array($ext, $allowed, true);
    }

    public static function hasMinimumDimensions(string $filePath, int $minWidth, int $minHeight): bool
    {
        $info = @getimagesize($filePath);
        if ($info === false) {
            return false;
        }
        return $info[0] >= $minWidth && $info[1] >= $minHeight;
    }

    public static function exceedsMaximumDimensions(string $filePath, int $maxWidth, int $maxHeight): bool
    {
        $info = @getimagesize($filePath);
        if ($info === false) {
            return false;
        }
        return $info[0] > $maxWidth || $info[1] > $maxHeight;
    }

    public static function meetsMinimumSize(string $filePath, int $minSize): bool
    {
        return is_file($filePath) && filesize($filePath) >= $minSize;
    }

    public static function exceedsMaximumSize(string $filePath, int $maxSize): bool
    {
        return is_file($filePath) && filesize($filePath) > $maxSize;
    }

    /**
     * Heuristic scan for suspicious PHP constructs. NOTE: this is a best-effort hint,
     * NOT antivirus — it both misses real threats and can flag legitimate code.
     */
    public static function containsMalware(string $filePath): bool
    {
        if (!is_file($filePath)) {
            return false;
        }
        $content = (string) file_get_contents($filePath);
        $patterns = [
            '/\beval\s*\(/i',
            '/\bassert\s*\(/i',
            '/\bbase64_decode\s*\(/i',
            '/\bgzinflate\s*\(/i',
            '/\bexec\s*\(/i',
            '/\bshell_exec\s*\(/i',
            '/\bsystem\s*\(/i',
            '/\bpassthru\s*\(/i',
            '/\bproc_open\s*\(/i',
            '/\bpopen\s*\(/i',
            '/preg_replace\s*\(\s*([\'"]).*\1\s*\/e/i', // /e modifier (code execution)
        ];
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return true;
            }
        }
        return false;
    }

    // --- country / language -------------------------------------------------

    /**
     * @param string     $country
     * @param array|null $validCountries Optional offline list. When null, the REST Countries
     *                                   API is queried (cached per process; false on failure).
     */
    public static function isValidCountry(string $country, ?array $validCountries = null): bool
    {
        $haystack = $validCountries !== null
            ? array_map('strtolower', $validCountries)
            : array_keys(self::fetchCountryData()['countries']);
        return in_array(strtolower(trim($country)), $haystack, true);
    }

    /**
     * @param string     $language
     * @param array|null $validLanguages Optional offline list. When null, the REST Countries
     *                                   API is queried (cached per process; false on failure).
     */
    public static function isValidLanguage(string $language, ?array $validLanguages = null): bool
    {
        $haystack = $validLanguages !== null
            ? array_map('strtolower', $validLanguages)
            : array_keys(self::fetchCountryData()['languages']);
        return in_array(strtolower(trim($language)), $haystack, true);
    }

    // --- internals ----------------------------------------------------------

    private static function isUploadCandidate(string $filePath, array $allowedExtensions, int $maxSize): bool
    {
        if (!is_file($filePath)) {
            return false;
        }
        $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        if (!in_array($ext, $allowedExtensions, true)) {
            return false;
        }
        $size = filesize($filePath);
        return $size !== false && $size <= $maxSize;
    }

    private static function mimeOf(string $filePath): ?string
    {
        if (function_exists('finfo_open')) {
            $finfo = @finfo_open(FILEINFO_MIME_TYPE);
            if ($finfo !== false) {
                $mime = @finfo_file($finfo, $filePath);
                finfo_close($finfo);
                if (is_string($mime) && $mime !== '') {
                    return $mime;
                }
            }
        }
        if (function_exists('mime_content_type')) {
            $mime = @mime_content_type($filePath);
            return $mime === false ? null : $mime;
        }
        return null;
    }

    /** Cheap signature sniff for embedded scripts (PHP tags / shebang). */
    private static function looksLikeScript(string $filePath): bool
    {
        $head = @file_get_contents($filePath, false, null, 0, 256);
        if ($head === false || $head === '') {
            return false;
        }
        return (bool) preg_match('/<\?php|<\?=|<\?\s|^#!/', $head);
    }

    /**
     * @return array{countries: array<string,bool>, languages: array<string,bool>}
     */
    private static function fetchCountryData(): array
    {
        if (self::$countryCache !== null && self::$languageCache !== null) {
            return ['countries' => self::$countryCache, 'languages' => self::$languageCache];
        }

        self::$countryCache = [];
        self::$languageCache = [];

        $context = stream_context_create(['http' => ['timeout' => 5]]);
        $json = @file_get_contents('https://restcountries.com/v3.1/all?fields=name,languages', false, $context);
        if ($json === false) {
            return ['countries' => [], 'languages' => []];
        }
        $data = json_decode($json, true);
        if (!is_array($data)) {
            return ['countries' => [], 'languages' => []];
        }

        foreach ($data as $country) {
            // name is an object: { common, official, nativeName }
            $common = $country['name']['common'] ?? null;
            if (is_string($common)) {
                self::$countryCache[strtolower($common)] = true;
            }
            foreach (($country['languages'] ?? []) as $language) {
                if (is_string($language)) {
                    self::$languageCache[strtolower($language)] = true;
                }
            }
        }

        return ['countries' => self::$countryCache, 'languages' => self::$languageCache];
    }
}
