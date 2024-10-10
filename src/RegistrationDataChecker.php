<?php

namespace JarirAhmed\RegistrationDataChecker;

class RegistrationDataChecker
{
    /**
     * Check if the email address is valid.
     */
    public function isValidEmail(string $email): bool
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * Check if the password is at least 8 characters long.
     */
    public function isValidPassword(string $password): bool
    {
        return strlen($password) >= 8;
    }

    /**
     * Check if the phone number is valid and includes the country code.
     */
    public function isValidPhoneNumber(string $phoneNumber): bool
    {
        // Regex for validating phone number (example for international format)
        return preg_match('/^\+\d{1,3}\s?\d{4,14}$/', $phoneNumber);
    }

    /**
     * Check if the user is 18 or older based on the provided date of birth.
     */
    public function isAgeValid(string $dateOfBirth): bool
    {
        $dob = new \DateTime($dateOfBirth);
        $today = new \DateTime();
        $age = $today->diff($dob)->y;
        return $age >= 18;
    }

    /**
     * Check if the uploaded image has a valid extension and size limit.
     */
    public function isValidImage(string $filePath, int $maxSize = 2 * 1024 * 1024): bool
    {
        $validExtensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff', 'svg', 'ico', 'heif', 'heic'];
        $fileExtension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        $fileSize = filesize($filePath);

        return in_array($fileExtension, $validExtensions) && $fileSize <= $maxSize;
    }

    /**
     * Check if the input country is valid using an API.
     */
    public function isValidCountry(string $country): bool
    {
        $countriesData = @file_get_contents('https://restcountries.com/v3.1/all');
        
        if ($countriesData === false) {
            return false; // Handle the error appropriately in production
        }

        $countries = json_decode($countriesData, true);
        $countryNames = array_column($countries, 'name');

        return in_array($country, $countryNames);
    }

    /**
     * Check if the input language is valid using an API.
     */
    public function isValidLanguage(string $language): bool
    {
        $countriesData = @file_get_contents('https://restcountries.com/v3.1/all');
        
        if ($countriesData === false) {
            return false; // Handle the error appropriately in production
        }

        $languages = [];
        foreach (json_decode($countriesData, true) as $country) {
            $languages = array_merge($languages, $country['languages'] ?? []);
        }

        return in_array($language, $languages);
    }

    /**
     * Check if the uploaded document has a valid extension and size limit.
     */
    public function isValidDocument(string $filePath, int $maxSize = 5 * 1024 * 1024): bool
    {
        $validExtensions = [
            'pdf',    // Portable Document Format
            'rtf',    // Rich Text Format
            'doc',    // Microsoft Word 97-2003 Document
            'docx',   // Microsoft Word 2007+ Document
            'txt',    // Plain Text File
            'odt',    // OpenDocument Text Document
            'wps',    // Microsoft Works Document
            'dot',    // Microsoft Word Template
            'dotx',   // Microsoft Word Template 2007+
            'xml',    // XML Document
            'xls',    // Microsoft Excel 97-2003 Spreadsheet
            'xlsx',   // Microsoft Excel 2007+ Spreadsheet
            'ppt',    // Microsoft PowerPoint 97-2003 Presentation
            'pptx',   // Microsoft PowerPoint 2007+ Presentation
            'csv',    // Comma-Separated Values
            'epub',   // Electronic Publication
            'md',     // Markdown Document
            'pages',   // Apple Pages Document
        ];        
        $fileExtension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        $fileSize = filesize($filePath);

        return in_array($fileExtension, $validExtensions) && $fileSize <= $maxSize;
    }

    /**
     * Check if the uploaded file has a valid custom extension.
     *
     * @param string $filePath The path of the file to check.
     * @param array $allowedExtensions An array of valid extensions.
     * @return bool True if the file has a valid extension; otherwise, false.
     */

    public function isValidCustomExtension(string $filePath, array $allowedExtensions): bool
    {
        $fileExtension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        return in_array($fileExtension, $allowedExtensions);
    }

    /**
     * Check if the uploaded image has minimum width and height.
     *
     * @param string $filePath The path of the image to check.
     * @param int $minWidth The minimum width in pixels.
     * @param int $minHeight The minimum height in pixels.
     * @return bool True if the image meets the minimum dimensions; otherwise, false.
     */
    public function hasMinimumDimensions(string $filePath, int $minWidth, int $minHeight): bool
    {
        list($width, $height) = getimagesize($filePath);
        
        return $width >= $minWidth && $height >= $minHeight;
    }

    /**
     * Check if the uploaded image exceeds the maximum width and height.
     *
     * @param string $filePath The path of the image to check.
     * @param int $maxWidth The maximum width in pixels.
     * @param int $maxHeight The maximum height in pixels.
     * @return bool True if the image is within the maximum dimensions; otherwise, false.
     */
    public function exceedsMaximumDimensions(string $filePath, int $maxWidth, int $maxHeight): bool
    {
        list($width, $height) = getimagesize($filePath);
        
        return $width > $maxWidth || $height > $maxHeight;
    }

    /**
     * Check if the uploaded file meets the minimum size requirement.
     *
     * @param string $filePath The path of the file to check.
     * @param int $minSize The minimum size in bytes.
     * @return bool True if the file size is greater than or equal to the minimum size; otherwise, false.
     */
    public function meetsMinimumSize(string $filePath, int $minSize): bool
    {
        $fileSize = filesize($filePath);
        
        return $fileSize >= $minSize;
    }

        /**
     * Check if the uploaded file exceeds the maximum size requirement.
     *
     * @param string $filePath The path of the file to check.
     * @param int $maxSize The maximum size in bytes.
     * @return bool True if the file size is less than or equal to the maximum size; otherwise, false.
     */
    public function exceedsMaximumSize(string $filePath, int $maxSize): bool
    {
        $fileSize = filesize($filePath);
        
        return $fileSize > $maxSize;
    }

    /**
     * Check if the uploaded PHP file contains known malware patterns.
     *
     * @param string $filePath The path of the PHP file to check.
     * @return bool True if malware patterns are found; otherwise, false.
     */
    public function containsMalware(string $filePath): bool
    {
        // Read the content of the PHP file
        $fileContent = file_get_contents($filePath);
        
        // Define a list of common malware patterns
        $malwarePatterns = [
            '/eval\(/i',                // eval function (often used in obfuscation)
            '/base64_decode\(/i',       // base64_decode function
            '/exec\(/i',                // exec function (execution of commands)
            '/shell_exec\(/i',          // shell_exec function
            '/system\(/i',              // system function
            '/passthru\(/i',            // passthru function
            '/preg_replace\(/i',        // preg_replace with e (eval in replacement)
            '/phpinfo\(/i',             // phpinfo (used for revealing system info)
            '/fopen\(/i',               // fopen function (could be used for file manipulation)
            '/<\?php\s*?>/i',           // Short opening tags
            '/\s*<\?php\s*.*?die\(/i',  // use of die function
        ];

        // Check for each malware pattern
        foreach ($malwarePatterns as $pattern) {
            if (preg_match($pattern, $fileContent)) {
                return true; // Malware pattern found
            }
        }

        return false; // No malware patterns found
    }

}
