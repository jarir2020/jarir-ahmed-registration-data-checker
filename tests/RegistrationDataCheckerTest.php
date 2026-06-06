<?php

namespace JarirAhmed\RegistrationDataChecker\Tests;

use JarirAhmed\RegistrationDataChecker\RegistrationDataChecker as R;
use PHPUnit\Framework\TestCase;

class RegistrationDataCheckerTest extends TestCase
{
    private string $dir;

    // 1x1 PNG
    private const PNG_B64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'rdc_' . uniqid('', true);
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $f) {
            @unlink($f);
        }
        @rmdir($this->dir);
    }

    private function write(string $name, string $content): string
    {
        $p = $this->dir . DIRECTORY_SEPARATOR . $name;
        file_put_contents($p, $content);
        return $p;
    }

    // --- basic validators ---------------------------------------------------

    public function testEmail()
    {
        $this->assertTrue(R::isValidEmail('test@example.com'));
        $this->assertFalse(R::isValidEmail('invalid-email'));
    }

    public function testPassword()
    {
        $this->assertTrue(R::isValidPassword('password123'));
        $this->assertFalse(R::isValidPassword('short'));
    }

    public function testPhone()
    {
        $this->assertTrue(R::isValidPhoneNumber('+1234567890123'));
        $this->assertFalse(R::isValidPhoneNumber('1234567890'));
    }

    // --- age ----------------------------------------------------------------

    public function testAge()
    {
        $this->assertTrue(R::isAgeValid('2000-01-01'));
        $this->assertFalse(R::isAgeValid((new \DateTime('-5 years'))->format('Y-m-d')));
    }

    public function testFutureBirthDateIsInvalid()
    {
        $this->assertFalse(R::isAgeValid('2999-01-01'));
    }

    public function testGarbageDateIsInvalid()
    {
        $this->assertFalse(R::isAgeValid('not-a-date'));
    }

    // --- upload content validation (the security fix) -----------------------

    public function testValidPngAccepted()
    {
        $png = $this->write('pic.png', base64_decode(self::PNG_B64));
        $this->assertTrue(R::isValidImage($png));
    }

    public function testScriptRenamedToJpgRejected()
    {
        $evil = $this->write('evil.jpg', "<?php system(\$_GET['c']); ?>");
        $this->assertFalse(R::isValidImage($evil)); // extension lies; content isn't an image
    }

    public function testMissingImageRejected()
    {
        $this->assertFalse(R::isValidImage($this->dir . '/nope.jpg'));
    }

    public function testSvgAccepted()
    {
        $svg = $this->write('vector.svg', '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"></svg>');
        $this->assertTrue(R::isValidImage($svg));
    }

    public function testValidTextDocumentAccepted()
    {
        $doc = $this->write('notes.txt', 'just some text');
        $this->assertTrue(R::isValidDocument($doc));
    }

    public function testScriptRenamedToPdfRejected()
    {
        $evil = $this->write('evil.pdf', "<?php eval(\$_POST['x']); ?>");
        $this->assertFalse(R::isValidDocument($evil));
    }

    public function testOversizeRejected()
    {
        $doc = $this->write('big.txt', str_repeat('x', 100));
        $this->assertFalse(R::isValidDocument($doc, 10)); // max 10 bytes
    }

    public function testCustomExtension()
    {
        $this->assertTrue(R::isValidCustomExtension('a.LOG', ['log', 'txt']));
        $this->assertFalse(R::isValidCustomExtension('a.exe', ['log', 'txt']));
    }

    // --- malware heuristic --------------------------------------------------

    public function testMalwareHeuristicFlagsEval()
    {
        $f = $this->write('x.php', "<?php eval(base64_decode('ZWNobyAx')); ?>");
        $this->assertTrue(R::containsMalware($f));
    }

    public function testMalwareHeuristicDoesNotFlagFopen()
    {
        $f = $this->write('ok.php', "<?php \$h = fopen('a.txt', 'r'); fclose(\$h);");
        $this->assertFalse(R::containsMalware($f)); // fopen is no longer a trigger
    }

    // --- country / language (offline, injected lists) -----------------------

    public function testCountryWithInjectedListIsCaseInsensitive()
    {
        $list = ['Bangladesh', 'India', 'Japan'];
        $this->assertTrue(R::isValidCountry('bangladesh', $list));
        $this->assertFalse(R::isValidCountry('Atlantis', $list));
    }

    public function testLanguageWithInjectedList()
    {
        $list = ['English', 'Bengali'];
        $this->assertTrue(R::isValidLanguage('english', $list));
        $this->assertFalse(R::isValidLanguage('Klingon', $list));
    }
}
