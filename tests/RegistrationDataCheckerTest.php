<?php

use PHPUnit\Framework\TestCase;
use JarirAhmed\RegistrationDataChecker\RegistrationDataChecker;

class RegistrationDataCheckerTest extends TestCase
{
    private $checker;

    protected function setUp(): void
    {
        $this->checker = new RegistrationDataChecker();
    }

    public function testIsValidEmail()
    {
        // Valid email
        $this->assertTrue($this->checker->isValidEmail("test@example.com"));

        // Invalid email
        $this->assertFalse($this->checker->isValidEmail("invalid-email"));
    }

    public function testIsValidPassword()
    {
        // Valid password (minimum 8 characters)
        $this->assertTrue($this->checker->isValidPassword("password123"));

        // Invalid password (less than 8 characters)
        $this->assertFalse($this->checker->isValidPassword("short"));
    }

    public function testIsValidPhoneNumber()
    {
        // Valid phone number with country code
        $this->assertTrue($this->checker->isValidPhoneNumber("+1234567890123"));

        // Invalid phone number (missing country code)
        $this->assertFalse($this->checker->isValidPhoneNumber("1234567890"));
    }

    public function testIsAgeValid()
    {
        // Valid age (18 or older)
        $this->assertTrue($this->checker->isAgeValid("2000-01-01"));

        // Invalid age (younger than 18)
        $this->assertFalse($this->checker->isAgeValid("2010-01-01"));
    }

    public function testIsValidImage()
    {
        // Valid image file (simulated path and size)
        // Assuming the file exists at this path and has the correct extension and size
        $this->assertTrue($this->checker->isValidImage("/path/to/image.jpg", 1024 * 1024)); // 1MB file

        // Invalid image file (wrong extension)
        $this->assertFalse($this->checker->isValidImage("/path/to/file.txt"));
    }

    public function testIsValidCountry()
    {
        // Simulate valid country (Assume API returns a valid response for testing)
        $this->assertTrue($this->checker->isValidCountry("Bangladesh"));

        // Simulate invalid country (Country not found)
        $this->assertFalse($this->checker->isValidCountry("InvalidCountry"));
    }

    public function testIsValidLanguage()
    {
        // Simulate valid language (Assume API returns a valid response for testing)
        $this->assertTrue($this->checker->isValidLanguage("English"));

        // Simulate invalid language (Language not found)
        $this->assertFalse($this->checker->isValidLanguage("InvalidLanguage"));
    }

    public function testIsValidDocument()
    {
        // Valid document file (simulated path and size)
        $this->assertTrue($this->checker->isValidDocument("/path/to/file.pdf", 1024 * 1024)); // 1MB file

        // Invalid document file (wrong extension)
        $this->assertFalse($this->checker->isValidDocument("/path/to/file.txt"));
    }
}
