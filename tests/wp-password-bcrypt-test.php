<?php

namespace Roots\PasswordArgon2I\Tests;

use Brain\Monkey;
use Brain\Monkey\Functions;
use Brain\Monkey\WP\Filters;
use Mockery as M;
use PHPUnit_Framework_TestCase;

/** {inheritdoc} */
class WpPasswordArgon2ITest extends PHPUnit_Framework_TestCase
{
    const PASSWORD = 'password';
    const HASH_ARGON2I = '$2y$10$KIMXDMJq9camkaNHkdrmcOaYJ0AT9lvovEf92yWA34sKdfnn97F9i';
    const HASH_PHPASS = '$P$BDMJH/qCLaUc5Lj8Oiwp7XmWzrCcJ21';

    /** {inheritdoc} */
    protected function setUp()
    {
        parent::setUp();
        Monkey::setUpWP();

        global $wpdb;

        $wpdb = M::mock('wpdb');
        $wpdb
            ->shouldReceive('update')
            ->withAnyArgs()
            ->andReturnNull();
        $wpdb->users = 'wp_users';
    }

    /** {inheritdoc} */
    protected function tearDown()
    {
        Monkey::tearDownWP();
        parent::tearDown();
    }

    /** @test */
    public function a_password_is_hashed_using_argon2i()
    {
        $userId = 1;

        Functions::expect('wp_cache_delete')->once()->andReturn(true);

        $argon2i_hash = wp_set_password(self::PASSWORD, $userId);
        $this->assertTrue(password_verify(self::PASSWORD, $argon2i_hash));
    }

    /** @test */
    public function hashing_password_applies_filter()
    {
        wp_hash_password(self::PASSWORD);

        Filters::expectApplied('wp_hash_password_options')->andReturn(self::HASH_ARGON2I);
    }

    /** @test */
    public function argon2i_passwords_should_be_verified()
    {
        $bad_hash = 'randomhash';

        $argon2i_check = wp_check_password(self::PASSWORD, self::HASH_ARGON2I);
        $bad_check = wp_check_password(self::PASSWORD, $bad_hash);

        $this->assertTrue($argon2i_check);
        $this->assertFalse($bad_check);
    }

    /** @test */
    public function phpass_passwords_should_be_verified_and_converted_to_argon2i()
    {
        global $wp_hasher;

        /** @var int $userId This is necessary to trigger wp_set_password() */
        $userId = 1;

        $wp_hasher = M::mock('PasswordHash');
        $wp_hasher
            ->shouldReceive('CheckPassword')
            ->once()
            ->with(self::PASSWORD, self::HASH_PHPASS)
            ->andReturn(true);

        Functions::expect('wp_cache_delete')->once()->andReturn(true);

        $phpass_check = wp_check_password(self::PASSWORD, self::HASH_PHPASS, $userId);
        $this->assertTrue($phpass_check);
    }
}
