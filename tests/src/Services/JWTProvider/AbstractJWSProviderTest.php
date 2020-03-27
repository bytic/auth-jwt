<?php

namespace ByTIC\AuthJWT\Tests\Services\JWTProvider;

use ByTIC\AuthJWT\Services\JWTProvider\JWTProviderInterface;
use ByTIC\AuthJWT\Signature\CreatedJWS;
use ByTIC\AuthJWT\Signature\LoadedJWS;
use ByTIC\AuthJWT\Tests\AbstractTest;
use ByTIC\AuthJWT\Tests\Fixtures\Keys\RS384;
use InvalidArgumentException;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * Class AbstractJWSProviderTest
 * @package ByTIC\AuthJWT\Tests\Services\JWTProvider
 */
abstract class AbstractJWSProviderTest extends AbstractTest
{
    protected static $privateKey;

    protected static $publicKey;

    protected static $providerClass;

    protected static $keyLoaderClass;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        static::$privateKey = RS384::$privateKey;
        static::$publicKey = RS384::$publicKey;
    }

    /**
     * Tests to create a signed JWT Token.
     */
    public function testCreate()
    {
        $keyLoaderMock = $this->getKeyLoaderMock();
        $keyLoaderMock
            ->expects(static::once())
            ->method('loadKey')
            ->with('private')
            ->willReturn(static::$privateKey);
        $keyLoaderMock
            ->expects(static::once())
            ->method('getPassphrase')
            ->willReturn('foobar');

        $payload = ['username' => 'chalasr'];
        /** @var JWTProviderInterface $jwsProvider */
        $jwsProvider = new static::$providerClass($keyLoaderMock, 'openssl', 'RS384', 3600, 0);

        static::assertInstanceOf(CreatedJWS::class, $created = $jwsProvider->create($payload));

        return $created->getToken();
    }

    /**
     * Tests to verify the signature of a valid given JWT Token.
     *
     * @depends testCreate
     * @param $jwt
     */
    public function testLoad($jwt)
    {
        $keyLoaderMock = $this->getKeyLoaderMock();
        $keyLoaderMock
            ->expects(static::once())
            ->method('loadKey')
            ->with('public')
            ->willReturn(static::$publicKey);

        /** @var JWTProviderInterface $jwsProvider */
        $jwsProvider = new static::$providerClass($keyLoaderMock, 'openssl', 'RS384', 3600, 0);
        $loadedJWS = $jwsProvider->load($jwt);
        static::assertInstanceOf(LoadedJWS::class, $loadedJWS);

        $payload = $loadedJWS->getPayload();
        static::assertTrue(isset($payload['exp']));
        static::assertTrue(isset($payload['iat']));
        static::assertTrue(isset($payload['username']));
    }

    public function testAllowEmptyTtl()
    {
        $keyLoader = $this->getKeyLoaderMock();
        $keyLoader
            ->expects(static::at(0))
            ->method('loadKey')
            ->with('private')
            ->willReturn(static::$privateKey);
        $keyLoader
            ->expects(static::at(1))
            ->method('getPassphrase')
            ->willReturn('foobar');

        $keyLoader
            ->expects(static::at(2))
            ->method('loadKey')
            ->with('public')
            ->willReturn(static::$publicKey);

        /** @var JWTProviderInterface $provider */
        $provider = new static::$providerClass($keyLoader, 'openssl', 'RS256', null, 0);
        $jws = $provider->create(['username' => 'chalasr']);

        static::assertInstanceOf(CreatedJWS::class, $jws);
        static::assertTrue($jws->isSigned());

        $jws = $provider->load($jws->getToken());

        static::assertInstanceOf(LoadedJWS::class, $jws);
        static::assertFalse($jws->isInvalid());
        static::assertFalse($jws->isExpired());
        static::assertTrue($jws->isVerified());
        static::assertArrayNotHasKey('exp', $jws->getPayload());
    }

    public function test_InvalidSignatureAlgorithm()
    {
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('The algorithm "wrongAlgorithm" is not supported');

        new static::$providerClass($this->getKeyLoaderMock(), 'openssl', 'wrongAlgorithm', 3600, 0);
    }

    public function test_InvalidTtl()
    {
        static::expectException(InvalidArgumentException::class);
        static::expectExceptionMessage('The TTL should be a numeric value');

        new static::$providerClass($this->getKeyLoaderMock(), 'openssl', 'wrongAlgorithm', 'invalid_ttl', 0);
    }

    /**
     * @return MockObject
     */
    protected function getKeyLoaderMock()
    {
        return $this
            ->getMockBuilder(static::$keyLoaderClass)
            ->disableOriginalConstructor()
            ->getMock();
    }
}