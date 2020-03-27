<?php

namespace ByTIC\AuthJWT\Tests\Services\JWTProvider;

use ByTIC\AuthJWT\Services\JWTProvider\LcobucciJWTProvider;
use ByTIC\AuthJWT\Services\KeyLoader\RawKeyLoader;

/**
 * Class LcobucciJWTProviderTest
 * @package ByTIC\AuthJWT\Services\JWTProvider
 */
class LcobucciJWTProviderTest extends AbstractJWSProviderTest
{
    public function __construct()
    {
        parent::__construct();

        self::$providerClass = LcobucciJWTProvider::class;
        self::$keyLoaderClass = RawKeyLoader::class;
    }
}