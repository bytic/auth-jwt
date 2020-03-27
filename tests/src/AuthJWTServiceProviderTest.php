<?php

namespace ByTIC\AuthJWT\Tests;

use ByTIC\AuthJWT\AuthJWTServiceProvider;
use ByTIC\AuthJWT\Services\JWTProvider\LcobucciJWTProvider;
use ByTIC\AuthJWT\Services\KeyLoader\RawKeyLoader;
use Nip\Container\Container;

/**
 * Class AuthJWTServiceProviderTest
 * @package ByTIC\AuthJWT\Tests
 */
class AuthJWTServiceProviderTest extends AbstractTest
{
    public function test_registerKeys()
    {
        $container = Container::getInstance();
        $this->loadConfigIntoContainer('basic');
        $serviceProvider = new AuthJWTServiceProvider();
        $serviceProvider->setContainer($container);
        $serviceProvider->register();

        $loader = $container->get('auth-jwt.jwt.keys.loader');
        self::assertInstanceOf(RawKeyLoader::class, $loader);
    }

    public function test_registerLcobucciProvider()
    {
        $container = Container::getInstance();
        $this->loadConfigIntoContainer('basic');
        $serviceProvider = new AuthJWTServiceProvider();
        $serviceProvider->setContainer($container);
        $serviceProvider->register();

        $loader = $container->get('auth-jwt.jwt.provider.lcobucci');
        self::assertInstanceOf(LcobucciJWTProvider::class, $loader);
    }
}
