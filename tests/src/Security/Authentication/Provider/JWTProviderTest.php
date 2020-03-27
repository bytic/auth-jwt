<?php

namespace ByTIC\AuthJWT\Tests\Security\Authentication\Provider;

use ByTIC\AuthJWT\Security\Authentication\Provider\JWTProvider;
use ByTIC\AuthJWT\Tests\AbstractTest;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * Class JWTProviderTest
 * @package ByTIC\AuthJWT\Tests\Security\Authentication\Provider
 */
class JWTProviderTest extends AbstractTest
{
    /**
     * test supports method.
     */
    public function test_supports()
    {
        $provider = new JWTProvider();

        /** @var TokenInterface $usernamePasswordToken */
        $usernamePasswordToken = $this
            ->getMockBuilder(\Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken::class)
            ->disableOriginalConstructor()
            ->getMock();

        static::assertFalse($provider->supports($usernamePasswordToken));


        /** @var TokenInterface $jwtUserToken */
        $jwtUserToken = $this
            ->getMockBuilder(\ByTIC\AuthJWT\Security\Authentication\Token\JWTUserToken::class)
            ->disableOriginalConstructor()
            ->getMock();

        static::assertTrue($provider->supports($jwtUserToken));
    }
}
