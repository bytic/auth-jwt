<?php

namespace ByTIC\AuthJWT\Security\Authentication\Provider;

use ByTIC\AuthJWT\Security\Authentication\Token\JWTUserToken;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * Class JWTProvider
 * @package ByTIC\AuthJWT\Security\Authentication\Provider
 */
class JWTProvider implements AuthenticationProviderInterface
{

    /**
     * @inheritDoc
     */
    public function authenticate(TokenInterface $token)
    {
        // TODO: Implement authenticate() method.
    }

    /**
     * @inheritDoc
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof JWTUserToken;
    }
}