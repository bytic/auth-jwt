<?php

namespace ByTIC\AuthJWT\Security\Authentication\Token;

use Symfony\Component\Security\Guard\Token\PreAuthenticationGuardToken;

/**
 * Class PreAuthenticationJWTUserToken
 * @package ByTIC\AuthJWT\Security\Authentication\Token
 */
final class PreAuthenticationJWTUserToken extends PreAuthenticationGuardToken
{
    /**
     * @var string
     */
    private $rawToken;

    /**
     * @var array
     */
    private $payload;

    /**
     * @inheritDoc
     * @param string $rawToken
     */
    public function __construct($credentials, string $guardProviderKey)
    {
        $this->rawToken = $credentials;
        parent::__construct($credentials, $guardProviderKey);
    }


    /**
     * {@inheritdoc}
     */
    public function setPayload(array $payload)
    {
        $this->payload = $payload;
    }

    /**
     * {@inheritdoc}
     */
    public function getPayload()
    {
        return $this->payload;
    }
}