<?php

namespace ByTIC\AuthJWT\Services\JWTProvider;

/**
 * Interface JWTProviderInterface
 * @package ByTIC\AuthJWT\Services\JWTProvider
 */
interface JWTProviderInterface
{
    /**
     * Creates a new JWS signature from a given payload.
     *
     * @param array $payload
     * @param array $header
     *
     * @return \ByTIC\AuthJWT\Signature\CreatedJWS
     */
    public function create(array $payload, array $header = []);

    /**
     * Loads an existing JWS signature from a given JWT token.
     *
     * @param string $token
     *
     * @return \ByTIC\AuthJWT\Signature\LoadedJWS
     */
    public function load($token);
}