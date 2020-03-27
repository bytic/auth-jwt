<?php

namespace ByTIC\AuthJWT\Encoder;

use ByTIC\AuthJWT\Exception\JWTDecodeFailureException;
use ByTIC\AuthJWT\Exception\JWTEncodeFailureException;

/**
 * Interface JWTEncoderInterface
 * @package ByTIC\AuthJWT\Encoder
 */
interface JWTEncoderInterface
{
    /**
     * @param array $data
     *
     * @return string the encoded token string
     *
     * @throws JWTEncodeFailureException If an error occurred while trying to create
     *                                   the token (invalid crypto key, invalid payload...)
     */
    public function encode(array $data);

    /**
     * @param string $token
     *
     * @return array
     *
     * @throws JWTDecodeFailureException If an error occurred while trying to load the token
     *                                   (invalid signature, invalid crypto key, expired token...)
     */
    public function decode($token);
}
