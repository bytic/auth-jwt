<?php

namespace ByTIC\AuthJWT;

use ByTIC\AuthJWT\Encoder\JWTEncoderInterface;

/**
 * Class JWTManager
 * @package ByTIC\AuthJWT
 */
class JWTManager
{

    /**
     * @var JWTEncoderInterface
     */
    protected $jwtEncoder;

    /**
     * JWTManager constructor.
     * @param JWTEncoderInterface $encoder
     */
    public function __construct(JWTEncoderInterface $encoder)
    {
        $this->jwtEncoder        = $encoder;
    }
}