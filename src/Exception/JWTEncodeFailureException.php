<?php

namespace ByTIC\AuthJWT\Exception;

/**
 * Class JWTEncodeFailureException
 * @package ByTIC\AuthJWT\Exception
 */
class JWTEncodeFailureException extends JWTFailureException
{
    const INVALID_CONFIG = 'invalid_config';

    const UNSIGNED_TOKEN = 'unsigned_token';
}