<?php

namespace ByTIC\JWTAuth\TokenExtractor;

/**
 * Class AuthorizationHeaderTokenExtractor
 * @package ByTIC\JWTAuth\TokenExtractor
 *
 * @inspiration https://github.com/lexik/LexikJWTAuthenticationBundle/blob/master/TokenExtractor/AuthorizationHeaderTokenExtractor.php
 */
class AuthorizationHeaderTokenExtractor
{
    /**
     * @var string
     */
    protected $prefix;

    /**
     * @var string
     */
    protected $name;

    /**
     * @param string|null $prefix
     * @param string $name
     */
    public function __construct($prefix, $name)
    {
        $this->prefix = $prefix;
        $this->name = $name;
    }

    /**
     * {@inheritdoc}
     */
    public function extract(Request $request)
    {
        if (!$request->headers->has($this->name)) {
            return false;
        }

        $authorizationHeader = $request->headers->get($this->name);

        if (empty($this->prefix)) {
            return $authorizationHeader;
        }

        $headerParts = explode(' ', $authorizationHeader);

        if (!(2 === count($headerParts) && 0 === strcasecmp($headerParts[0], $this->prefix))) {
            return false;
        }

        return $headerParts[1];
    }
}