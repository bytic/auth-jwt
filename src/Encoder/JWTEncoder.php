<?php

namespace ByTIC\AuthJWT\Encoder;

use ByTIC\AuthJWT\Exception\JWTDecodeFailureException;
use ByTIC\AuthJWT\Exception\JWTEncodeFailureException;
use ByTIC\AuthJWT\Services\JWTProvider\JWTProviderInterface;

/**
 * Class JWTEncoder
 * @package ByTIC\AuthJWT\Encoder
 */
class JWTEncoder implements JWTEncoderInterface
{

    /**
     * @var JWTProviderInterface
     */
    protected $jwsProvider;

    /**
     * @param JWTProviderInterface $jwsProvider
     */
    public function __construct(JWTProviderInterface $jwsProvider)
    {
        $this->jwsProvider = $jwsProvider;
    }

    /**
     * {@inheritdoc}
     */
    public function encode(array $payload, array $header = [])
    {
        try {
            $jws = $this->jwsProvider->create($payload, $header);
        } catch (\InvalidArgumentException $e) {
            throw new JWTEncodeFailureException(
                JWTEncodeFailureException::INVALID_CONFIG,
                'An error occurred while trying to encode the JWT token. Please verify your configuration (private key/passphrase)',
                $e
            );
        }

        if (!$jws->isSigned()) {
            throw new JWTEncodeFailureException(
                JWTEncodeFailureException::UNSIGNED_TOKEN,
                'Unable to create a signed JWT from the given configuration.'
            );
        }

        return $jws->getToken();
    }

    /**
     * {@inheritdoc}
     */
    public function decode($token)
    {
        try {
            $jws = $this->jwsProvider->load($token);
        } catch (\Exception $e) {
            throw new JWTDecodeFailureException(JWTDecodeFailureException::INVALID_TOKEN, 'Invalid JWT Token', $e);
        }

        if ($jws->isInvalid()) {
            throw new JWTDecodeFailureException(JWTDecodeFailureException::INVALID_TOKEN, 'Invalid JWT Token');
        }

        if ($jws->isExpired()) {
            throw new JWTDecodeFailureException(JWTDecodeFailureException::EXPIRED_TOKEN, 'Expired JWT Token');
        }

        if (!$jws->isVerified()) {
            throw new JWTDecodeFailureException(
                JWTDecodeFailureException::UNVERIFIED_TOKEN,
                'Unable to verify the given JWT through the given configuration. If the "lexik_jwt_authentication.encoder" encryption options have been changed since your last authentication, please renew the token. If the problem persists, verify that the configured keys/passphrase are valid.'
            );
        }

        return $jws->getPayload();
    }
}
