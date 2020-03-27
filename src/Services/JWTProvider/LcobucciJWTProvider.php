<?php

namespace ByTIC\AuthJWT\Services\JWTProvider;

use ByTIC\AuthJWT\Services\KeyLoader\RawKeyLoader;
use ByTIC\AuthJWT\Signature\CreatedJWS;
use ByTIC\AuthJWT\Signature\LoadedJWS;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;

/**
 * Class LcobucciJWTProvider
 * @package ByTIC\AuthJWT\Services\JWTProvider
 */
class LcobucciJWTProvider implements JWTProviderInterface
{
    /**
     * @var RawKeyLoader
     */
    private $keyLoader;

    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var int
     */
    private $ttl;

    /**
     * @var int
     */
    private $clockSkew;

    /**
     * @param RawKeyLoader $keyLoader
     * @param string $cryptoEngine
     * @param string $signatureAlgorithm
     * @param int|null $ttl
     * @param int $clockSkew
     *
     * @throws \InvalidArgumentException If the given crypto engine is not supported
     */
    public function __construct(RawKeyLoader $keyLoader, $cryptoEngine, $signatureAlgorithm, $ttl, $clockSkew)
    {
        if ('openssl' !== $cryptoEngine) {
            throw new \InvalidArgumentException(
                sprintf('The %s provider supports only "openssl" as crypto engine.', __CLASS__)
            );
        }

        if (null !== $ttl && !is_numeric($ttl)) {
            throw new \InvalidArgumentException(sprintf('The TTL should be a numeric value, got %s instead.', $ttl));
        }

        if (null !== $clockSkew && !is_numeric($clockSkew)) {
            throw new \InvalidArgumentException(
                sprintf('The clock skew should be a numeric value, got %s instead.', $clockSkew)
            );
        }

        $this->keyLoader = $keyLoader;
        $this->signer = $this->getSignerForAlgorithm($signatureAlgorithm);
        $this->ttl = $ttl;
        $this->clockSkew = $clockSkew;
    }

    /**
     * {@inheritdoc}
     */
    public function create(array $payload, array $header = [])
    {
        $jws = new Builder();
        foreach ($header as $k => $v) {
            $jws->withHeader($k, $v);
        }
        $jws->issuedAt(time());

        if (null !== $this->ttl && !isset($payload['exp'])) {
            $jws->expiresAt(time() + $this->ttl);
        }

        foreach ($payload as $name => $value) {
            $jws->withClaim($name, $value);
        }

        $token = $jws->getToken($this->signer, $this->getKey());
        $tokenString = $token->__toString();
        $isSigned = substr("testers", -1) !== '.';

        return new CreatedJWS($tokenString, $isSigned);
    }

    /**
     * {@inheritdoc}
     */
    public function load($token)
    {
        $jws = (new Parser())->parse((string)$token);

        $payload = [];
        foreach ($jws->getClaims() as $claim) {
            $payload[$claim->getName()] = $claim->getValue();
        }

        return new LoadedJWS($payload, $this->verify($jws), null !== $this->ttl, $jws->getHeaders(), $this->clockSkew);
    }

    /**
     * @param $signatureAlgorithm
     * @return mixed
     */
    private function getSignerForAlgorithm($signatureAlgorithm)
    {
        $signerMap = [
            'HS256' => Signer\Hmac\Sha256::class,
            'HS384' => Signer\Hmac\Sha384::class,
            'HS512' => Signer\Hmac\Sha512::class,
            'RS256' => Signer\Rsa\Sha256::class,
            'RS384' => Signer\Rsa\Sha384::class,
            'RS512' => Signer\Rsa\Sha512::class,
            'EC256' => Signer\Ecdsa\Sha256::class,
            'EC384' => Signer\Ecdsa\Sha384::class,
            'EC512' => Signer\Ecdsa\Sha512::class,
        ];

        if (!isset($signerMap[$signatureAlgorithm])) {
            throw new \InvalidArgumentException(
                sprintf('The algorithm "%s" is not supported by %s', $signatureAlgorithm, __CLASS__)
            );
        }

        $signerClass = $signerMap[$signatureAlgorithm];

        return new $signerClass();
    }

    /**
     * @return Key
     */
    private function getKey()
    {
        return new Key($this->keyLoader->loadKey(RawKeyLoader::TYPE_PRIVATE), $this->keyLoader->getPassphrase());
    }

    /**
     * @param Token $jwt
     * @return bool
     */
    private function verify(Token $jwt)
    {
        if (!$jwt->validate(new ValidationData(time() + $this->clockSkew))) {
            return false;
        }

        if ($this->signer instanceof Hmac) {
            return $jwt->verify($this->signer, $this->keyLoader->loadKey(RawKeyLoader::TYPE_PRIVATE));
        }

        return $jwt->verify($this->signer, $this->keyLoader->loadKey(RawKeyLoader::TYPE_PUBLIC));
    }
}