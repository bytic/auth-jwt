<?php

namespace ByTIC\AuthJWT\Services\KeyLoader;

/**
 * Class AbstractKeyLoader
 * @package ByTIC\AuthJWT\Services\KeyLoader
 */
abstract class AbstractKeyLoader implements KeyLoaderInterface
{
    /**
     * @var string
     */
    protected $privateKey;

    /**
     * @var string|null
     */
    protected $publicKey;

    /**
     * @var string|null
     */
    protected $passphrase;

    /**
     * @param string|null $privateKey
     * @param string|null $publicKey
     * @param string|null $passphrase
     */
    public function __construct($privateKey = null, $publicKey = null, $passphrase = null)
    {
        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
        $this->passphrase = $passphrase;
    }

    /**
     * {@inheritdoc}
     */
    public function getPassphrase()
    {
        return $this->passphrase;
    }

    /**
     * @return false|string|null
     */
    protected function getPrivateKey()
    {
        return is_file($this->privateKey) ? $this->readKey(self::TYPE_PRIVATE) : $this->privateKey;
    }

    /**
     * @return false|string|null
     */
    protected function getPublicKey()
    {
        return is_file($this->publicKey) ? $this->readKey(self::TYPE_PUBLIC) : $this->publicKey;
    }

    /**
     * @param string $type One of "public" or "private"
     *
     * @return string The path of the key, an empty string if not a valid path
     *
     * @throws \InvalidArgumentException If the given type is not valid
     * @throws \InvalidArgumentException If the given type is not valid
     */
    protected function getKeyPath($type)
    {
        if (!in_array($type, [self::TYPE_PUBLIC, self::TYPE_PRIVATE])) {
            throw new \InvalidArgumentException(
                sprintf('The key type must be "public" or "private", "%s" given.', $type)
            );
        }

        $path = self::TYPE_PUBLIC === $type ? $this->publicKey : $this->privateKey;

        if (!is_file($path) || !is_readable($path)) {
            throw new \RuntimeException(
                sprintf('%s key is not a file or is not readable.', ucfirst($type))
            );
        }

        return $path;
    }

    /**
     * @param $type
     * @return false|string|null
     */
    protected function readKey($type)
    {
        $isPublic = self::TYPE_PUBLIC === $type;
        $key = $isPublic ? $this->publicKey : $this->privateKey;

        if (!$key || !is_file($key) || !is_readable($key)) {
            if ($isPublic) {
                return null;
            }

            throw new \RuntimeException(
                sprintf(
                    'Signature key "%s" does not exist or is not readable. Did you correctly set the "auth-jwt.keys" configuration key?',
                    $key,
                    $type
                )
            );
        }

        return file_get_contents($key);
    }
}
