<?php

namespace ByTIC\AuthJWT\Services\KeyLoader;

/**
 * Class RawKeyLoader
 * @package ByTIC\AuthJWT\Services\KeyLoader
 */
class RawKeyLoader extends AbstractKeyLoader
{
    /**
     * @param string $type
     *
     * @return string
     *
     * @throws \RuntimeException If the key cannot be read
     */
    public function loadKey($type)
    {
        if (!in_array($type, [self::TYPE_PUBLIC, self::TYPE_PRIVATE])) {
            throw new \InvalidArgumentException(sprintf('The key type must be "public" or "private", "%s" given.', $type));
        }

        if (self::TYPE_PUBLIC === $type) {
            return $this->dumpKey();
        }

        return $this->getPrivateKey();
    }
}