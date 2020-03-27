<?php

namespace ByTIC\AuthJWT\Services\KeyLoader;

/**
 * Interface KeyLoaderInterface
 * @package ByTIC\AuthJWT\Services\KeyLoader
 */
interface KeyLoaderInterface
{
    const TYPE_PUBLIC  = 'public';

    const TYPE_PRIVATE = 'private';

    /**
     * Loads a key from a given type (public or private).
     *
     * @param resource|string|null
     *
     * @return resource|string|null
     */
    public function loadKey($type);

    /**
     * @return string|null
     */
    public function getPassphrase();
}
