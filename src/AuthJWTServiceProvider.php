<?php

namespace ByTIC\AuthJWT;

use ByTIC\AuthJWT\Services\JWTProvider\LcobucciJWTProvider;
use ByTIC\AuthJWT\Services\KeyLoader\RawKeyLoader;
use Nip\Container\ServiceProviders\Providers\AbstractSignatureServiceProvider;

/**
 * Class AuthJWTServiceProvider
 * @package ByTIC\AuthJWT
 */
class AuthJWTServiceProvider extends AbstractSignatureServiceProvider
{
    /**
     * @inheritdoc
     */
    public function register()
    {
        $this->registerJWTProvider();
        $this->registerKeys();
    }

    /**
     * Register the bindings for the JSON Web Token provider.
     *
     * @return void
     */
    protected function registerJWTProvider()
    {
//        $this->registerNamshiProvider();
        $this->registerLcobucciProvider();
    }


    /**
     * Register the bindings for the Lcobucci JWT provider.
     *
     * @return void
     */
    protected function registerLcobucciProvider()
    {
        $this->getContainer()->share(
            'auth-jwt.jwt.provider.lcobucci',
            function () {
                return new LcobucciJWTProvider(
                    $this->getContainer()->get('auth-jwt.jwt.keys.loader'),
                    'openssl',
                    $this->config('algo', 'HS256'),
                    $this->config('ttl', 3600),
                    $this->config('clock_skew', 0)
                );
            }
        );
    }

    protected function registerKeys()
    {
        foreach (['public', 'private', 'passphrase'] as $key) {
            $this->getContainer()->share(
                'auth-jwt.jwt.keys.' . $key,
                function () use ($key) {
                    $this->config('keys.' . $key);
                }
            );
        }

        $this->getContainer()->share(
            'auth-jwt.jwt.keys.loader',
            function () {
                return new RawKeyLoader(
                    $this->getContainer()->get('auth-jwt.jwt.keys.public'),
                    $this->getContainer()->get('auth-jwt.jwt.keys.private'),
                    $this->getContainer()->get('auth-jwt.jwt.keys.passphrase')
                );
            }
        );
    }

    /**
     * @inheritdoc
     */
    public function provides()
    {
        return [
            'auth-jwt.jwt.provider',
            'auth-jwt.jwt.keys.public',
            'auth-jwt.jwt.keys.private',
            'auth-jwt.jwt.keys.loader',
        ];
    }


    /**
     * Helper to get the config values.
     *
     * @param string $key
     * @param string $default
     *
     * @return mixed
     */
    protected function config($key, $default = null)
    {
        return config("auth-jwt.$key", $default);
    }
}
