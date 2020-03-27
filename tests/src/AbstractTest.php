<?php

namespace ByTIC\AuthJWT\Tests;

use Nip\Config\Config;
use Nip\Container\Container;
use PHPUnit\Framework\TestCase;

/**
 * Class AbstractTest
 * @package ByTIC\AuthJWT\Tests
 */
abstract class AbstractTest extends TestCase
{

    protected function setUp(): void
    {
        parent::setUp();

        Container::setInstance(new Container());
    }

    /**
     * @param $file
     */
    protected function loadConfigIntoContainer($file)
    {
        /** @noinspection PhpIncludeInspection */
        $data = require TEST_FIXTURE_PATH. DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . $file . '.php';
        $data = [
            'auth-jwt' => $data
        ];
        $config = new Config($data);
        Container::getInstance()->set('config', $config);
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        Container::setInstance(null);
    }
}