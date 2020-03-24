<?php

namespace ByTIC\JWTAuth\Security\Firewall;

/**
 * Class AbstractListener
 * @package ByTIC\JWTAuth\Security\Firewall
 */
abstract class AbstractListener
{
    /**
     * @param $event
     * @return mixed
     */
    abstract public function __invoke($event);
}