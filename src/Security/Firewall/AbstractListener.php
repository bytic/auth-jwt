<?php

namespace ByTIC\AuthJWT\Security\Firewall;

/**
 * Class AbstractListener
 * @package ByTIC\AuthJWT\Security\Firewall
 */
abstract class AbstractListener
{
    /**
     * @param $event
     * @return mixed
     */
    abstract public function __invoke($event);
}