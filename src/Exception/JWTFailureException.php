<?php

namespace ByTIC\AuthJWT\Exception;

/**
 * Class JWTFailureException
 * @package ByTIC\AuthJWT\Exception
 */
class JWTFailureException extends \Exception
{
    /**
     * @var string
     */
    private $reason;

    /**
     * @param string $reason
     * @param string $message
     * @param \Exception|null $previous
     */
    public function __construct($reason, $message, \Exception $previous = null)
    {
        $this->reason = $reason;

        parent::__construct($message, 0, $previous);
    }

    /**
     * @return string
     */
    public function getReason()
    {
        return $this->reason;
    }
}