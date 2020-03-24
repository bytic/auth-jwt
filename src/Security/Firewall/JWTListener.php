<?php

namespace ByTIC\JWTAuth\Security\Firewall;

use ByTIC\JWTAuth\TokenExtractor\TokenExtractorInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Class JWTListener
 * @package ByTIC\JWTAuth\Security\Firewall
 */
class JWTListener extends AbstractListener
{

    /**
     * @var array
     */
    protected $tokenExtractors;

    /**
     * @param GetResponseEvent|RequestEvent $event
     */
    public function __invoke($event)
    {
        $requestToken = $this->getRequestToken($event->getRequest());

        if (null === $requestToken) {
            $jwtNotFoundEvent = new JWTNotFoundEvent();
            if ($this->dispatcher instanceof ContractsEventDispatcherInterface) {
                $this->dispatcher->dispatch($jwtNotFoundEvent, Events::JWT_NOT_FOUND);
            } else {
                $this->dispatcher->dispatch(Events::JWT_NOT_FOUND, $jwtNotFoundEvent);
            }


            if ($response = $jwtNotFoundEvent->getResponse()) {
                $event->setResponse($response);
            }

            return;
        }

        try {
            $token = new JWTUserToken();
            $token->setRawToken($requestToken);

            $authToken = $this->authenticationManager->authenticate($token);
            $this->tokenStorage->setToken($authToken);

            return;
        } catch (AuthenticationException $failed) {
            if ($this->config['throw_exceptions']) {
                throw $failed;
            }

            $response = new JWTAuthenticationFailureResponse($failed->getMessage());

            $jwtInvalidEvent = new JWTInvalidEvent($failed, $response);
            if ($this->dispatcher instanceof ContractsEventDispatcherInterface) {
                $this->dispatcher->dispatch($jwtInvalidEvent, Events::JWT_INVALID);
            } else {
                $this->dispatcher->dispatch(Events::JWT_INVALID, $jwtInvalidEvent);
            }


            $event->setResponse($jwtInvalidEvent->getResponse());
        }
    }

    /**
     * @param TokenExtractorInterface $extractor
     */
    public function addTokenExtractor(TokenExtractorInterface $extractor)
    {
        $this->tokenExtractors[] = $extractor;
    }

    /**
     * @param Request $request
     *
     * @return string
     */
    protected function getRequestToken(Request $request)
    {
        /** @var TokenExtractorInterface $tokenExtractor */
        foreach ($this->tokenExtractors as $tokenExtractor) {
            if (($token = $tokenExtractor->extract($request))) {
                return $token;
            }
        }
    }
}