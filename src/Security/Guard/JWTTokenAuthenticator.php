<?php

namespace ByTIC\AuthJWT\Security\Guard;

use ByTIC\AuthJWT\Security\Authentication\Token\JWTUserToken;
use ByTIC\AuthJWT\TokenExtractor\AuthorizationHeaderTokenExtractor;
use ByTIC\AuthJWT\TokenExtractor\TokenExtractorInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

/**
 * Class JWTTokenAuthenticator
 * @package ByTIC\AuthJWT\Security\Guard
 */
class JWTTokenAuthenticator extends AbstractGuardAuthenticator
{
    protected $tokenExtractor;

    public function __construct()
    {
        $this->tokenExtractor = new AuthorizationHeaderTokenExtractor(
            'Bearer',
            'Authorization'
        );
    }


    /**
     * @inheritDoc
     */
    public function supports(Request $request)
    {
        return false !== $this->getTokenExtractor()->extract($request);
    }

    /**
     * @inheritDoc
     */
    public function getCredentials(Request $request)
    {
        $token = $this->tokenExtractor->extract($request);

        if (!$token) {
            return null;
        }

        return $token;
    }

    /**
     * @inheritDoc
     */
    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        // TODO: Implement getUser() method.
    }

    /**
     * @inheritDoc
     */
    public function checkCredentials($credentials, UserInterface $user)
    {
        return true;
    }

    /**
     * @inheritDoc
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        // TODO: Implement onAuthenticationFailure() method.
    }

    /**
     * @inheritDoc
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        // TODO: Implement onAuthenticationSuccess() method.
    }

    /**
     * {@inheritdoc}
     *
     * @throws \RuntimeException If there is no pre-authenticated token previously stored
     */
    public function createAuthenticatedToken(UserInterface $user, $providerKey)
    {
        $preAuthToken = $this->preAuthenticationTokenStorage->getToken();

        if (null === $preAuthToken) {
            throw new \RuntimeException('Unable to return an authenticated token since there is no pre authentication token.');
        }

        $authToken = new JWTUserToken($user->getRoles(), $user, $preAuthToken->getCredentials(), $providerKey);

        if ($this->dispatcher instanceof ContractsEventDispatcherInterface) {
            $this->dispatcher->dispatch(new JWTAuthenticatedEvent($preAuthToken->getPayload(), $authToken),
                Events::JWT_AUTHENTICATED);
        } else {
            $this->dispatcher->dispatch(Events::JWT_AUTHENTICATED,
                new JWTAuthenticatedEvent($preAuthToken->getPayload(), $authToken));
        }

        $this->preAuthenticationTokenStorage->setToken(null);

        return $authToken;
    }

    /**
     * @inheritDoc
     */
    public function supportsRememberMe()
    {
        return false;
    }

    /**
     * @inheritDoc
     * @return JWTAuthenticationFailureResponsecreateAuthenticatedToken
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        // TODO: Implement start() method.
    }

    /**
     * Gets the token extractor to be used for retrieving a JWT token in the
     * current request.
     *
     * Override this method for adding/removing extractors to the chain one or
     * returning a different {@link TokenExtractorInterface} implementation.
     *
     * @return TokenExtractorInterface
     */
    protected function getTokenExtractor()
    {
        return $this->tokenExtractor;
    }
}
