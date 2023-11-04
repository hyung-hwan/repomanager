<?php

namespace Controllers\Api;

use Exception;

class Controller
{
    protected $method;
    protected $uri;
    protected $data;
    protected $apiKeyAuthentication = false;
    protected $hostAuthentication = false;

    public function __construct(string $method, array $uri)
    {
        $this->method = $method;
        $this->uri = $uri;
    }

    /**
     *  Set API key authentication status (true or false)
     */
    public function setApiKeyAuthentication(bool $apiKeyAuthentication)
    {
        $this->apiKeyAuthentication = $apiKeyAuthentication;
    }

    /**
     *  Set host authentication status (true or false)
     */
    public function setHostAuthentication(bool $hostAuthentication)
    {
        $this->hostAuthentication = $hostAuthentication;
    }

    /**
     *  Set retrieved JSON data from request
     */
    public function setJsonData(object $data)
    {
        $this->data = $data;
    }
}
