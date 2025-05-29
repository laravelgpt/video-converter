<?php

namespace Multipay\Payment;

use Multipay\Payment\Exceptions\GatewayNotFoundException;

class PaymentProcessor
{
    private array $gateways = [];
    private array $gatewayConfigs = []; // Store configurations

    /**
     * Add a gateway with its configuration.
     *
     * @param string $name Alias for the gateway.
     * @param string $className The fully qualified class name of the gateway.
     * @param array $config Configuration for the gateway.
     */
    public function addGateway(string $name, string $className, array $config): void
    {
        if (!class_exists($className) || !is_subclass_of($className, PaymentGateway::class)) {
            throw new \InvalidArgumentException("Invalid gateway class: {$className}");
        }
        $this->gateways[$name] = $className;
        $this->gatewayConfigs[$name] = $config;
    }

    /**
     * Get an initialized gateway instance.
     *
     * @param string $name
     * @return PaymentGateway
     * @throws GatewayNotFoundException
     */
    public function getGateway(string $name): PaymentGateway
    {
        if (!isset($this->gateways[$name])) {
            throw new GatewayNotFoundException($name);
        }
        $className = $this->gateways[$name];
        $config = $this->gatewayConfigs[$name] ?? [];
        return new $className($config); // Instantiate with config
    }

    public function initialize(string $gatewayName, array $data): array
    {
        $gatewayInstance = $this->getGateway($gatewayName);
        return $gatewayInstance->initialize($data);
    }

    public function process(string $gatewayName, array $data): array
    {
        $gatewayInstance = $this->getGateway($gatewayName);
        return $gatewayInstance->process($data);
    }

    public function verify(string $gatewayName, array $data): array
    {
        $gatewayInstance = $this->getGateway($gatewayName);
        return $gatewayInstance->verify($data);
    }

    public function refund(string $gatewayName, array $data): array
    {
        $gatewayInstance = $this->getGateway($gatewayName);
        return $gatewayInstance->refund($data);
    }
} 