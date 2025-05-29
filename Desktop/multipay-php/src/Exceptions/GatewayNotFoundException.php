<?php

namespace Multipay\Payment\Exceptions;

class GatewayNotFoundException extends PaymentException
{
    public function __construct(string $gatewayName, int $code = 0, \Throwable $previous = null)
    {
        parent::__construct("Gateway '{$gatewayName}' not found or not configured.", $code, $previous);
    }
} 