<?php

namespace Multipay\Payment\Exceptions;

class InvalidConfigurationException extends PaymentException
{
    public function __construct(string $message = "Invalid gateway configuration.", int $code = 0, \Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
} 