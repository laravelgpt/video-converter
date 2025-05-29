<?php

namespace Multipay\Payment\Exceptions;

class InitializationException extends PaymentException
{
    public function __construct(string $message = "Payment initialization failed.", int $code = 0, \Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
} 