<?php

namespace Multipay\Payment\Exceptions;

class ProcessingException extends PaymentException
{
    public function __construct(string $message = "Payment processing failed.", int $code = 0, \Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
} 