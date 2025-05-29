<?php

namespace Multipay\Payment\Exceptions;

class RefundException extends PaymentException
{
    public function __construct(string $message = "Payment refund failed.", int $code = 0, \Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
} 