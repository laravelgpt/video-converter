<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class StcpayGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://api.sandbox.stcpay.com.sa'; // Example
    private const API_BASE_URL_PRODUCTION = 'https://api.stcpay.com.sa'; // Example

    protected function getDefaultConfig(): array
    {
        return [
            'merchantId' => '',
            'apiKey' => '', // Or client_id, client_secret
            'secretKey' => '',
            'isSandbox' => true,
            'callbackUrl' => 'https://example.com/stcpay/callback',
            'timeout' => 45, // STC Pay might have longer timeouts
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['merchantId', 'apiKey', 'secretKey'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("STC Pay: {$key} is required.");
            }
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    private function generateSignature(array $params): string
    {
        // Placeholder: STC Pay signature logic. Often HMAC-SHA256 or similar.
        ksort($params);
        $stringToSign = http_build_query($params);
        return hash_hmac('sha256', $stringToSign, $this->config['secretKey']);
    }

    private function getRequestHeaders(): array
    {
        return [
            'Content-Type' => 'application/json',
            'Authorization' => 'Bearer ' . $this->config['apiKey'], // Or other auth scheme
            // 'X-Merchant-Id' => $this->config['merchantId'],
        ];
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('STC Pay: Invalid or missing amount.');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('STC Pay: Missing orderId.');
        }

        $payload = [
            'MerchantId' => $this->config['merchantId'],
            'Amount' => (float)$sanitizedData['amount'], // STC Pay might prefer float
            'MerchantReference' => $sanitizedData['orderId'],
            'ConfirmationLink' => $sanitizedData['callbackUrl'] ?? $this->config['callbackUrl'],
            'PaymentMethod' => 'STCPAY', // Or specific method if choices available
            'Currency' => $sanitizedData['currency'] ?? 'SAR',
            // ... other STC Pay specific params like customer details, branch ID, etc.
        ];
        // $payload['Signature'] = $this->generateSignature($payload); // Signature might be on selected fields or whole payload

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/v3/payments', $payload, $this->getRequestHeaders());
            // Mocked Response
            if ($sanitizedData['amount'] == 999) { 
                 throw new InitializationException('STC Pay: API rejected initialization (simulated).');
            }
            $mockStcRef = 'STCREF' . strtoupper(uniqid());
            $mockPaymentUrl = $this->getApiBaseUrl() . '/pg/auth?ref=' . $mockStcRef; // Example Redirect
            
            $response = ['body' => [
                    'PaymentResponse' => [
                        'PaymentId' => $mockStcRef,
                        'PaymentURL' => $mockPaymentUrl,
                        'ResponseMessage' => 'Success'
                    ]
                ],
                'status_code' => 200 
            ];

            if ($response['status_code'] !== 200 || ($response['body']['PaymentResponse']['ResponseMessage'] ?? '') !== 'Success') {
                throw new InitializationException('STC Pay: Failed to initialize payment. API Error: ' . ($response['body']['PaymentResponse']['ResponseMessage'] ?? 'Unknown error'));
            }

            return [
                'status' => 'pending_user_action',
                'message' => 'STC Pay payment initialized. Redirect user.',
                'gatewayReferenceId' => $response['body']['PaymentResponse']['PaymentId'],
                'paymentUrl' => $response['body']['PaymentResponse']['PaymentURL'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new InitializationException('STC Pay: Initialization request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        $sanitizedData = $this->sanitize($data); // Data from STC Pay callback
        // Verify callback authenticity - might involve checking a signature or re-querying.
        // For example, STC Pay might send `paymentid` and `status`.

        if (empty($sanitizedData['paymentid'])) {
            throw new ProcessingException('STC Pay: Missing paymentid in callback.');
        }

        $status = $sanitizedData['status'] ?? 'Failed'; // e.g. Paid, Failed, Pending
        $isSuccess = strtoupper($status) === 'PAID' || strtoupper($status) === 'SUCCESS';

        // It's often best to call verify() here to get the authoritative status from STC Pay server
        // return $this->verify(['gatewayReferenceId' => $sanitizedData['paymentid']]);

        return [
            'status' => $isSuccess ? 'success' : (strtoupper($status) === 'PENDING' ? 'pending' : 'failed'),
            'message' => 'STC Pay payment processed. Status: ' . $status,
            'transactionId' => $sanitizedData['paymentid'], // Or a separate transaction ID if provided
            'orderId' => $sanitizedData['merchantreference'] ?? null, // If sent back
            'paymentStatus' => $status,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['gatewayReferenceId'])) { // STC Pay's PaymentId
            throw new VerificationException('STC Pay: Missing gatewayReferenceId (PaymentId) for verification.');
        }

        $paymentId = $sanitizedData['gatewayReferenceId'];
        // Payload for verification - STC Pay might use GET with PaymentId in URL or POST
        // $payload = ['MerchantId' => $this->config['merchantId'], 'PaymentId' => $paymentId];
        // $payload['Signature'] = $this->generateSignature($payload);

        try {
            // $response = $this->httpClient('GET', $this->getApiBaseUrl() . '/v3/payments/' . $paymentId, [], $this->getRequestHeaders());
            // Mocked Response
            $mockStatus = 'Paid'; $mockMerchRef = 'ORDER' . strtoupper(uniqid());
            if ($paymentId === 'fail_verify_ref') {
                $mockStatus = 'Failed';
            }

            $response = ['body' => [
                    'PaymentStatusResponse' => [
                        'PaymentId' => $paymentId,
                        'Status' => $mockStatus, // e.g. Paid, Failed, Pending, Authorized
                        'MerchantReference' => $mockMerchRef,
                        'Amount' => $sanitizedData['original_amount_for_test'] ?? 100.00,
                        'ResponseMessage' => 'Success'
                    ]
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || ($response['body']['PaymentStatusResponse']['ResponseMessage'] ?? '') !== 'Success') {
                throw new VerificationException('STC Pay: Failed to verify payment. API Error: ' . ($response['body']['PaymentStatusResponse']['ResponseMessage'] ?? 'Unknown error'));
            }

            $paymentStatus = $response['body']['PaymentStatusResponse']['Status'] ?? 'UNKNOWN';
            $isSuccess = strtoupper($paymentStatus) === 'PAID' || strtoupper($paymentStatus) === 'AUTHORIZED';

            return [
                'status' => $isSuccess ? 'success' : (strtoupper($paymentStatus) === 'PENDING' ? 'pending' : 'failed'),
                'message' => 'STC Pay verification result: ' . $paymentStatus,
                'transactionId' => $paymentId, // STC Pay uses PaymentId as the primary transaction ref
                'orderId' => $response['body']['PaymentStatusResponse']['MerchantReference'] ?? null,
                'paymentStatus' => $paymentStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('STC Pay: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // STC Pay's PaymentId
            throw new RefundException('STC Pay: Missing transactionId (PaymentId) for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('STC Pay: Invalid or missing amount for refund.');
        }

        $payload = [
            'MerchantId' => $this->config['merchantId'],
            'OriginalPaymentId' => $sanitizedData['transactionId'],
            'Amount' => (float)$sanitizedData['amount'],
            'Reason' => $sanitizedData['reason'] ?? 'Customer request',
            // 'MerchantRefundReference' => 'REFUND_'.($sanitizedData['orderId'] ?? $sanitizedData['transactionId'])
        ];
        // $payload['Signature'] = $this->generateSignature($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/v3/payments/refund', $payload, $this->getRequestHeaders());
            // Mocked response
            if ($sanitizedData['amount'] == 999) { 
                 throw new RefundException('STC Pay: API rejected refund (simulated).');
            }
            $response = ['body' => [
                    'RefundResponse' => [
                        'RefundId' => 'STCREFUND' . strtoupper(uniqid()),
                        'Status' => 'Processed',
                        'ResponseMessage' => 'Success'
                    ]
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || ($response['body']['RefundResponse']['ResponseMessage'] ?? '') !== 'Success') {
                throw new RefundException('STC Pay: Failed to process refund. API Error: ' . ($response['body']['RefundResponse']['ResponseMessage'] ?? 'Unknown error'));
            }

            return [
                'status' => 'success', // Or 'pending' if refunds are asynchronous
                'message' => 'STC Pay refund processed successfully.',
                'refundId' => $response['body']['RefundResponse']['RefundId'] ?? null,
                'paymentStatus' => $response['body']['RefundResponse']['Status'] ?? null,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('STC Pay: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 