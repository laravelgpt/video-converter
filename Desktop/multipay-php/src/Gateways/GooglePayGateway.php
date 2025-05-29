<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class GooglePayGateway extends PaymentGateway
{
    // Google Pay is not a standalone processor. It provides tokens to actual processors.
    // This is a conceptual gateway. Real integration involves a client-side SDK and a backend processor (e.g., Stripe, Braintree).
    private const PROCESSOR_API_BASE_URL_SANDBOX = 'https://api.sandbox.youractualprocessor.com'; // Example
    private const PROCESSOR_API_BASE_URL_PRODUCTION = 'https://api.youractualprocessor.com'; // Example

    protected function getDefaultConfig(): array
    {
        return [
            // Config for the *underlying* payment processor that handles Google Pay tokens
            'processorMerchantId' => '', // E.g., Your Stripe, Braintree, Adyen merchant ID
            'processorApiKey' => '',     // API key for that processor
            'processorApiSecret' => '',  // Secret for that processor
            'googlePayMerchantId' => '', // Your Google Pay Merchant ID (from Google Pay Business Console)
            'gatewayName' => 'YourProcessorName', // e.g., stripe, braintree
            'isSandbox' => true,
            'timeout' => 60,
        ];
    }

    protected function validateConfig(array $config): void
    {
        // Validate config for the underlying processor
        foreach (['processorMerchantId', 'processorApiKey', 'googlePayMerchantId', 'gatewayName'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("Google Pay (via {$config['gatewayName']}): {$key} is required.");
            }
        }
    }

    private function getProcessorApiBaseUrl(): string
    {
        // This would depend on the chosen underlying processor
        return $this->config['isSandbox'] ? self::PROCESSOR_API_BASE_URL_SANDBOX : self::PROCESSOR_API_BASE_URL_PRODUCTION;
    }

    public function initialize(array $data): array
    {
        // Initialization for Google Pay is mostly client-side using Google Pay SDK.
        // Server side might prepare some parameters for the client (e.g., amount, currency, merchant info).
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Google Pay: Invalid or missing amount.');
        }
        if (empty($sanitizedData['currency'])) {
            throw new InitializationException('Google Pay: Missing currency code.');
        }

        // These parameters are for the Google Pay client SDK
        $googlePayClientParams = [
            'merchantInfo' => [
                'merchantId' => $this->config['googlePayMerchantId'],
                'merchantName' => $sanitizedData['merchantName'] ?? 'Your Store Name',
            ],
            'transactionInfo' => [
                'totalPriceStatus' => 'FINAL',
                'totalPrice' => sprintf('%.2f', $sanitizedData['amount']),
                'currencyCode' => strtoupper($sanitizedData['currency']),
                'countryCode' => $sanitizedData['countryCode'] ?? 'US', // Transaction country
                'checkoutOption' => 'COMPLETE_IMMEDIATE_PURCHASE',
            ],
            'allowedPaymentMethods' => [[
                'type' => 'CARD',
                'parameters' => [
                    'allowedAuthMethods' => ["PAN_ONLY", "CRYPTOGRAM_3DS"],
                    'allowedCardNetworks' => $sanitizedData['allowedCardNetworks'] ?? ["AMEX", "DISCOVER", "JCB", "MASTERCARD", "VISA"],
                ],
                'tokenizationSpecification' => [
                    'type' => 'PAYMENT_GATEWAY',
                    'parameters' => [
                        'gateway' => $this->config['gatewayName'], // e.g. "stripe", "braintree"
                        // Processor-specific parameters:
                        // 'stripe:version' => '2020-08-27',
                        // 'stripe:publishableKey' => 'pk_test_yourstripesandboxkey'
                        // 'braintree:merchantId' => 'yourBraintreeMerchantId'
                        // 'braintree:apiVersion' => 'v1'
                        // ... add parameters specific to your chosen processor (this->config['gatewayName'])
                    ]
                ]
            ]],
            'callbackIntents' => ['PAYMENT_AUTHORIZATION'], // To receive payment token
            'emailRequired' => $sanitizedData['emailRequired'] ?? false,
            'shippingAddressRequired' => $sanitizedData['shippingAddressRequired'] ?? false,
            // ... other Google Pay SDK parameters
        ];
        
        if($this->config['gatewayName'] === 'stripe'){
            $googlePayClientParams['allowedPaymentMethods'][0]['tokenizationSpecification']['parameters']['stripe:publishableKey'] = $this->config['processorApiKey']; // Stripe uses publishable key here
            $googlePayClientParams['allowedPaymentMethods'][0]['tokenizationSpecification']['parameters']['stripe:version'] = '2020-08-27';
        }

        return [
            'status' => 'client_setup_required',
            'message' => 'Google Pay requires client-side SDK setup with these parameters.',
            'googlePayParameters' => $googlePayClientParams,
            'orderId' => $sanitizedData['orderId'] ?? 'GPAY_ORDER_'.uniqid(), // Your internal order ID
            'rawData' => $googlePayClientParams
        ];
    }

    public function process(array $data): array
    {
        // Process for Google Pay: Server receives the payment token from client, sends it to the actual payment processor.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['paymentToken'])) { // Google Pay Payment Token (stringified JSON)
            throw new ProcessingException('Google Pay: Missing paymentToken.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new ProcessingException('Google Pay: Invalid or missing amount for processing.');
        }
        if (empty($sanitizedData['currency'])) {
            throw new ProcessingException('Google Pay: Missing currency for processing.');
        }

        $paymentToken = $sanitizedData['paymentToken']; // This is the encrypted token from Google Pay SDK
        // $decodedToken = json_decode($paymentToken, true); // Potentially inspect parts of it if needed

        // Payload to send to your *actual* payment processor (e.g., Stripe)
        $processorPayload = [
            'amount' => (int)($sanitizedData['amount'] * 100), // Amount in cents/paisa for most processors
            'currency' => strtolower($sanitizedData['currency']),
            'description' => $sanitizedData['description'] ?? 'Google Pay transaction',
            'payment_method_data' => [
                'type' => 'google_pay',
                'token' => $paymentToken, // The raw token from Google
            ],
            // 'metadata' => ['order_id' => $sanitizedData['orderId']]
            // This structure is highly dependent on the chosen processor (Stripe, Braintree, Adyen etc.)
        ];

        try {
            // $response = $this->httpClient('POST', $this->getProcessorApiBaseUrl() . '/v1/charges', $processorPayload, /* Processor specific headers */);
            // Mocked Response from the underlying processor
            if ($sanitizedData['amount'] == 999) { 
                 throw new ProcessingException('Google Pay (via Processor): API rejected charge (simulated).');
            }
            $mockProcessorTxnId = strtoupper($this->config['gatewayName']) . '_TXN_' . strtoupper(uniqid());
            $response = ['body' => [
                    'id' => $mockProcessorTxnId,
                    'status' => 'succeeded',
                    'amount' => $processorPayload['amount'],
                    'currency' => $processorPayload['currency'],
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] >= 300 || strtolower($response['body']['status'] ?? '') !== 'succeeded') {
                throw new ProcessingException('Google Pay (via Processor): Payment failed. ' . ($response['body']['failure_message'] ?? 'Processor error'));
            }

            return [
                'status' => 'success',
                'message' => 'Google Pay payment processed successfully via ' . $this->config['gatewayName'] . '.',
                'transactionId' => $response['body']['id'], // Transaction ID from the actual processor
                'orderId' => $sanitizedData['orderId'] ?? null,
                'paymentStatus' => $response['body']['status'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new ProcessingException('Google Pay (via Processor): Processing request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function verify(array $data): array
    {
        // Verification would be against the actual payment processor, using their transaction ID.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Transaction ID from the underlying processor
            throw new VerificationException('Google Pay (via Processor): Missing transactionId for verification.');
        }
        $processorTransactionId = $sanitizedData['transactionId'];

        try {
            // $response = $this->httpClient('GET', $this->getProcessorApiBaseUrl() . '/v1/charges/' . $processorTransactionId, [], /* Processor headers */);
            // Mocked Response
            $mockStatus = 'succeeded';
            if ($processorTransactionId === 'fail_verify_ref') {
                $mockStatus = 'failed';
            }
            $response = ['body' => [
                    'id' => $processorTransactionId,
                    'status' => $mockStatus,
                    'amount' => ($sanitizedData['original_amount_for_test'] ?? 100) * 100,
                    'currency' => 'usd',
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200) {
                throw new VerificationException('Google Pay (via Processor): Failed to verify. API Error.');
            }

            $paymentStatus = $response['body']['status'] ?? 'unknown';
            $isSuccess = strtolower($paymentStatus) === 'succeeded' || strtolower($paymentStatus) === 'paid';

            return [
                'status' => $isSuccess ? 'success' : 'failed',
                'message' => 'Google Pay (via Processor) verification result: ' . $paymentStatus,
                'transactionId' => $response['body']['id'],
                'orderId' => $sanitizedData['orderId'] ?? null, // If you stored it with the processor txn
                'paymentStatus' => $paymentStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('Google Pay (via Processor): Verification failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        // Refund would be against the actual payment processor.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Processor's transaction ID
            throw new RefundException('Google Pay (via Processor): Missing transactionId for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Google Pay (via Processor): Invalid or missing amount for refund.');
        }

        $processorTransactionId = $sanitizedData['transactionId'];
        $processorPayload = [
            'amount' => (int)($sanitizedData['amount'] * 100),
            'reason' => $sanitizedData['reason'] ?? 'requested_by_customer',
            // 'charge' => $processorTransactionId, // For Stripe, if refunding a charge
        ];

        try {
            // $response = $this->httpClient('POST', $this->getProcessorApiBaseUrl() . '/v1/refunds', $processorPayload, /* Processor headers */);
            // (Stripe: /v1/refunds with 'charge' param; Braintree: /transactions/{id}/refund)
            // Mocked response
             if ($processorPayload['amount'] == 99900) { 
                 throw new RefundException('Google Pay (via Processor): API rejected refund (simulated).');
            }
            $response = ['body' => [
                    'id' => 'REFUND_' . strtoupper($this->config['gatewayName']) . '_' . strtoupper(uniqid()),
                    'status' => 'succeeded',
                    'amount' => $processorPayload['amount']
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] >= 300 || strtolower($response['body']['status'] ?? '') !== 'succeeded') {
                throw new RefundException('Google Pay (via Processor): Refund failed. ' . ($response['body']['failure_reason'] ?? 'Processor error'));
            }

            return [
                'status' => 'success',
                'message' => 'Google Pay (via Processor) refund processed successfully.',
                'refundId' => $response['body']['id'],
                'paymentStatus' => $response['body']['status'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Google Pay (via Processor): Refund failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 