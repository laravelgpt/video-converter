<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class AdyenGateway extends PaymentGateway
{
    // Adyen uses dynamic URLs based on environment and specific service
    // For Checkout API: [random]-[company_name]-checkout-[environment].adyenpayments.com/checkout/[version]
    // For Classic API: [random]-[company_name]-[live|test].adyenpayments.com/pal/servlet/Payment/[version]
    // This mock will use a generic placeholder.
    private const API_CHECKOUT_BASE_URL_SANDBOX = 'https://checkout-test.adyen.com/v69'; // Example for Checkout API v69
    private const API_CHECKOUT_BASE_URL_PRODUCTION_TEMPLATE = 'https://{PREFIX}-checkout-live.adyenpayments.com/checkout/v69';
    // For Classic API (Refunds, Modifications)
    private const API_PAL_BASE_URL_SANDBOX = 'https://pal-test.adyen.com/pal/servlet/Payment/v64'; // Example for v64
    private const API_PAL_BASE_URL_PRODUCTION_TEMPLATE = 'https://{PREFIX}-pal-live.adyenpayments.com/pal/servlet/Payment/v64';


    protected function getDefaultConfig(): array
    {
        return [
            'merchantAccount' => '', // Your Adyen Merchant Account
            'apiKey' => '',          // API Key for Checkout API or Basic Auth for Classic API
            'clientKey' => '',       // Client Key for frontend components (optional for this mock)
            'liveEndpointPrefix' => '', // Your unique live URL prefix (e.g., 1234567890abcdef-MyCompany)
            'isSandbox' => true,
            'hmacKey' => '',         // For webhook notification verification
            'timeout' => 60,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['merchantAccount', 'apiKey'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("Adyen: {$key} is required.");
            }
        }
        if (!$config['isSandbox'] && empty($config['liveEndpointPrefix'])) {
            throw new InvalidConfigurationException("Adyen: liveEndpointPrefix is required for production environment.");
        }
    }

    private function getCheckoutApiBaseUrl(): string
    {
        if ($this->config['isSandbox']) {
            return self::API_CHECKOUT_BASE_URL_SANDBOX;
        }
        return str_replace('{PREFIX}', $this->config['liveEndpointPrefix'], self::API_CHECKOUT_BASE_URL_PRODUCTION_TEMPLATE);
    }
    
    private function getPalApiBaseUrl(): string
    {
        if ($this->config['isSandbox']) {
            return self::API_PAL_BASE_URL_SANDBOX;
        }
        return str_replace('{PREFIX}', $this->config['liveEndpointPrefix'], self::API_PAL_BASE_URL_PRODUCTION_TEMPLATE);
    }


    private function getRequestHeaders(): array
    {
        return [
            'Content-Type' => 'application/json',
            'X-API-Key' => $this->config['apiKey'],
        ];
    }
    
    // Placeholder for Adyen webhook signature verification
    protected function verifyWebhookSignature(string $payload, string $signature): bool
    {
        // $calculatedSignature = base64_encode(hash_hmac('sha256', $payload, hex2bin($this->config['hmacKey']), true));
        // return hash_equals($calculatedSignature, $signature);
        if ($signature === 'FAIL_ADYEN_SIGNATURE') return false;
        return true;
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Adyen: Invalid or missing amount. Amount in minor units (e.g., cents).');
        }
        if (empty($sanitizedData['currency'])) {
            throw new InitializationException('Adyen: Missing currency code.');
        }
        if (empty($sanitizedData['orderId'])) { // merchantReference
            throw new InitializationException('Adyen: Missing orderId (merchantReference).');
        }

        $payload = [
            'merchantAccount' => $this->config['merchantAccount'],
            'amount' => [
                'currency' => strtoupper($sanitizedData['currency']),
                'value' => (int) $sanitizedData['amount'], // Adyen expects amount in minor units
            ],
            'reference' => $sanitizedData['orderId'], // Your unique transaction reference
            'paymentMethod' => $sanitizedData['paymentMethodDetails'] ?? ['type' => 'scheme'], // E.g., from Adyen Drop-in or Components
            'returnUrl' => $sanitizedData['returnUrl'] ?? 'https://example.com/adyen/return?orderId=' . $sanitizedData['orderId'],
            // 'shopperReference' => $sanitizedData['customerId'] ?? null,
            // 'shopperEmail' => $sanitizedData['email'] ?? null,
            // 'countryCode' => $sanitizedData['countryCode'] ?? null, // e.g. NL, US
            // ... other Adyen specific parameters like lineItems, browserInfo, billingAddress, etc.
        ];

        try {
            // $response = $this->httpClient('POST', $this->getCheckoutApiBaseUrl() . '/payments', $payload, $this->getRequestHeaders());
            // Mocked Response
            if ($payload['amount']['value'] == 99900) { // 999.00 in currency
                 throw new InitializationException('Adyen: API rejected payment (simulated).');
            }
            
            $mockPspReference = 'ADYENPSP' . strtoupper(uniqid());
            $resultCode = 'RedirectShopper'; // Could be Authorised, Refused, Error, ChallengeShopper etc.
            $action = null;
            if ($resultCode === 'RedirectShopper') {
                $action = [
                    'type' => 'redirect',
                    'paymentMethodType' => 'scheme',
                    'url' => 'https://checkout-test.adyen.com/redirect?token=MOCK_ADYEN_TOKEN_' . uniqid(),
                    'method' => 'GET'
                ];
            }

            $responseBody = [
                'resultCode' => $resultCode,
                'pspReference' => $mockPspReference,
                'merchantReference' => $payload['reference'],
            ];
            if ($action) {
                $responseBody['action'] = $action;
            }

            $response = ['body' => $responseBody, 'status_code' => 200];

            if ($response['status_code'] !== 200 || empty($response['body']['pspReference'])) {
                throw new InitializationException('Adyen: Failed to initialize payment. API Error: ' . ($response['body']['refusalReason'] ?? 'Unknown error'));
            }

            $status = 'pending_user_action';
            $message = 'Adyen payment initiated.';
            $paymentUrl = null;

            if (!empty($response['body']['action']) && $response['body']['action']['type'] === 'redirect') {
                $message .= ' Redirect user.';
                $paymentUrl = $response['body']['action']['url'];
            } elseif ($response['body']['resultCode'] === 'Authorised') {
                $status = 'success'; // Or 'authorized' if capture is separate
                 $message = 'Adyen payment authorized.';
            } else {
                 // Could be requires_client_action (for 3DS2 challenge) or other states
                 $message .= ' Additional action may be required or check status.';
            }


            return [
                'status' => $status,
                'message' => $message,
                'gatewayReferenceId' => $response['body']['pspReference'], // PSP Reference
                'orderId' => $response['body']['merchantReference'],
                'paymentUrl' => $paymentUrl, // If redirect
                'action' => $response['body']['action'] ?? null, // For client-side handling (e.g. 3DS2 challenge)
                'resultCode' => $response['body']['resultCode'],
                'rawData' => $response['body']
            ];

        } catch (\Exception $e) {
            throw new InitializationException('Adyen: Payment initialization failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // Process for Adyen:
        // 1. Handling /payments/details call after redirect or challenge.
        // 2. Handling webhook notifications.
        // This mock simulates handling a webhook notification.
        $sanitizedData = $this->sanitize($data); // Assuming $data is the decoded webhook notification item

        if (empty($sanitizedData['pspReference']) || empty($sanitizedData['eventCode'])) {
            throw new ProcessingException('Adyen: Invalid webhook data. Missing pspReference or eventCode.');
        }
        
        // Optional: Verify webhook signature
        // $rawNotificationItemJson = json_encode($sanitizedData); // Or the raw JSON string received
        // $receivedHmacSignature = $_SERVER['HTTP_HMACSIGNATURE'] ?? ''; // Example, depends on how you receive it
        // if (!$this->verifyWebhookSignature($rawNotificationItemJson, $receivedHmacSignature)) {
        //     throw new ProcessingException('Adyen: Webhook HMAC signature verification failed.');
        // }

        $eventCode = $sanitizedData['eventCode'];
        $isSuccess = (bool)($sanitizedData['success'] ?? false);
        $finalStatus = 'failed';
        
        if ($eventCode === 'AUTHORISATION' && $isSuccess) {
            $finalStatus = 'success'; // Or 'authorized' if capture is separate
        } elseif ($eventCode === 'AUTHORISATION' && !$isSuccess) {
            $finalStatus = 'failed';
        } elseif ($eventCode === 'CAPTURE' && $isSuccess) {
            $finalStatus = 'success'; // Payment captured
        } elseif ($eventCode === 'CAPTURE_FAILED') {
            $finalStatus = 'failed';
        } elseif ($eventCode === 'REFUND' && $isSuccess) {
            // This indicates a refund was successful, handle in refund specific logic or here for refund status updates
            $finalStatus = 'refunded'; // Custom status
        }
        // ... handle other eventCodes like OFFER_CLOSED, CANCELLATION, PENDING etc.

        return [
            'status' => $finalStatus,
            'message' => 'Adyen payment processed via webhook. Event: ' . $eventCode . '. Reason: ' . ($sanitizedData['reason'] ?? 'N/A'),
            'transactionId' => $sanitizedData['pspReference'],
            'orderId' => $sanitizedData['merchantReference'] ?? null,
            'paymentStatus' => $eventCode, // Adyen event code
            'amount' => isset($sanitizedData['amount']['value']) ? ($sanitizedData['amount']['value'] / 100) : null, // amount is in minor units
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        // Adyen doesn't have a direct "verify" or "status" API endpoint like some gateways.
        // Status is typically confirmed via webhooks.
        // For an explicit check, one might re-use parts of process logic or if a specific API for audit/reconciliation exists.
        // This mock will assume that verify means checking data that was previously stored from a webhook.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['gatewayReferenceId'])) { // PSP Reference
            throw new VerificationException('Adyen: Missing gatewayReferenceId (PSP Reference) for verification.');
        }

        // This is a conceptual mock; real verification involves checking your DB state updated by webhooks.
        // Or using Adyen's Reporting/Reconciliation APIs which are more complex.
        // Let's simulate a "lookup" that returns a previously known status.
        
        $mockStatus = 'AUTHORISATION'; // Default to AUTHORISATION success if no specific test case
        $mockPspRef = $sanitizedData['gatewayReferenceId'];
        $mockSuccess = true;

        if ($mockPspRef === 'psp_fail_verify') {
            $mockStatus = 'AUTHORISATION';
            $mockSuccess = false;
        } else if ($mockPspRef === 'psp_pending_verify') {
            $mockStatus = 'PENDING'; // Adyen specific pending code
            $mockSuccess = true; // Pending is still a 'successful' API call
        }
        
        $responseBody = [
            'pspReference' => $mockPspRef,
            'merchantReference' => $sanitizedData['orderId'] ?? 'ORD_MOCK_'.uniqid(),
            'paymentMethod' => ['brand' => 'visa', 'type' => 'scheme'],
            'amount' => ['currency' => 'USD', 'value' => ($sanitizedData['original_amount_for_test'] ?? 100) * 100],
            'eventCode' => $mockStatus,
            'success' => $mockSuccess,
            'reason' => $mockSuccess ? '' : 'Refused by bank'
        ];

        $isTransactionSuccess = $responseBody['eventCode'] === 'AUTHORISATION' && $responseBody['success'];
        $isTransactionPending = $responseBody['eventCode'] === 'PENDING';

        return [
            'status' => $isTransactionSuccess ? 'success' : ($isTransactionPending ? 'pending' : 'failed'),
            'message' => 'Adyen (simulated) verification. Event: ' . $responseBody['eventCode'] . '. Success: ' . ($responseBody['success'] ? 'true' : 'false'),
            'transactionId' => $responseBody['pspReference'],
            'orderId' => $responseBody['merchantReference'],
            'paymentStatus' => $responseBody['eventCode'],
            'rawData' => $responseBody
        ];
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Original PSP Reference of the payment to refund
            throw new RefundException('Adyen: Missing transactionId (original PSP Reference) for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Adyen: Invalid or missing amount for refund. Amount in minor units.');
        }

        $payload = [
            'merchantAccount' => $this->config['merchantAccount'],
            'modificationAmount' => [
                'currency' => strtoupper($sanitizedData['currency'] ?? 'USD'), // Must match original or be supported
                'value' => (int) $sanitizedData['amount'], // Amount in minor units
            ],
            'originalReference' => $sanitizedData['transactionId'],
            'reference' => $sanitizedData['refundId'] ?? 'REFUND_' . $sanitizedData['transactionId'] . '_' . time(), // Your unique reference for the refund
            // ... other optional fields like 'merchantOrderReference'
        ];

        try {
            // API call for refund (using Classic API in this example)
            // $response = $this->httpClient('POST', $this->getPalApiBaseUrl() . '/refund', $payload, $this->getRequestHeaders());
            // Mocked Response
            if ($payload['modificationAmount']['value'] == 99900) {
                 throw new RefundException('Adyen: API rejected refund (simulated).');
            }
            $mockRefundPspReference = 'ADYENREFUNDPSP' . strtoupper(uniqid());
            $response = ['body' => [
                    'pspReference' => $mockRefundPspReference, // PSP reference for the refund modification
                    'response' => '[refund-received]', // Or [refund-approved], [refund-error] etc.
                ],
                'status_code' => 200
            ];
            
            // Adyen refund responses can be [refund-received] initially. Actual success/failure via webhook.
            if ($response['status_code'] !== 200 || !str_contains(strtolower($response['body']['response'] ?? ''), 'received')) {
                 throw new RefundException('Adyen: Failed to submit refund request. Response: ' . ($response['body']['response'] ?? 'Unknown error'));
            }

            return [
                'status' => 'pending', // Refunds are often asynchronous, confirm via webhook (eventCode: REFUND)
                'message' => 'Adyen refund request received. Final status will be confirmed via webhook. Response: ' . $response['body']['response'],
                'refundId' => $payload['reference'], // Your refund reference
                'gatewayReferenceId' => $response['body']['pspReference'], // PSP Reference for the refund itself
                'paymentStatus' => $response['body']['response'], // Initial response from Adyen
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Adyen: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 