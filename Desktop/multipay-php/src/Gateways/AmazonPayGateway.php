<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class AmazonPayGateway extends PaymentGateway
{
    // Amazon Pay API has different endpoints for different regions (NA, EU, JP)
    // This mock uses a generic placeholder; a real implementation needs regional endpoints.
    private const API_BASE_URL_SANDBOX_NA = 'https://pay-api.amazon.com/sandbox/na'; // Example for North America
    private const API_BASE_URL_PRODUCTION_NA = 'https://pay-api.amazon.com/live/na';
    // Login with Amazon (LWA) endpoints are also region-specific for token exchange
    private const LWA_TOKEN_ENDPOINT = 'https://api.amazon.com/auth/o2/token'; // Common, but might vary

    protected function getDefaultConfig(): array
    {
        return [
            'merchantId' => '',      // Your Amazon Pay Merchant ID
            'accessKey' => '',       // AWS Access Key ID (linked to Amazon Pay)
            'secretKey' => '',       // AWS Secret Access Key
            'clientId' => '',        // Login with Amazon Client ID (for LWA integration)
            'region' => 'NA',         // NA, EU, or JP - determines API endpoint and currency handling
            'publicKeyId' => '',     // New API (v2) uses PublicKeyId for request signing
            'privateKeyPath' => '', // Path to your private key file for API v2 signing
            'isSandbox' => true,
            'timeout' => 60,
            'sandboxSimulationString' => null, // For simulating specific responses in sandbox
        ];
    }

    protected function validateConfig(array $config): void
    {
        $requiredKeys = ['merchantId', 'accessKey', 'secretKey', 'clientId', 'region'];
        // For API v2, publicKeyId and privateKeyPath would be required instead of access/secret for signing
        // This mock will primarily consider a conceptual flow but acknowledge both.
        if (!empty($config['publicKeyId']) || !empty($config['privateKeyPath'])) {
            $requiredKeys = ['merchantId', 'clientId', 'region', 'publicKeyId', 'privateKeyPath'];
        }

        foreach ($requiredKeys as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("Amazon Pay: {$key} is required.");
            }
        }
        if (!in_array(strtoupper($config['region']), ['NA', 'EU', 'JP'])) {
            throw new InvalidConfigurationException("Amazon Pay: Invalid region. Must be NA, EU, or JP.");
        }
        if (!empty($config['privateKeyPath']) && !file_exists($config['privateKeyPath'])){
             throw new InvalidConfigurationException("Amazon Pay: privateKeyPath file does not exist: " . $config['privateKeyPath']);
        }
    }

    private function getApiBaseUrl(): string
    {
        $env = $this->config['isSandbox'] ? 'sandbox' : 'live';
        $regionCode = strtolower($this->config['region']);
        // This is a simplified URL construction. Real URLs are more specific, e.g. pay-api.amazon.com/sandbox/v2/checkoutSessions
        return "https://pay-api.amazon.com/{$env}/{$regionCode}"; // Generic, specific paths added later
    }
    
    // Placeholder for Amazon Pay API v2 Signature Generation
    // This is complex and involves canonical requests, string to sign, and RSA-SHA256 encryption.
    private function generateV2Signature(string $method, string $uriPath, array $queryParams, string $payload): string
    {
        if (empty($this->config['privateKeyPath']) || empty($this->config['publicKeyId'])) {
            return 'MOCK_V1_SIGNATURE_IF_NEEDED'; // Fallback or error if v2 keys not set
        }
        // $privateKey = file_get_contents($this->config['privateKeyPath']);
        // ... complex signature logic here ...
        return 'MOCK_AMZN_V2_SIGNATURE_FOR_' . strtoupper(md5($payload . $uriPath));
    }

    private function getRequestHeadersV2(string $method, string $uriPath, array $queryParams, string $payload): array
    {
        $timestamp = gmdate("Ymd\\THis\\Z");
        $signature = $this->generateV2Signature($method, $uriPath, $queryParams, $payload);
        $headers = [
            'Content-Type' => 'application/json',
            'Accept' => 'application/json',
            'x-amz-pay-region' => $this->config['region'],
            'x-amz-pay-date' => $timestamp,
            'x-amz-pay-host' => parse_url($this->getApiBaseUrl(), PHP_URL_HOST), // e.g. pay-api.amazon.com
            // Authorization: Signature Algo + PublicKeyId + SignedHeaders + Signature
            'Authorization' => sprintf(
                'AMZN-PAY-RSASSA-PSS PublicKeyId=%s, SignedHeaders=accept;content-type;x-amz-pay-date;x-amz-pay-host;x-amz-pay-region, Signature=%s',
                $this->config['publicKeyId'],
                $signature
            )
        ];
        if ($this->config['isSandbox'] && !empty($this->config['sandboxSimulationString'])) {
            // $headers['x-amz-pay-sandbox-simulation-reference'] = $this->config['sandboxSimulationString'];
        }
        return $headers;
    }

    public function initialize(array $data): array
    {
        // Amazon Pay v2: Create Checkout Session
        // This returns a redirect URL for the buyer to authenticate and select payment on Amazon.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Amazon Pay: Invalid or missing amount.');
        }
        if (empty($sanitizedData['currency'])) {
            throw new InitializationException('Amazon Pay: Missing currency code.');
        }
        if (empty($sanitizedData['orderId'])) { // chargePermissionId or merchantReferenceId
            throw new InitializationException('Amazon Pay: Missing orderId (merchantReferenceId).');
        }

        $payload = [
            'webCheckoutDetails' => [
                'checkoutReviewReturnUrl' => $sanitizedData['returnUrl'] ?? 'https://example.com/amazonpay/review',
                // 'checkoutResultReturnUrl' => $sanitizedData['confirmUrl'] ?? 'https://example.com/amazonpay/confirm', // Often same as review for simplicity
            ],
            'storeId' => $this->config['clientId'], // Or a specific storeId if configured
            'scopes' => ['name', 'email', 'postalCode', 'billingAddress'], // Example scopes
            'chargePermissionDetails' => [
                'chargePermissionType' => 'OneTime',
                'recurringMetadata' => null, // Set for recurring
            ],
            'paymentDetails' => [
                'paymentIntent' => 'AuthorizeWithCapture', // Or Authorize, Confirm
                'canHandlePendingAuthorization' => false,
                'chargeAmount' => [
                    'amount' => number_format((float)$sanitizedData['amount'], 2, '.', ''),
                    'currencyCode' => strtoupper($sanitizedData['currency'])
                ],
                // 'presentmentCurrency' => ... // If different from charge currency
                // 'softDescriptor' => ...
            ],
            'merchantMetadata' => [
                'merchantReferenceId' => $sanitizedData['orderId'],
                'merchantStoreName' => $sanitizedData['storeName'] ?? 'My Awesome Store',
                'noteToBuyer' => $sanitizedData['description'] ?? ('Order ' . $sanitizedData['orderId']),
                // 'customInformation' => ...
            ],
            // 'addressRestrictions' => ...
            // 'platformId' => ... // If you are a solution provider
        ];
        $payloadString = json_encode($payload);

        try {
            // $uriPath = '/v2/checkoutSessions';
            // $headers = $this->getRequestHeadersV2('POST', $uriPath, [], $payloadString);
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . $uriPath, $payloadString, $headers, true);

            // Mocked Response
            if ($payload['paymentDetails']['chargeAmount']['amount'] == '999.00') {
                 throw new InitializationException('Amazon Pay: Checkout session creation failed (simulated error).');
            }
            $mockCheckoutSessionId = 'AMZNCS-' . strtoupper(uniqid());
            $mockRedirectUrl = sprintf(
                'https://pay.amazon.com/%s/checkout/%s?amazonCheckoutSessionId=%s',
                strtolower($this->config['region']),
                $this->config['merchantId'],
                $mockCheckoutSessionId
            );

            $responseBody = [
                'checkoutSessionId' => $mockCheckoutSessionId,
                'webCheckoutDetails' => ['amazonPayRedirectUrl' => $mockRedirectUrl],
                // ... other details like constraints, billingAgreementDetails, etc.
            ];
            $response = ['body' => $responseBody, 'status_code' => 201]; // 201 Created for success

            if ($response['status_code'] !== 201 || empty($response['body']['checkoutSessionId']) || empty($response['body']['webCheckoutDetails']['amazonPayRedirectUrl'])) {
                throw new InitializationException('Amazon Pay: Failed to create checkout session. Error: ' . ($response['body']['reasonCode'] ?? 'Unknown API error'));
            }

            return [
                'status' => 'pending_user_action',
                'message' => 'Amazon Pay checkout session created. Redirect user.',
                'paymentUrl' => $response['body']['webCheckoutDetails']['amazonPayRedirectUrl'],
                'gatewayReferenceId' => $response['body']['checkoutSessionId'], // This is the CheckoutSessionId
                'orderId' => $sanitizedData['orderId'],
                'rawData' => $response['body']
            ];

        } catch (\Exception $e) {
            throw new InitializationException('Amazon Pay: Checkout session creation failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // This method would typically be called after the user returns from Amazon Pay's site.
        // The `checkoutSessionId` is usually passed back in the return URL.
        // The next step is to "Complete Checkout Session" (or Update and then Complete) which creates a Charge Permission and optionally a Charge.
        $sanitizedData = $this->sanitize($data);
        $checkoutSessionId = $sanitizedData['checkoutSessionId'] ?? ($sanitizedData['gatewayReferenceId'] ?? null);

        if (empty($checkoutSessionId)) {
            throw new ProcessingException('Amazon Pay: Missing checkoutSessionId to complete payment.');
        }
        // Amount and currency for the charge, should match or be derived from initialized data.
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new ProcessingException('Amazon Pay: Invalid or missing amount for charge.');
        }
        if (empty($sanitizedData['currency'])) {
            throw new ProcessingException('Amazon Pay: Missing currency for charge.');
        }

        $payload = [
            'chargeAmount' => [
                'amount' => number_format((float)$sanitizedData['amount'], 2, '.', ''),
                'currencyCode' => strtoupper($sanitizedData['currency'])
            ],
            // 'totalOrderAmount' => ..., // If different from chargeAmount, e.g. for partial auth
            // 'paymentIntent' => ..., // Can override from checkout session, usually not needed
            // 'softDescriptor' => ...
        ];
        $payloadString = json_encode($payload);

        try {
            // $uriPath = '/v2/checkoutSessions/' . $checkoutSessionId . '/complete';
            // $headers = $this->getRequestHeadersV2('POST', $uriPath, [], $payloadString);
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . $uriPath, $payloadString, $headers, true);

            // Mocked Response
            if ($checkoutSessionId === 'AMZNCS-FAILCOMPLETE') {
                throw new ProcessingException('Amazon Pay: Complete checkout session failed (simulated API error).');
            }
            
            $mockChargePermissionId = 'AMZNCP-' . strtoupper(uniqid());
            $mockChargeId = 'AMZNCH-' . strtoupper(uniqid());
            
            $responseBody = [
                'chargePermissionId' => $mockChargePermissionId,
                'chargeId' => $mockChargeId,
                'statusDetails' => [
                    'state' => 'Completed', // Could be Authorized, Captured, Declined, Cancelled
                    // 'reasonCode' => ...
                    // 'reasonDescription' => ...
                ]
            ];
            $response = ['body' => $responseBody, 'status_code' => 200];

            if ($response['status_code'] !== 200 || empty($response['body']['chargeId'])) {
                throw new ProcessingException('Amazon Pay: Failed to complete checkout session. Error: ' . ($response['body']['reasonDescription'] ?? 'Unknown error'));
            }

            $statusDetails = $response['body']['statusDetails'];
            $finalStatus = 'failed';
            $message = 'Amazon Pay payment processing: ' . $statusDetails['state'];

            if ($statusDetails['state'] === 'Completed') { // Assuming 'Completed' means captured
                $finalStatus = 'success';
            } elseif ($statusDetails['state'] === 'Authorized') {
                $finalStatus = 'authorized';
            } elseif (in_array($statusDetails['state'], ['Declined', 'Cancelled'])) {
                $finalStatus = 'failed';
                $message .= ' Reason: ' . ($statusDetails['reasonCode'] ?? 'N/A');
            } else {
                 $finalStatus = 'pending'; // For other states like Pending
            }

            return [
                'status' => $finalStatus,
                'message' => $message,
                'transactionId' => $response['body']['chargeId'], // This is the Charge ID
                'gatewayReferenceId' => $response['body']['chargePermissionId'], // ChargePermissionId is also important
                'orderId' => $sanitizedData['orderId'] ?? null,
                'paymentStatus' => $statusDetails['state'],
                'rawData' => $response['body']
            ];

        } catch (\Exception $e) {
            throw new ProcessingException('Amazon Pay: Complete checkout session failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function verify(array $data): array
    {
        // Verification means getting the status of a Charge or Charge Permission.
        // This mock will verify a Charge.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Charge ID
            throw new VerificationException('Amazon Pay: Missing transactionId (Charge ID) for verification.');
        }
        $chargeId = $sanitizedData['transactionId'];

        try {
            // $uriPath = '/v2/charges/' . $chargeId;
            // $headers = $this->getRequestHeadersV2('GET', $uriPath, [], '');
            // $response = $this->httpClient('GET', $this->getApiBaseUrl() . $uriPath, '', $headers);
            // Mocked Response
            if ($chargeId === 'AMZNCH-FAILVERIFY') {
                throw new VerificationException('Amazon Pay: API error during charge verification (simulated).');
            }
            
            $mockChargeDetails = null;
            if ($chargeId === 'AMZNCH-SUCCESS') {
                $mockChargeDetails = [
                    'chargeId' => $chargeId,
                    'chargePermissionId' => 'AMZNCP-' . strtoupper(uniqid()),
                    'chargeAmount' => ['amount' => '100.00', 'currencyCode' => 'USD'],
                    'statusDetails' => ['state' => 'Captured'], // Captured, Authorized, Declined, Cancelled, CaptureInitiated
                    'merchantMetadata' => ['merchantReferenceId' => $sanitizedData['orderIdForTest'] ?? 'ORDER_MOCK_VERIFY']
                ];
            } elseif ($chargeId === 'AMZNCH-PENDING') {
                $mockChargeDetails = ['chargeId' => $chargeId, 'statusDetails' => ['state' => 'AuthorizationInitiated']];
            }
            
            $response = ['body' => $mockChargeDetails, 'status_code' => $mockChargeDetails ? 200 : 404];

            if ($response['status_code'] !== 200 || empty($response['body'])) {
                throw new VerificationException('Amazon Pay: Failed to verify charge. Charge not found or API error.');
            }

            $charge = $response['body'];
            $state = $charge['statusDetails']['state'];
            $currentStatus = 'failed';

            if ($state === 'Captured') {
                $currentStatus = 'success';
            } elseif ($state === 'Authorized') {
                $currentStatus = 'authorized';
            } elseif (in_array($state, ['AuthorizationInitiated', 'CaptureInitiated'])) {
                $currentStatus = 'pending';
            }

            return [
                'status' => $currentStatus,
                'message' => 'Amazon Pay charge status: ' . $state,
                'transactionId' => $charge['chargeId'],
                'orderId' => $charge['merchantMetadata']['merchantReferenceId'] ?? null,
                'paymentStatus' => $state,
                'amount' => $charge['chargeAmount']['amount'] ?? null,
                'currency' => $charge['chargeAmount']['currencyCode'] ?? null,
                'rawData' => $charge
            ];

        } catch (\Exception $e) {
            throw new VerificationException('Amazon Pay: Charge verification failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Original Charge ID to refund
            throw new RefundException('Amazon Pay: Missing transactionId (Charge ID) for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Amazon Pay: Invalid or missing amount for refund.');
        }
        if (empty($sanitizedData['currency'])) {
            throw new RefundException('Amazon Pay: Missing currency for refund.');
        }

        $payload = [
            'chargeId' => $sanitizedData['transactionId'],
            'refundAmount' => [
                'amount' => number_format((float)$sanitizedData['amount'], 2, '.', ''),
                'currencyCode' => strtoupper($sanitizedData['currency'])
            ],
            'softDescriptor' => $sanitizedData['refundReason'] ?? 'Merchant Refund'
        ];
        $payloadString = json_encode($payload);

        try {
            // $uriPath = '/v2/refunds';
            // $headers = $this->getRequestHeadersV2('POST', $uriPath, [], $payloadString);
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . $uriPath, $payloadString, $headers, true);
            // Mocked Response
            if ($payload['refundAmount']['amount'] == '99.99') {
                throw new RefundException('Amazon Pay: API rejected refund (simulated amount error).');
            }
            
            $mockRefundId = 'AMZNRF-' . strtoupper(uniqid());
            $responseBody = [
                'refundId' => $mockRefundId,
                'statusDetails' => [
                    'state' => 'RefundPending', // Or Refunded, Declined
                    // 'reasonCode' => ...
                ]
            ];
            $response = ['body' => $responseBody, 'status_code' => 201]; // 201 for successful refund creation

            if ($response['status_code'] !== 201 || empty($response['body']['refundId'])) {
                 throw new RefundException('Amazon Pay: Failed to create refund. Error: ' . ($response['body']['reasonDescription'] ?? 'Unknown API error'));
            }

            $statusDetails = $response['body']['statusDetails'];
            $finalStatus = 'pending';
            if ($statusDetails['state'] === 'Refunded') {
                $finalStatus = 'success';
            } elseif ($statusDetails['state'] === 'Declined') {
                $finalStatus = 'failed';
            }
            
            return [
                'status' => $finalStatus, // Refunds can be asynchronous
                'message' => 'Amazon Pay refund status: ' . $statusDetails['state'],
                'refundId' => $response['body']['refundId'],
                'gatewayReferenceId' => $sanitizedData['transactionId'], // Original charge ID
                'paymentStatus' => $statusDetails['state'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Amazon Pay: Refund failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 