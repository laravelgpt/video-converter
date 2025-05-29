<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class PayPalGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://api.sandbox.paypal.com';
    private const API_BASE_URL_PRODUCTION = 'https://api.paypal.com';

    private ?string $accessToken = null;

    protected function getDefaultConfig(): array
    {
        return [
            'clientId' => '',
            'clientSecret' => '',
            'isSandbox' => true,
            'returnUrl' => 'https://example.com/paypal/success',
            'cancelUrl' => 'https://example.com/paypal/cancel',
            'brandName' => 'My Application',
            'timeout' => 60, // PayPal can be slow
        ];
    }

    protected function validateConfig(array $config): void
    {
        if (empty($config['clientId'])) {
            throw new InvalidConfigurationException('PayPal: Client ID is required.');
        }
        if (empty($config['clientSecret'])) {
            throw new InvalidConfigurationException('PayPal: Client Secret is required.');
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    private function getAccessToken(): string
    {
        if ($this->accessToken) {
            // TODO: Check token expiry and refresh if necessary
            return $this->accessToken;
        }

        $auth = base64_encode($this->config['clientId'] . ':' . $this->config['clientSecret']);
        $headers = [
            'Authorization' => 'Basic ' . $auth,
            'Content-Type' => 'application/x-www-form-urlencoded'
        ];
        $data = ['grant_type' => 'client_credentials'];

        try {
            // Mocking, in reality, use $this->httpClient (but it needs to handle basic auth & x-www-form-urlencoded properly)
            // For now, direct simulation:
            if ($this->config['clientId'] === 'force_token_error') {
                 throw new InitializationException("PayPal: Failed to obtain access token (simulated).");
            }
            $responseBody = ['access_token' => 'mock_paypal_access_token_' . uniqid(), 'expires_in' => 3600];
            $statusCode = 200;
            
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/v1/oauth2/token', $data, $headers); // Needs httpClient to support this form
            // $statusCode = $response['status_code'];
            // $responseBody = $response['body'];

            if ($statusCode !== 200 || empty($responseBody['access_token'])) {
                throw new InitializationException('PayPal: Failed to obtain access token. ' . ($responseBody['error_description'] ?? 'Unknown OAuth error'));
            }
            $this->accessToken = $responseBody['access_token'];
            return $this->accessToken;
        } catch (\Exception $e) {
            throw new InitializationException('PayPal: Access token request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    private function getRequestHeaders(bool $includeAuth = true): array
    {
        $headers = ['Content-Type' => 'application/json'];
        if ($includeAuth) {
            $headers['Authorization'] = 'Bearer ' . $this->getAccessToken();
        }
        return $headers;
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('PayPal: Invalid or missing amount.');
        }
        if (empty($sanitizedData['currency'])) {
            throw new InitializationException('PayPal: Missing currency code.');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('PayPal: Missing orderId (merchant request id).');
        }

        $payload = [
            'intent' => 'CAPTURE', // Or AUTHORIZE
            'application_context' => [
                'brand_name' => $this->config['brandName'],
                'landing_page' => 'LOGIN', // Or GUEST_CHECKOUT
                'user_action' => 'PAY_NOW',
                'return_url' => $sanitizedData['returnUrl'] ?? $this->config['returnUrl'],
                'cancel_url' => $sanitizedData['cancelUrl'] ?? $this->config['cancelUrl'],
            ],
            'purchase_units' => [
                [
                    'reference_id' => $sanitizedData['orderId'], // Your internal order ID
                    'amount' => [
                        'currency_code' => strtoupper($sanitizedData['currency']),
                        'value' => sprintf('%.2f', $sanitizedData['amount']),
                    ],
                    'description' => $sanitizedData['description'] ?? 'Payment for order ' . $sanitizedData['orderId'],
                    // 'custom_id' => 'Your custom ID if needed'
                ]
            ]
        ];

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/v2/checkout/orders', $payload, $this->getRequestHeaders());
            // Mocked response
             if ($sanitizedData['amount'] == 999) { 
                 throw new InitializationException('PayPal: API rejected order creation (simulated).');
            }
            $mockPaypalOrderId = 'MOCKPAYPALORDER_' . strtoupper(uniqid());
            $mockApprovalLink = 'https://www.sandbox.paypal.com/checkoutnow?token=' . $mockPaypalOrderId;
            
            $response = ['body' => [
                    'id' => $mockPaypalOrderId,
                    'status' => 'CREATED',
                    'links' => [
                        ['href' => $mockApprovalLink, 'rel' => 'approve', 'method' => 'GET'],
                    ]
                ],
                'status_code' => 201
            ];

            if ($response['status_code'] !== 201 || empty($response['body']['id']) || empty($response['body']['links'])) {
                throw new InitializationException('PayPal: Failed to create order. ' . ($response['body']['message'] ?? 'Unknown API error'));
            }

            $approvalUrl = null;
            foreach ($response['body']['links'] as $link) {
                if ($link['rel'] === 'approve') {
                    $approvalUrl = $link['href'];
                    break;
                }
            }
            if (!$approvalUrl) {
                throw new InitializationException('PayPal: No approval URL found in API response.');
            }

            return [
                'status' => 'pending_user_action',
                'message' => 'PayPal order created. Redirect user for approval.',
                'gatewayReferenceId' => $response['body']['id'], // PayPal Order ID
                'paymentUrl' => $approvalUrl,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new InitializationException('PayPal: Order creation request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * process is typically capturing the payment after user approval.
     * User is redirected back to your site with `token` (PayPal Order ID) and `PayerID`.
     */
    public function process(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['token']) && empty($sanitizedData['gatewayReferenceId'])) { // `token` is PayPal Order ID from redirect
            throw new ProcessingException('PayPal: Missing token (PayPal Order ID) for capture.');
        }
        
        $paypalOrderId = $sanitizedData['token'] ?? $sanitizedData['gatewayReferenceId'];

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/v2/checkout/orders/' . $paypalOrderId . '/capture', [], $this->getRequestHeaders());
            // Mocked response
            $mockCaptureId = 'MOCKCAPTUREID_'.strtoupper(uniqid());
            $mockStatus = 'COMPLETED';
            if ($paypalOrderId === 'force_capture_error'){
                $mockStatus = 'FAILED';
                throw new ProcessingException('PayPal: Capture failed (simulated API error).');
            }

            $response = ['body' => [
                'id' => $paypalOrderId,
                'status' => $mockStatus, // COMPLETED, FAILED, etc.
                'purchase_units' => [
                    [
                        'payments' => [
                            'captures' => [
                                ['id' => $mockCaptureId, 'status' => $mockStatus]
                            ]
                        ]
                    ]
                ]
            ], 'status_code' => 201]; // Or 200

            if (($response['status_code'] !== 200 && $response['status_code'] !== 201) || strtoupper($response['body']['status'] ?? '') !== 'COMPLETED') {
                throw new ProcessingException('PayPal: Failed to capture payment. ' . ($response['body']['message'] ?? 'Capture not completed'));
            }

            $captureId = $response['body']['purchase_units'][0]['payments']['captures'][0]['id'] ?? null;

            return [
                'status' => 'success',
                'message' => 'PayPal payment captured successfully.',
                'transactionId' => $captureId, // This is the actual transaction/capture ID
                'orderId' => $paypalOrderId,
                'paymentStatus' => $response['body']['status'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new ProcessingException('PayPal: Capture request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['gatewayReferenceId'])) { // PayPal Order ID
            throw new VerificationException('PayPal: Missing gatewayReferenceId (Order ID) for verification.');
        }
        $paypalOrderId = $sanitizedData['gatewayReferenceId'];

        try {
            // $response = $this->httpClient('GET', $this->getApiBaseUrl() . '/v2/checkout/orders/' . $paypalOrderId, [], $this->getRequestHeaders());
            // Mocked response
            $mockStatus = 'COMPLETED';
            if ($paypalOrderId === 'fail_verify_ref'){
                 $mockStatus = 'CREATED'; // or FAILED etc.
            }
            $response = ['body' => [
                'id' => $paypalOrderId,
                'status' => $mockStatus, // e.g. CREATED, SAVED, APPROVED, VOIDED, COMPLETED
                 'purchase_units' => [
                    [
                        'reference_id' => 'YOUR_INTERNAL_ORDER_ID'
                    ]
                ]
            ], 'status_code' => 200];

            if ($response['status_code'] !== 200) {
                throw new VerificationException('PayPal: Failed to verify payment. ' . ($response['body']['message'] ?? 'API error'));
            }

            $paymentStatus = $response['body']['status'] ?? 'UNKNOWN';
            $isSuccess = strtoupper($paymentStatus) === 'COMPLETED' || strtoupper($paymentStatus) === 'APPROVED'; // Approved means funds are ready to be captured

            return [
                'status' => $isSuccess ? 'success' : (strtoupper($paymentStatus) === 'CREATED' || strtoupper($paymentStatus) === 'SAVED' || strtoupper($paymentStatus) === 'PAYER_ACTION_REQUIRED' ? 'pending' : 'failed'),
                'message' => 'PayPal verification result: ' . $paymentStatus,
                'transactionId' => null, // Order details don't have final transaction ID, capture does
                'orderId' => $response['body']['purchase_units'][0]['reference_id'] ?? $paypalOrderId,
                'paymentStatus' => $paymentStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('PayPal: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // PayPal Capture ID
            throw new RefundException('PayPal: Missing transactionId (Capture ID) for refund.');
        }

        $captureId = $sanitizedData['transactionId'];
        $payload = [
            // 'invoice_id' => 'optional_invoice_id_for_refund',
            // 'note_to_payer' => $sanitizedData['reason'] ?? 'Refund for your order.',
        ];
        if (!empty($sanitizedData['amount'])) {
            $payload['amount'] = [
                'value' => sprintf('%.2f', $sanitizedData['amount']),
                'currency_code' => strtoupper($sanitizedData['currency'] ?? 'USD') // Important: Use original currency
            ];
        }

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/v2/payments/captures/' . $captureId . '/refund', $payload, $this->getRequestHeaders());
            // Mocked response
             if (($sanitizedData['amount'] ?? 0) == 999) { 
                 throw new RefundException('PayPal: API rejected refund (simulated).');
            }
            $response = ['body' => [
                'id' => 'MOCKREFUNDID_'.strtoupper(uniqid()),
                'status' => 'COMPLETED', // or PENDING
            ], 'status_code' => 201];

            if ($response['status_code'] !== 201 || !in_array(strtoupper($response['body']['status'] ?? ''), ['COMPLETED', 'PENDING'])) {
                throw new RefundException('PayPal: Failed to process refund. ' . ($response['body']['message'] ?? 'Refund not completed'));
            }

            return [
                'status' => strtolower($response['body']['status']) === 'completed' ? 'success' : 'pending',
                'message' => 'PayPal refund status: ' . $response['body']['status'],
                'refundId' => $response['body']['id'],
                'paymentStatus' => $response['body']['status'],
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('PayPal: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 