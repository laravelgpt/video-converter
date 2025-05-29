<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class PortWalletGateway extends PaymentGateway
{
    // PortWallet API Host URLs
    private const API_HOST_SANDBOX = 'https://payment-sandbox.portwallet.com';
    private const API_HOST_PRODUCTION = 'https://payment.portwallet.com';

    // PortWallet API Endpoints
    private const ENDPOINT_CREATE_INVOICE = '/payment/request/create/';
    private const ENDPOINT_VERIFY_PAYMENT = '/payment/request/verify/'; // Note: {invoice_id} needs to be appended
    private const ENDPOINT_REFUND = '/payment/request/refund/';
    private const ENDPOINT_INVOICE_REDIRECT_PAGE = '/payment/request/invoice/'; // Note: {invoice_id} needs to be appended for user redirection


    protected function getDefaultConfig(): array
    {
        return [
            'app_key' => '',          // Your PortWallet App Key
            'secret_key' => '',       // Your PortWallet Secret Key
            'isSandbox' => true,
            'currency' => 'BDT',
            'redirect_url' => 'https://example.com/portwallet/return', // User returns here after payment attempt
            'ipn_url' => 'https://example.com/portwallet/ipn',       // IPN listener URL
            'timeout' => 60,
            'product_description' => 'Payment for Order',
        ];
    }

    protected function validateConfig(array $config): void
    {
        if (empty($config['app_key'])) {
            throw new InvalidConfigurationException('PortWallet: app_key is required.');
        }
        if (empty($config['secret_key'])) {
            throw new InvalidConfigurationException('PortWallet: secret_key is required.');
        }
    }

    private function getApiHost(): string
    {
        return $this->config['isSandbox'] ? self::API_HOST_SANDBOX : self::API_HOST_PRODUCTION;
    }

    private function getCreateInvoiceUrl(): string
    {
        return $this->getApiHost() . self::ENDPOINT_CREATE_INVOICE;
    }
    
    private function getVerifyPaymentBaseUrl(): string
    {
        return $this->getApiHost() . self::ENDPOINT_VERIFY_PAYMENT;
    }
    
    private function getRefundApiUrl(): string
    {
        return $this->getApiHost() . self::ENDPOINT_REFUND;
    }

    private function getInvoiceRedirectPageUrl(string $invoiceId): string
    {
        return $this->getApiHost() . self::ENDPOINT_INVOICE_REDIRECT_PAGE . $invoiceId;
    }

    // PortWallet uses a token generated from app_key and secret_key for API authentication.
    // Authorization: Bearer base64_encode(app_key:sha256(secret_key))
    private function generateAuthToken(): string
    {
        return base64_encode($this->config['app_key'] . ':' . hash('sha256', $this->config['secret_key']));
    }
    
    // Generate IPN signature if applicable (PortWallet might use token auth for IPN validation call instead of request hash)
    // If they do use a hash for IPN data itself, it would be documented.
    // For this mock, we'll rely on the IPN validation call rather than hashing IPN POST data.

    public function initialize(array $data): array
    {
        // Creates an invoice/payment request with PortWallet, gets a redirect URL.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) { // unique order_id for merchant
            throw new InitializationException('PortWallet: Missing orderId.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('PortWallet: Invalid or missing amount.');
        }

        $payload = [
            'order_id' => $sanitizedData['orderId'],
            'amount' => (float)$sanitizedData['amount'],
            'currency' => $sanitizedData['currency'] ?? $this->config['currency'],
            'redirect_url' => $sanitizedData['redirect_url'] ?? $this->config['redirect_url'],
            'ipn_url' => $sanitizedData['ipn_url'] ?? $this->config['ipn_url'],
            'name' => $sanitizedData['customerName'] ?? 'N/A',
            'email' => $sanitizedData['customerEmail'] ?? 'noreply@example.com',
            'phone' => $sanitizedData['customerPhone'] ?? 'N/A',
            'address' => $sanitizedData['customerAddress1'] ?? 'N/A',
            'city' => $sanitizedData['customerCity'] ?? 'N/A',
            'country' => $sanitizedData['customerCountry'] ?? 'BD',
            'description' => $sanitizedData['description'] ?? $this->config['product_description'] . ' ' . $sanitizedData['orderId'],
            // Optional custom parameters: product_name, emi (0 or 1), custom1, custom2 etc.
            'custom1' => $sanitizedData['customParam1'] ?? '',
            'custom2' => $sanitizedData['customParam2'] ?? '',
            // 'discount' => 0, // Optional discount amount
        ];

        $headers = [
            'Authorization' => 'Bearer ' . $this->generateAuthToken(),
            'Content-Type' => 'application/json',
            'Accept' => 'application/json'
        ];

        try {
            // $responseJson = $this->httpClient('POST', $this->getCreateInvoiceUrl(), json_encode($payload), $headers);
            // $response = json_decode($responseJson, true);
            // Mocked Response
            $mockResponse = [];
            if ($payload['amount'] == 9999.99) { 
                $mockResponse = ['status' => 'error', 'message' => 'Insufficient balance or invalid amount for testing.', 'data' => null];
            } elseif ($payload['order_id'] === 'FAIL_PW_INIT') {
                $mockResponse = ['status' => 'error', 'message' => 'Simulated PortWallet initialization failure.', 'data' => null];
            } else {
                $invoiceId = 'PW' . strtoupper(uniqid()) . substr($payload['order_id'], -4);
                $mockResponse = [
                    'status' => 'success',
                    'message' => 'Invoice created successfully',
                    'data' => [
                        'invoice_id' => $invoiceId,
                        'redirect_url' => $this->getInvoiceRedirectPageUrl($invoiceId),
                        // Other details like 'created_at', 'amount', 'currency' might be in data array
                    ]
                ];
            }
            $response = $mockResponse;
            // End Mock

            if (!$response || $response['status'] !== 'success' || empty($response['data']['redirect_url'])) {
                $errorMsg = $response['message'] ?? (is_array($response['data'] ?? null) ? json_encode($response['data']) : ($response['data'] ?? 'Unknown error from PortWallet'));
                throw new InitializationException('PortWallet: Failed to create invoice. ' . $errorMsg);
            }

            return [
                'status' => 'pending_user_redirect',
                'message' => 'PortWallet invoice created. Redirect user to payment page.',
                'paymentUrl' => $response['data']['redirect_url'],
                'invoiceId' => $response['data']['invoice_id'], // PortWallet's invoice ID
                'orderId' => $payload['order_id'],
                'gatewayReferenceId' => $response['data']['invoice_id'],
                'rawData' => $response
            ];
        } catch (\Exception $e) {
            if ($e instanceof InitializationException) throw $e;
            throw new InitializationException('PortWallet: Payment initialization failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // Processes IPN callback from PortWallet (POST data to ipn_url)
        // PortWallet recommends validating IPN by calling their /payment/request/verify/{invoice_id} endpoint.
        // The POSTed data itself might not have a signature, or if it does, it should be verified.
        $sanitizedData = $this->sanitize($data); // This is $_POST from PortWallet IPN

        // Key fields from PortWallet IPN: invoice_id, order_id, amount, currency, status, card_brand, etc.
        if (empty($sanitizedData['invoice_id']) || empty($sanitizedData['order_id']) || empty($sanitizedData['status'])) {
            throw new ProcessingException('PortWallet IPN: Invalid data. Missing invoice_id, order_id, or status.');
        }

        // Instead of relying on IPN data directly for final status (as it could be spoofed without a signature here),
        // it's best practice to use the `verify` method (which calls the IPN validation endpoint) to confirm.
        // However, this `process` method can provide an initial interpretation.

        $invoiceId = $sanitizedData['invoice_id'];
        $orderId = $sanitizedData['order_id'];
        $paymentStatus = strtoupper($sanitizedData['status']); // e.g., COMPLETED, PENDING, FAILED, CANCELLED, REJECTED
        $message = 'PortWallet IPN status: ' . $paymentStatus;
        $finalStatus = 'failed';

        if ($paymentStatus === 'COMPLETED') {
            $finalStatus = 'success';
        } elseif ($paymentStatus === 'PENDING') {
            $finalStatus = 'pending';
        } elseif (in_array($paymentStatus, ['FAILED', 'CANCELLED', 'REJECTED', 'EXPIRED'])){
            $finalStatus = 'failed';
            if ($paymentStatus === 'CANCELLED') $message = 'PortWallet: User cancelled payment.';
            else $message .= ' Reason: ' . ($sanitizedData['reason'] ?? 'N/A');
        }
        
        if (($sanitizedData['risk_status'] ?? '') === 'SIMULATE_PW_PROCESS_FAIL'){
            $finalStatus = 'failed';
            $message = 'PortWallet IPN: Simulated processing failure due to risk status.';
        }

        // Respond to PortWallet IPN with HTTP 200 OK if received, after logging/processing.

        return [
            'status' => $finalStatus,
            'message' => $message,
            'transactionId' => $invoiceId, // PortWallet invoice_id is the main reference
            'orderId' => $orderId,
            'paymentStatus' => $paymentStatus,
            'amount' => $sanitizedData['amount'] ?? null,
            'cardType' => $sanitizedData['card_brand'] ?? ($sanitizedData['pg_gateway'] ?? null), // e.g. VISA, MASTER, BKASH
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        // Calls PortWallet's IPN Validation API: /payment/request/verify/{invoice_id}
        $sanitizedData = $this->sanitize($data);
        $invoiceId = $sanitizedData['invoiceId'] ?? $sanitizedData['transactionId'] ?? null;

        if (empty($invoiceId)) {
            throw new VerificationException('PortWallet: invoiceId is required for verification.');
        }

        $headers = [
            'Authorization' => 'Bearer ' . $this->generateAuthToken(),
            'Accept' => 'application/json'
        ];
        $validationUrl = $this->getVerifyPaymentBaseUrl() . $invoiceId . '/'; // As per PortWallet docs, trailing slash might be needed for GET

        try {
            // $responseJson = $this->httpClient('GET', $validationUrl, [], $headers);
            // $response = json_decode($responseJson, true);
            // Mocked Response
            $mockResponse = [];
            if ($invoiceId === 'FAIL_PW_VERIFY_API') {
                 $mockResponse = ['status' => 'error', 'message' => 'Simulated API error during verification', 'data' => null];
            }
            elseif (strpos($invoiceId, 'PW_COMPLETED') !== false) {
                 $mockResponse = [
                    'status' => 'success',
                    'message' => 'Invoice data found',
                    'data' => [
                        'invoice_id' => $invoiceId, 'order_id' => 'ORD_FOR_'.$invoiceId,
                        'status' => 'COMPLETED', 'amount' => '100.00', 'currency' => 'BDT',
                        'card_brand' => 'VISA', 'pg_gateway' => 'BRAC_VISA',
                        'created_at' => date('Y-m-d H:i:s'), 'customer_name' => 'Test User'
                        // ... other details like customer email, phone etc.
                    ]
                 ];
            } elseif (strpos($invoiceId, 'PW_PENDING') !== false) {
                 $mockResponse = ['status' => 'success', 'message' => 'Invoice data found', 'data' => ['invoice_id' => $invoiceId, 'order_id' => 'ORD_PEND', 'status' => 'PENDING', 'amount' => '50.00']];
            } elseif (strpos($invoiceId, 'PW_FAILED') !== false) {
                $mockResponse = ['status' => 'success', 'message' => 'Invoice data found', 'data' => ['invoice_id' => $invoiceId, 'order_id' => 'ORD_FAIL', 'status' => 'FAILED', 'reason' => 'Insufficient funds']];
            } else { // Not found or other error
                $mockResponse = ['status' => 'error', 'message' => 'Invoice not found or an error occurred', 'data' => null];
            }
            $response = $mockResponse;
            // End Mock

            if (!$response || $response['status'] !== 'success' || empty($response['data'])) {
                throw new VerificationException('PortWallet Verify: Failed to retrieve transaction details. ' . ($response['message'] ?? 'Unknown API error.'));
            }

            $responseData = $response['data'];
            $paymentApiStatus = strtoupper($responseData['status'] ?? 'ERROR');
            $finalStatus = 'failed';

            if ($paymentApiStatus === 'COMPLETED') {
                $finalStatus = 'success';
            } elseif ($paymentApiStatus === 'PENDING') {
                $finalStatus = 'pending';
            }
            
            return [
                'status' => $finalStatus,
                'message' => 'PortWallet Verify Status: ' . $paymentApiStatus . '. ' . ($responseData['reason'] ?? ($response['message'] ?? '')),
                'transactionId' => $responseData['invoice_id'] ?? null,
                'orderId' => $responseData['order_id'] ?? null,
                'paymentStatus' => $paymentApiStatus,
                'amount' => $responseData['amount'] ?? null,
                'cardType' => $responseData['card_brand'] ?? ($responseData['pg_gateway'] ?? null),
                'rawData' => $response
            ];
        } catch (\Exception $e) {
            if ($e instanceof VerificationException) throw $e;
            throw new VerificationException('PortWallet: Transaction verification failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['invoiceId'])) { // PortWallet's invoice_id
            throw new RefundException('PortWallet: invoiceId is required for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('PortWallet: Invalid refund amount.');
        }

        $payload = [
            'invoice_id' => $sanitizedData['invoiceId'],
            'amount' => (float)$sanitizedData['amount'],
            'reason' => $sanitizedData['reason'] ?? 'Merchant requested refund',
            'refund_id' => $sanitizedData['refundId'] ?? ('PWREF' . uniqid()) // Your unique ID for this refund request
        ];

        $headers = [
            'Authorization' => 'Bearer ' . $this->generateAuthToken(),
            'Content-Type' => 'application/json',
            'Accept' => 'application/json'
        ];

        try {
            // $responseJson = $this->httpClient('POST', $this->getRefundApiUrl(), json_encode($payload), $headers);
            // $response = json_decode($responseJson, true);
            // Mocked Response
            $mockResponse = [];
            if ($payload['amount'] == 99.98) {
                $mockResponse = ['status' => 'error', 'message' => 'Refund amount exceeds allowed limit (simulated).', 'data' => null];
            } elseif ($payload['invoice_id'] === 'PW_INV_NO_REFUND') {
                 $mockResponse = ['status' => 'error', 'message' => 'Transaction not eligible for refund (simulated).', 'data' => ['status' => 'REJECTED']];
            } else {
                $mockResponse = [
                    'status' => 'success',
                    'message' => 'Refund request submitted successfully',
                    'data' => [
                        'invoice_id' => $payload['invoice_id'],
                        'refund_id' => $payload['refund_id'],
                        'status' => 'PENDING', // Or PROCESSING, COMPLETED depending on PortWallet flow
                        'amount' => $payload['amount'],
                        'message' => 'Refund is being processed.'
                    ]
                ];
            }
            $response = $mockResponse;
            // End Mock

            if (!$response || $response['status'] !== 'success' || empty($response['data'])) {
                 throw new RefundException('PortWallet Refund: Failed. ' . ($response['message'] ?? 'Unknown error from refund API.'));
            }

            $refundData = $response['data'];
            $refundApiStatus = strtoupper($refundData['status'] ?? 'ERROR');
            $finalStatus = 'failed';

            if (in_array($refundApiStatus, ['COMPLETED', 'REFUNDED'])) {
                $finalStatus = 'success';
            } elseif (in_array($refundApiStatus, ['PENDING', 'PROCESSING', 'SUBMITTED'])) {
                $finalStatus = 'pending';
            }

            return [
                'status' => $finalStatus,
                'message' => 'PortWallet Refund: ' . ($refundData['message'] ?? $refundApiStatus),
                'refundId' => $refundData['refund_id'] ?? $payload['refund_id'],
                'transactionId' => $refundData['invoice_id'] ?? null,
                'paymentStatus' => 'REFUND_' . $refundApiStatus,
                'amount' => $refundData['amount'] ?? null,
                'rawData' => $response
            ];
        } catch (\Exception $e) {
            if ($e instanceof RefundException) throw $e;
            throw new RefundException('PortWallet: Refund processing failed. ' . $e->getMessage(), 0, $e);
        }
    }
}
