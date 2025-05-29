<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class TwoCheckoutGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://sandbox.2checkout.com/checkout/api/1'; // Example, actual API version and URL might vary
    private const API_BASE_URL_PRODUCTION = 'https://www.2checkout.com/checkout/api/1';
    private const ORDER_CREATE_URL_SANDBOX = 'https://sandbox.2checkout.com/checkout/purchase';
    private const ORDER_CREATE_URL_PRODUCTION = 'https://www.2checkout.com/checkout/purchase';

    protected function getDefaultConfig(): array
    {
        return [
            'sellerId' => '',        // Your 2Checkout Merchant Code (Seller ID)
            'privateKey' => '',      // For API calls (if applicable for direct API integration)
            'secretWord' => '',      // For INS/IPN hash verification
            'publishableKey' => '',  // If using 2Pay.js or similar client-side tokenization
            'isSandbox' => true,
            'timeout' => 60,
        ];
    }

    protected function validateConfig(array $config): void
    {
        if (empty($config['sellerId'])) {
            throw new InvalidConfigurationException('2Checkout: sellerId is required.');
        }
        // secretWord is crucial for verifying notifications, privateKey for API actions
        if (empty($config['secretWord'])) {
            throw new InvalidConfigurationException('2Checkout: secretWord is required for INS/IPN verification.');
        }
        // Depending on the integration type (e.g., direct API vs. hosted checkout), privateKey might also be mandatory.
        // For this mock, we'll assume it's needed for refunds/verification via API.
        if (empty($config['privateKey'])) {
            throw new InvalidConfigurationException('2Checkout: privateKey is required for API operations like refunds.');
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    private function getOrderCreateBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::ORDER_CREATE_URL_SANDBOX : self::ORDER_CREATE_URL_PRODUCTION;
    }

    // Hash calculation for Pass-Through Products / Standard Checkout parameters
    // MD5(secretWord + sellerId + orderId + amount) - This is a simplified example; actual hash might differ.
    // For INS/IPN, the hash is more complex and includes more fields.
    private function generateCheckoutHash(string $orderId, string $amount): string
    {
        $stringToHash = $this->config['secretWord'] . $this->config['sellerId'] . $orderId . $amount;
        return md5($stringToHash);
    }
    
    // IPN / INS Hash Verification (simplified example, actual order of params matters)
    // The hash is calculated as an uppercase MD5 hash of the concatenated values of certain parameters IN A SPECIFIC ORDER,
    // plus your secret word. The parameters included depend on the message type.
    // Example for `ORDER_CREATED` (from 2Checkout docs for API version 6.0 - might be different for older versions or other notifications)
    // Hash = md5(SALE_ID + SALE_DATE_TIME + ORDER_REF + ORDER_TOTAL + CURRENCY + IPN_PID[] + IPN_PNAME[] + IPN_PCODE[] + IPN_PRICE[] + IPN_QTY[] + IPN_VAT[] + IPN_VAT_RATE[] + IPN_COMMISSION + SECRET_WORD)
    // This is a very simplified version for demonstration. Real implementation needs to handle various IPN message types.
    private function verifyIpnSignature(array $ipnData, string $receivedHash): bool
    {
        // For this mock, we'll simulate a simpler hash. In reality, you'd construct the string based on specific IPN fields.
        // Example: using order number (invoice_id from IPN) and sale_id
        if (empty($ipnData['invoice_id']) || empty($ipnData['sale_id'])) return false; 
        
        $stringToHash = ($ipnData['sale_id'] ?? '') . ($this->config['sellerId'] ?? '') . ($ipnData['invoice_id'] ?? '') . ($this->config['secretWord'] ?? '');
        $calculatedHash = strtoupper(md5($stringToHash)); // 2Checkout hashes are often uppercase

        if ($receivedHash === 'FAIL_2CO_SIGNATURE') return false;
        return hash_equals($calculatedHash, $receivedHash);
    }

    public function initialize(array $data): array
    {
        // 2Checkout often involves redirecting to their hosted page or using their JS library (2Pay.js).
        // This mock simulates preparing data for a redirect to their standard checkout page.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('2Checkout: Invalid or missing amount.');
        }
        if (empty($sanitizedData['currency'])) {
            throw new InitializationException('2Checkout: Missing currency code (e.g., USD).');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('2Checkout: Missing orderId (merchant_order_id).');
        }

        $orderAmount = number_format((float)$sanitizedData['amount'], 2, '.', '');

        // Parameters for the standard checkout redirect
        // Note: 2Checkout has various integration methods. This is a generic one.
        $payload = [
            'sid' => $this->config['sellerId'],
            'mode' => '2CO', // 2CO for full checkout page, IACH for inline checkout with 2Pay.js
            'li_0_type' => 'product',
            'li_0_name' => $sanitizedData['description'] ?? ('Order ' . $sanitizedData['orderId']),
            'li_0_price' => $orderAmount,
            'li_0_quantity' => 1,
            'li_0_tangible' => 'N', // 'Y' or 'N'
            'card_holder_name' => $sanitizedData['cardholderName'] ?? '',
            'street_address' => $sanitizedData['address1'] ?? '',
            'street_address2' => $sanitizedData['address2'] ?? '',
            'city' => $sanitizedData['city'] ?? '',
            'state' => $sanitizedData['state'] ?? '',
            'zip' => $sanitizedData['zipCode'] ?? '',
            'country' => $sanitizedData['countryCode'] ?? '', // Country code (e.g., USA)
            'email' => $sanitizedData['email'] ?? '',
            'phone' => $sanitizedData['phone'] ?? '',
            'merchant_order_id' => $sanitizedData['orderId'],
            'currency_code' => strtoupper($sanitizedData['currency']),
            'x_receipt_link_url' => $sanitizedData['returnUrl'] ?? 'https://example.com/2co/return', // Also used for IPN/INS if not set separately
            // 'signature' => $this->generateCheckoutHash($sanitizedData['orderId'], $orderAmount) // Might be needed depending on account settings
        ];

        // Simulate a scenario where direct API call for order creation is used (less common for init)
        if ($orderAmount == '999.00') {
            throw new InitializationException('2Checkout: API rejected payment (simulated high amount error).');
        }
        
        $paymentUrl = $this->getOrderCreateBaseUrl() . '/?' . http_build_query($payload);
        // 2Checkout transaction ID (Sale ID) is generated after payment success.
        // Here, we use the merchant_order_id as a temporary reference if needed before redirect.

        return [
            'status' => 'pending_user_action',
            'message' => '2Checkout payment initialization successful. Redirect user to complete payment.',
            'orderId' => $sanitizedData['orderId'],
            'paymentUrl' => $paymentUrl,
            'gatewayReferenceId' => null, // 2Checkout Sale ID comes later via IPN or API
            'rawData' => ['redirectParams' => $payload]
        ];
    }

    public function process(array $data): array
    {
        // This method primarily handles Instant Payment Notifications (IPN/INS) from 2Checkout.
        $sanitizedData = $this->sanitize($data); // This should be the $_POST data from 2Checkout IPN

        // Key IPN fields: invoice_id (your orderId), sale_id (2CO transaction ID), md5_hash (or signature_sha2_256)
        // message_type (e.g., ORDER_CREATED, RECURRING_INSTALLMENT_SUCCESS, FRAUD_STATUS_CHANGED)
        
        $requiredFields = ['invoice_id', 'sale_id', 'md5_hash', 'message_type']; // Simplified, real one is longer
        foreach ($requiredFields as $field) {
            if (empty($sanitizedData[$field])) {
                throw new ProcessingException("2Checkout IPN: Missing required field '{$field}'.");
            }
        }
        
        // Verify the hash (signature)
        // Note: The actual hash fields and order vary based on IPN message type and 2CO API version / account settings
        // This is a conceptual verification.
        if (!$this->verifyIpnSignature($sanitizedData, $sanitizedData['md5_hash'])) {
            throw new ProcessingException('2Checkout IPN: Hash verification failed.');
        }

        $messageType = $sanitizedData['message_type'];
        $paymentStatus = 'failed';
        $message = '2Checkout IPN received: ' . $messageType;

        // ORDER_CREATED is a common success indicator for one-time payments
        // FRAUD_STATUS_CHANGED: can be pass, fail, wait
        if ($messageType === 'ORDER_CREATED' && ($sanitizedData['fraud_status'] ?? 'fail') === 'pass') {
            $paymentStatus = 'success';
            $message = '2Checkout payment successful (IPN: ORDER_CREATED, Fraud Passed).';
        } elseif ($messageType === 'ORDER_CREATED' && ($sanitizedData['fraud_status'] ?? 'fail') === 'wait') {
            $paymentStatus = 'pending';
            $message = '2Checkout payment pending fraud review (IPN: ORDER_CREATED, Fraud Wait).';
        } elseif ($messageType === 'FRAUD_STATUS_CHANGED' && $sanitizedData['fraud_status'] === 'pass') {
            $paymentStatus = 'success';
            $message = '2Checkout fraud status approved (IPN: FRAUD_STATUS_CHANGED).';
        } elseif (str_contains($messageType, 'FAIL') || ($sanitizedData['fraud_status'] ?? '') === 'fail') {
            $paymentStatus = 'failed';
            $message = '2Checkout payment failed or fraud check failed. IPN: ' . $messageType . ', Fraud: ' . ($sanitizedData['fraud_status'] ?? 'N/A');
        }
        // Handle other message types like REFUND_ISSUED, RECURRING_*, etc.
        if ($messageType === 'REFUND_ISSUED'){
            $paymentStatus = 'refunded';
            $message = '2Checkout refund processed (IPN: REFUND_ISSUED).';
        }

        return [
            'status' => $paymentStatus,
            'message' => $message,
            'transactionId' => $sanitizedData['sale_id'], // 2Checkout Sale ID
            'orderId' => $sanitizedData['invoice_id'],    // Your merchant order ID
            'paymentStatus' => $messageType . ' (Fraud: ' . ($sanitizedData['fraud_status'] ?? 'N/A') . ')',
            'amount' => $sanitizedData['invoice_list_amount'] ?? ($sanitizedData['item_list_amount_1'] ?? null), // Example total amount field
            'currency' => $sanitizedData['list_currency'] ?? null,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        // Verification can be done using the Admin API's `detail_sale` endpoint.
        $sanitizedData = $this->sanitize($data);
        $orderId = $sanitizedData['orderId'] ?? null;
        $saleId = $sanitizedData['transactionId'] ?? null;

        if (empty($orderId) && empty($saleId)) {
            throw new VerificationException('2Checkout: Either orderId or transactionId (saleId) is required for verification.');
        }

        $requestParams = [
            'seller_id' => $this->config['sellerId'],
            // 'sale_id' => $saleId, // Use one or the other
            // 'invoice_id' => $orderId,
        ];
        if ($saleId) $requestParams['sale_id'] = $saleId;
        elseif ($orderId) $requestParams['invoice_id'] = $orderId;
        
        try {
            // $response = $this->httpClient('GET', $this->getApiBaseUrl() . '/sales/detail_sale/', $requestParams, ['Accept' => 'application/json']);
            // Mocked response for detail_sale
            if ($saleId === 'FAIL_VERIFY_2CO' || $orderId === 'FAIL_VERIFY_2CO_ORD') {
                throw new VerificationException('2Checkout: API error during verification (simulated).');
            }
            
            $mockSaleDetails = null;
            if ($saleId === '2001' || $orderId === 'ORD2001') { // Simulate success
                $mockSaleDetails = [
                    'sale' => [
                        'sale_id' => $saleId ?? '2001',
                        'invoice_id' => $orderId ?? 'ORD2001',
                        'status' => 'COMPLETE', // Could be PENDING, REFUNDED etc.
                        'payment_type' => 'cc',
                        'total' => '100.00',
                        'currency_code' => 'USD',
                        'customer' => ['email' => 'test@example.com'],
                        'invoices' => [[ // Invoices array within sale details
                            'invoice_id' => $orderId ?? 'ORD2001',
                            'status' => 'approved', // Other statuses: deposited, pending, declined
                            'list_currency' => 'USD',
                            'total' => '100.00',
                            'lineitems' => [['name' => 'Test Product', 'price' => '100.00']]
                        ]]
                    ]
                ];
            } elseif ($saleId === '2002' || $orderId === 'ORD2002') { // Simulate fraud pending
                 $mockSaleDetails = [
                    'sale' => [
                        'sale_id' => $saleId ?? '2002',
                        'invoice_id' => $orderId ?? 'ORD2002',
                        'status' => 'PENDING',
                        'invoices' => [[ 'status' => 'pending', 'total' => '50.00']]
                    ]
                ];
            } else { // Not found or other error
                 $mockSaleDetails = ['errors' => [['code' => 'NOT_FOUND', 'message' => 'Sale not found.']]];
            }

            $response = ['body' => $mockSaleDetails, 'status_code' => 200]; // Assume 200 for API call, error in body

            if ($response['status_code'] !== 200 || !empty($response['body']['errors'])) {
                $errorMsg = $response['body']['errors'][0]['message'] ?? 'Unknown API error';
                throw new VerificationException("2Checkout: Verification API call failed. Error: {$errorMsg}");
            }

            $sale = $response['body']['sale'] ?? null;
            if (!$sale || !isset($sale['invoices'][0])) {
                 throw new VerificationException("2Checkout: Invalid response structure from verification API.");
            }
            
            $invoice = $sale['invoices'][0];
            $currentStatus = 'failed';
            $message = '2Checkout verification: Sale status ' . ($sale['status'] ?? 'N/A') . ', Invoice status ' . ($invoice['status'] ?? 'N/A');

            if (($sale['status'] ?? '') === 'COMPLETE' && ($invoice['status'] ?? '') === 'approved') {
                $currentStatus = 'success';
            } elseif (($sale['status'] ?? '') === 'PENDING' || ($invoice['status'] ?? '') === 'pending') {
                $currentStatus = 'pending';
            } elseif (($sale['status'] ?? '') === 'REFUNDED') {
                $currentStatus = 'refunded';
            }

            return [
                'status' => $currentStatus,
                'message' => $message,
                'transactionId' => $sale['sale_id'] ?? $saleId,
                'orderId' => $sale['invoice_id'] ?? $orderId, // Main sale invoice_id
                'paymentStatus' => 'Sale: ' .($sale['status'] ?? 'N/A'). ' / Invoice: ' . ($invoice['status'] ?? 'N/A'),
                'amount' => $invoice['total'] ?? null,
                'currency' => $invoice['list_currency'] ?? null,
                'rawData' => $response['body']
            ];

        } catch (\Exception $e) {
            throw new VerificationException('2Checkout: Verification failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        // Refunds are done via the `create_refund` API call.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // 2Checkout Sale ID
            throw new RefundException('2Checkout: Missing transactionId (Sale ID) for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('2Checkout: Invalid or missing amount for refund.');
        }

        $payload = [
            'sale_id' => $sanitizedData['transactionId'],
            'amount' => number_format((float)$sanitizedData['amount'], 2, '.', ''),
            'currency' => 'vendor', // or 'customer' or specific currency code (USD)
            'comment' => $sanitizedData['reason'] ?? 'Merchant initiated refund.',
            'reason' => $sanitizedData['reasonCode'] ?? 'Other' // Predefined reason codes by 2Checkout
        ];

        try {
            // $headers = ['Accept' => 'application/json', 'Content-Type' => 'application/json'];
            // To use privateKey for auth (if required by endpoint, sometimes basic auth sellerId:privateKey)
            // This mock assumes auth is handled by httpClient based on config (e.g. basic auth)

            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/sales/refund_invoice/', $payload, $headers, true);
            // Mocked response
            if ($payload['amount'] == '99.99') {
                throw new RefundException('2Checkout: API rejected refund (simulated amount error).');
            }
            
            $mockRefundResponse = null;
            if ($payload['sale_id'] === 'NO_REFUND_SALE'){
                $mockRefundResponse = ['errors' => [['code' => 'NOT_ALLOWED', 'message' => 'Refund not allowed for this sale.']]];
            } else {
                $mockRefundResponse = ['response_code' => 'OK', 'response_message' => 'Refund request successfully submitted.'];
            }
            
            $response = ['body' => $mockRefundResponse, 'status_code' => 200];

            if ($response['status_code'] !== 200 || !empty($response['body']['errors'])) {
                $errorMsg = $response['body']['errors'][0]['message'] ?? ($response['body']['response_message'] ?? 'Unknown API error');
                throw new RefundException("2Checkout: Refund API call failed. Error: {$errorMsg}");
            }

            if (strtoupper($response['body']['response_code'] ?? '') !== 'OK') {
                throw new RefundException('2Checkout: Refund request submission failed. Message: ' . ($response['body']['response_message'] ?? 'Unknown reason'));
            }
            
            // Refunds are usually processed asynchronously. IPN will confirm final status.
            return [
                'status' => 'pending', // Or 'success' if API confirms immediate refund processing
                'message' => '2Checkout refund request submitted successfully. Status will be confirmed via IPN.',
                'refundId' => $sanitizedData['refundId'] ?? 'REF_' . $sanitizedData['transactionId'] . time(), // Your internal refund ID
                'gatewayReferenceId' => $sanitizedData['transactionId'], // Original sale ID
                'paymentStatus' => 'REFUND_PENDING', // Custom status or from API if available
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('2Checkout: Refund failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 