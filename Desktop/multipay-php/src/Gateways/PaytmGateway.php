<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class PaytmGateway extends PaymentGateway
{
    // Note: Paytm has different APIs (JS Checkout, Custom Checkout, etc.)
    // This mock will be generic for a server-side flow leading to a redirect.
    private const API_BASE_URL_STAGING = 'https://securegw-stage.paytm.in';
    private const API_BASE_URL_PRODUCTION = 'https://securegw.paytm.in';

    protected function getDefaultConfig(): array
    {
        return [
            'merchantId' => '', // MID
            'merchantKey' => '',
            'websiteName' => 'WEBSTAGING', // Or your production website name
            'industryTypeId' => 'Retail', // As provided by Paytm
            'channelId' => 'WEB', // WEB or WAP
            'isSandbox' => true,
            'callbackUrl' => 'https://example.com/paytm/callback',
            'timeout' => 45,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['merchantId', 'merchantKey', 'websiteName', 'industryTypeId'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("Paytm: {$key} is required.");
            }
        }
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_STAGING : self::API_BASE_URL_PRODUCTION;
    }

    /**
     * Generate Paytm checksum (old method, new is JWT based or different for new APIs).
     * This is a simplified placeholder for SHA256 based checksum.
     * Paytm provides SDKs/libraries for checksum generation which should be used.
     */
    private function generateChecksum(array $params): string
    {
        ksort($params);
        $paramString = "";
        foreach($params as $key => $value) {
            if ($value == "" || $value == "null") continue; // Skip empty or null values
            $paramString .= $value . "|"; // Or just concatenate, check Paytm docs
        }
        $paramString = rtrim($paramString, '|');
        return hash("sha256", $paramString . $this->config['merchantKey']);
        // For actual implementation, refer to Paytm's official checksum utility.
    }

    /**
     * Verify Paytm checksum for callback.
     */
    private function verifyChecksum(array $params, string $receivedChecksum): bool
    {
        // $generatedChecksum = $this->generateChecksum($params); // Careful: Paytm callback might have fields not in original request
        // return $generatedChecksum === $receivedChecksum;
        // Placeholder, always consult Paytm docs for callback checksum verification.
        if ($receivedChecksum === 'FAIL_CHECKSUM') return false;
        return true; // Mock as true
    }

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Paytm: Invalid or missing amount.');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('Paytm: Missing orderId.');
        }
        if (empty($sanitizedData['customerId'])) {
            throw new InitializationException('Paytm: Missing customerId.');
        }

        $orderId = $sanitizedData['orderId'];
        $txnAmount = sprintf('%.2f', $sanitizedData['amount']);

        $payload = [
            'MID' => $this->config['merchantId'],
            'WEBSITE' => $this->config['websiteName'],
            'INDUSTRY_TYPE_ID' => $this->config['industryTypeId'],
            'CHANNEL_ID' => $this->config['channelId'],
            'ORDER_ID' => $orderId,
            'CUST_ID' => $sanitizedData['customerId'],
            'TXN_AMOUNT' => $txnAmount,
            'CALLBACK_URL' => $sanitizedData['callbackUrl'] ?? $this->config['callbackUrl'],
            'EMAIL' => $sanitizedData['email'] ?? null,
            'MOBILE_NO' => $sanitizedData['mobileNumber'] ?? null,
        ];

        // Remove null values before checksum generation as Paytm might ignore them
        $checksumParams = array_filter($payload, fn($value) => $value !== null && $value !== '');
        $payload['CHECKSUMHASH'] = $this->generateChecksum($checksumParams);

        // For JS Checkout, you'd get a transaction token here via a different API
        // For server-side redirect (older method), you build a form and POST to Paytm.

        // This simulates a direct API call that returns a redirect URL or parameters for a form post
        // In reality, for non-JS checkout, you usually construct an HTML form and auto-submit it.
        try {
             if ($txnAmount == '999.00') { 
                 throw new InitializationException('Paytm: API rejected initialization (simulated).');
            }
            $paymentUrl = $this->getApiBaseUrl() . '/theia/processTransaction'; // Standard Paytm endpoint

            return [
                'status' => 'pending_user_action',
                'message' => 'Paytm payment requires user redirection. Submit the form provided.',
                'paymentUrl' => $paymentUrl, // This is the URL to POST the form to
                'formData' => $payload,      // These are the fields for the auto-submitting form
                'gatewayReferenceId' => $orderId, // ORDER_ID is the primary ref here
                'rawData' => ['formAction' => $paymentUrl, 'formFields' => $payload]
            ];
        } catch (\Exception $e) {
            throw new InitializationException('Paytm: Initialization request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // Process for Paytm means handling the callback (POST request from Paytm to your CALLBACK_URL).
        $sanitizedData = $this->sanitize($data); // $data is typically $_POST from Paytm

        if (empty($sanitizedData['ORDERID']) || empty($sanitizedData['MID'])) {
            throw new ProcessingException('Paytm: Invalid callback data. Missing ORDERID or MID.');
        }
        if ($sanitizedData['MID'] !== $this->config['merchantId']) {
            throw new ProcessingException('Paytm: Merchant ID mismatch in callback.');
        }

        $receivedChecksum = $sanitizedData['CHECKSUMHASH'] ?? '';
        unset($sanitizedData['CHECKSUMHASH']); // Remove checksum before verifying

        // if (!$this->verifyChecksum($sanitizedData, $receivedChecksum)) {
        //     throw new ProcessingException('Paytm: Callback checksum mismatch.');
        // }

        $status = $sanitizedData['STATUS'] ?? 'TXN_FAILURE';
        $isSuccess = $status === 'TXN_SUCCESS';

        return [
            'status' => $isSuccess ? 'success' : 'failed',
            'message' => 'Paytm payment processed. Status: ' . $status . ' - ' . ($sanitizedData['RESPMSG'] ?? ''),
            'transactionId' => $sanitizedData['TXNID'] ?? null, // Paytm's transaction ID
            'orderId' => $sanitizedData['ORDERID'],
            'amount' => $sanitizedData['TXNAMOUNT'] ?? null,
            'paymentStatus' => $status,
            'bankTransactionId' => $sanitizedData['BANKTXNID'] ?? null,
            'paymentMode' => $sanitizedData['PAYMENTMODE'] ?? null,
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['orderId'])) {
            throw new VerificationException('Paytm: Missing orderId for verification.');
        }

        $payload = [
            'MID' => $this->config['merchantId'],
            'ORDERID' => $sanitizedData['orderId'],
        ];
        $payload['CHECKSUMHASH'] = $this->generateChecksum($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/oltp/HANDLER_INTERNAL/TXNSTATUS', $payload, ['Content-Type' => 'application/x-www-form-urlencoded']);
            // Mocked Response (Paytm status API returns JSON)
            $mockStatus = 'TXN_SUCCESS';
            $mockTxnId = 'PAYTMTXN' . strtoupper(uniqid());
            if ($sanitizedData['orderId'] === 'fail_verify') {
                $mockStatus = 'TXN_FAILURE'; $mockTxnId = null;
            } else if ($sanitizedData['orderId'] === 'pending_verify') {
                 $mockStatus = 'PENDING';
            }
            
            $response = ['body' => [
                    'MID' => $this->config['merchantId'],
                    'ORDERID' => $sanitizedData['orderId'],
                    'TXNAMOUNT' => $sanitizedData['original_amount_for_test'] ?? '100.00',
                    'TXNID' => $mockTxnId,
                    'STATUS' => $mockStatus,
                    'RESPCODE' => ($mockStatus === 'TXN_SUCCESS' ? '01' : ($mockStatus === 'PENDING' ? '296' : '330')),
                    'RESPMSG' => 'Status query successful'
                ],
                'status_code' => 200
            ];

            // Note: Real Paytm status API might not have a top-level 'status_code' like other JSON APIs.
            // Check based on RESPCODE or STATUS field.
            if (empty($response['body']['STATUS'])) {
                throw new VerificationException('Paytm: Failed to verify payment. Invalid API response.');
            }

            $paymentStatus = $response['body']['STATUS'];
            $isSuccess = $paymentStatus === 'TXN_SUCCESS';
            $isPending = $paymentStatus === 'PENDING';

            return [
                'status' => $isSuccess ? 'success' : ($isPending ? 'pending' : 'failed'),
                'message' => 'Paytm verification result: ' . $paymentStatus . ' - ' . ($response['body']['RESPMSG'] ?? ''),
                'transactionId' => $response['body']['TXNID'] ?? null,
                'orderId' => $response['body']['ORDERID'] ?? null,
                'paymentStatus' => $paymentStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('Paytm: Verification request failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Paytm's TXNID
            throw new RefundException('Paytm: Missing transactionId (TXNID) for refund.');
        }
        if (empty($sanitizedData['orderId'])) { 
            throw new RefundException('Paytm: Missing orderId for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Paytm: Invalid or missing amount for refund.');
        }

        $refundId = $sanitizedData['refundId'] ?? ('REFUND_' . $sanitizedData['orderId'] . '_' . time());
        $refundAmount = sprintf('%.2f', $sanitizedData['amount']);

        $payload = [
            'MID' => $this->config['merchantId'],
            'ORDERID' => $sanitizedData['orderId'], // Original Order ID
            'TXNID' => $sanitizedData['transactionId'], // Original Transaction ID
            'REFID' => $refundId, // Your unique refund ID
            'TXNTYPE' => 'REFUND',
            'REFUNDAMOUNT' => $refundAmount,
        ];
        $payload['CHECKSUMHASH'] = $this->generateChecksum($payload);

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/oltp/HANDLER_INTERNAL/REFUND', $payload, ['Content-Type' => 'application/x-www-form-urlencoded']);
            // Mocked response
            if ($refundAmount == '999.00') { 
                 throw new RefundException('Paytm: API rejected refund (simulated).');
            }
            $response = ['body' => [
                    'MID' => $this->config['merchantId'],
                    'ORDERID' => $sanitizedData['orderId'],
                    'TXNID' => $sanitizedData['transactionId'],
                    'REFID' => $refundId,
                    'STATUS' => 'TXN_SUCCESS', // Can be PENDING as well
                    'RESPCODE' => '10', // Refund success code
                    'RESPMSG' => 'Refund request accepted successfully' 
                ],
                'status_code' => 200 // Mocked, actual API might not conform to this structure directly
            ];

            if (empty($response['body']['STATUS']) || ($response['body']['RESPCODE'] !== '10' && $response['body']['RESPCODE'] !== '600' /* Pending code example */)) {
                throw new RefundException('Paytm: Failed to process refund. API Error: ' . ($response['body']['RESPMSG'] ?? 'Unknown error'));
            }

            $refundApiStatus = $response['body']['STATUS'];
            $isSuccess = $refundApiStatus === 'TXN_SUCCESS';
            $isPending = ($response['body']['RESPCODE'] ?? '') === '600' || strpos(strtoupper($refundApiStatus), 'PENDING') !== false;

            return [
                'status' => $isSuccess ? 'success' : ($isPending ? 'pending' : 'failed'),
                'message' => 'Paytm refund status: ' . $refundApiStatus . ' - ' . ($response['body']['RESPMSG'] ?? ''),
                'refundId' => $refundId,
                'transactionId' => $response['body']['TXNID'] ?? null, // Original TXNID
                'paymentStatus' => $refundApiStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Paytm: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 