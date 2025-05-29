<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class PayFastGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://sandbox.payfast.co.za';
    private const API_BASE_URL_PRODUCTION = 'https://www.payfast.co.za';
    private const PROCESS_PATH = '/eng/process'; // For redirecting the user
    private const ITN_VALIDATE_PATH_SANDBOX = '/eng/query/validate'; // Sandbox ITN validation
    private const ITN_VALIDATE_PATH_PRODUCTION = '/eng/query/validate'; // Production ITN validation (can be same as sandbox path, but on www host)


    protected function getDefaultConfig(): array
    {
        return [
            'merchantId' => '',      // Your PayFast Merchant ID
            'merchantKey' => '',     // Your PayFast Merchant Key
            'passphrase' => '',      // Optional: Your PayFast Passphrase for signature generation/validation
            'isSandbox' => true,
            'timeout' => 60,
            'defaultReturnUrl' => 'https://example.com/payfast/return',
            'defaultCancelUrl' => 'https://example.com/payfast/cancel',
            'defaultNotifyUrl' => 'https://example.com/payfast/notify', // ITN URL
        ];
    }

    protected function validateConfig(array $config): void
    {
        if (empty($config['merchantId'])) {
            throw new InvalidConfigurationException('PayFast: merchantId is required.');
        }
        if (empty($config['merchantKey'])) {
            throw new InvalidConfigurationException('PayFast: merchantKey is required.');
        }
        // Passphrase is not strictly required for basic integration but IS for signature validation (highly recommended)
    }

    private function getApiBaseUrl(bool $forItnValidation = false): string
    {
        if ($this->config['isSandbox']) {
            return self::API_BASE_URL_SANDBOX;
        }
        // For ITN validation, PayFast documentation sometimes implies using www.payfast.co.za even if the main calls might go elsewhere for specific products.
        // However, the /eng/query/validate path is usually relative to the main host.
        return self::API_BASE_URL_PRODUCTION;
    }

    private function generateSignature(array $data, string $passphrase = null): string
    {
        $passphraseToUse = $passphrase ?? $this->config['passphrase'] ?? '';
        
        // Create URL encoded query string
        $queryString = http_build_query($data);
        if (!empty($passphraseToUse)) {
            $queryString .= '&passphrase=' . urlencode($passphraseToUse);
        }
        return md5($queryString);
    }

    public function initialize(array $data): array
    {
        // This prepares data for a redirect to PayFast's payment page.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('PayFast: Invalid or missing amount. Amount in ZAR (or other supported currency).');
        }
        if (empty($sanitizedData['orderId'])) { // m_payment_id
            throw new InitializationException('PayFast: Missing orderId (m_payment_id).');
        }
        if (empty($sanitizedData['itemName'])) {
            throw new InitializationException('PayFast: Missing itemName.');
        }

        $payload = [
            'merchant_id' => $this->config['merchantId'],
            'merchant_key' => $this->config['merchantKey'],
            'return_url' => $sanitizedData['returnUrl'] ?? $this->config['defaultReturnUrl'],
            'cancel_url' => $sanitizedData['cancelUrl'] ?? $this->config['defaultCancelUrl'],
            'notify_url' => $sanitizedData['notifyUrl'] ?? $this->config['defaultNotifyUrl'],

            'm_payment_id' => $sanitizedData['orderId'],
            'amount' => number_format((float)$sanitizedData['amount'], 2, '.', ''),
            'item_name' => $sanitizedData['itemName'],
            'item_description' => $sanitizedData['description'] ?? $sanitizedData['itemName'],
            
            // Optional customer details
            'name_first' => $sanitizedData['firstName'] ?? '',
            'name_last' => $sanitizedData['lastName'] ?? '',
            'email_address' => $sanitizedData['email'] ?? '',
            // 'cell_number' => $sanitizedData['phone'] ?? '',

            // Optional: subscription type for recurring billing (e.g., 'subscription')
            // 'subscription_type' => $sanitizedData['subscriptionType'] ?? '',
            // If subscription, other params like frequency, cycles etc. are needed.

            // 'email_confirmation' => '1',
            // 'confirmation_address' => $this->config['merchantEmailForConfirmation'] ?? '',
        ];
        
        // Add custom fields (up to 5: custom_str1-5, custom_int1-5)
        if(isset($sanitizedData['custom_str1'])) $payload['custom_str1'] = $sanitizedData['custom_str1'];

        // Generate signature if passphrase is set
        if (!empty($this->config['passphrase'])) {
            // Create a temporary array without merchant_key for signature generation, as per PayFast docs (key is not part of signed data)
            $signablePayload = $payload; // Copy payload
            // PayFast docs sometimes say to sign ALL data EXCEPT signature itself.
            // Other times it says to NOT include merchant_key.
            // Let's exclude merchant_key for signature generation for this mock.
            // A common practice is to sort the array by key before generating the query string for the signature.
            // ksort($signablePayload);
            $payload['signature'] = $this->generateSignature($signablePayload, $this->config['passphrase']);
        }

        // Simulate an error if amount is specific value
        if ($payload['amount'] == '9999.00') {
            throw new InitializationException('PayFast: Simulated error during payment variables preparation.');
        }

        $paymentUrl = ($this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION) . self::PROCESS_PATH;
        // The payload will be POSTed to this URL by the user's browser, typically via a form.
        // This `initialize` method will return the URL and the payload to build that form.

        return [
            'status' => 'pending_user_action',
            'message' => 'PayFast payment initialization successful. Prepare a form to POST data to PayFast.',
            'paymentUrl' => $paymentUrl, // URL to POST the form to
            'formData' => $payload,    // Data to be included as hidden fields in the form
            'orderId' => $sanitizedData['orderId'],
            'gatewayReferenceId' => null, // PayFast pf_payment_id comes via ITN
            'rawData' => ['formAction' => $paymentUrl, 'formFields' => $payload]
        ];
    }

    public function process(array $data): array
    {
        // This processes the Instant Transaction Notification (ITN) from PayFast.
        // $data here is the $_POST data from PayFast.
        $sanitizedData = $this->sanitize($data); // ITN data $_POST

        // 1. Verify the source of the ITN (optional, by checking remote IP if possible/reliable)

        // 2. Validate the data by sending it back to PayFast
        $validationPayload = [];
        foreach ($sanitizedData as $key => $value) { // Rebuild payload as PayFast expects
            $validationPayload[$key] = stripslashes($value);
        }

        $itnValidationUrl = ($this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION) .
                              ($this->config['isSandbox'] ? self::ITN_VALIDATE_PATH_SANDBOX : self::ITN_VALIDATE_PATH_PRODUCTION);
        
        try {
            // $validationResponse = $this->httpClient('POST', $itnValidationUrl, $validationPayload, ['Content-Type' => 'application/x-www-form-urlencoded']);
            // Mocked ITN Validation Response
            $mockValidationResponse = 'INVALID';
            if (!empty($sanitizedData['pf_payment_id']) && $sanitizedData['pf_payment_id'] !== 'FAIL_ITN_VALIDATION') {
                // Simulate signature check if passphrase was used
                if (!empty($this->config['passphrase'])) {
                    $receivedSignature = $sanitizedData['signature'] ?? '';
                    $payloadForSignature = $sanitizedData; // Full ITN data as received
                    unset($payloadForSignature['signature']); // Remove signature itself from data to be signed
                    // ksort($payloadForSignature);
                    $expectedSignature = $this->generateSignature($payloadForSignature, $this->config['passphrase']);
                    if (hash_equals($expectedSignature, $receivedSignature)) {
                        $mockValidationResponse = 'VALID';
                    } else {
                        $mockValidationResponse = 'INVALID_SIGNATURE'; // Custom mock status
                    }
                } else {
                     $mockValidationResponse = 'VALID'; // If no passphrase, assume ITN is valid if it came from PayFast
                }
            }
             if (($sanitizedData['custom_str1'] ?? '') === 'FORCE_ITN_INVALID') $mockValidationResponse = 'INVALID';


            $response = ['body' => $mockValidationResponse, 'status_code' => 200]; // httpClient usually returns array, this is simplified

            if ($response['status_code'] !== 200 || trim($response['body']) !== 'VALID') {
                $reason = 'ITN validation failed.';
                if (trim($response['body']) === 'INVALID_SIGNATURE') $reason = 'ITN signature mismatch.';
                elseif (trim($response['body']) !== 'VALID') $reason .= ' Response: ' . $response['body'];
                throw new ProcessingException('PayFast ITN: ' . $reason);
            }

            // 3. Check payment_status
            $paymentStatus = strtolower($sanitizedData['payment_status'] ?? '');
            $finalStatus = 'failed';
            $message = 'PayFast ITN received. Payment Status: ' . $paymentStatus;

            if ($paymentStatus === 'complete') {
                $finalStatus = 'success';
            } elseif ($paymentStatus === 'failed') {
                $finalStatus = 'failed';
            } elseif ($paymentStatus === 'pending') {
                $finalStatus = 'pending'; // e.g. for EFT payments awaiting confirmation
            }
            // Potentially handle 'cancelled' as well.

            return [
                'status' => $finalStatus,
                'message' => $message,
                'transactionId' => $sanitizedData['pf_payment_id'] ?? null, // PayFast Payment ID
                'orderId' => $sanitizedData['m_payment_id'] ?? null,      // Your merchant payment ID
                'paymentStatus' => $paymentStatus,
                'amount' => $sanitizedData['amount_gross'] ?? ($sanitizedData['amount_net'] ?? null),
                'currency' => 'ZAR', // PayFast transactions are typically in ZAR unless multi-currency is enabled
                'rawData' => $sanitizedData
            ];

        } catch (\Exception $e) {
            throw new ProcessingException('PayFast ITN: Processing failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function verify(array $data): array
    {
        // PayFast does not have a direct transaction status query API in the same way some other gateways do.
        // Verification is primarily done via ITN. Once an ITN is received and validated as 'VALID',
        // you check the `payment_status` within that ITN payload.
        // This `verify` method could conceptually re-validate an ITN or check internal records.
        // For this mock, we will simulate that we are re-processing a stored ITN payload.
        $sanitizedData = $this->sanitize($data); // Assume $data is a stored ITN payload, including pf_payment_id

        if (empty($sanitizedData['pf_payment_id'])) {
            throw new VerificationException('PayFast: pf_payment_id is required for verification (from stored ITN).');
        }
        if (empty($sanitizedData['payment_status'])) {
             throw new VerificationException('PayFast: payment_status is required in data for verification.');
        }
        
        // Simulate the ITN validation again for completeness, though in reality you might trust your stored, validated ITN.
        // For this mock, we'll just use the provided payment_status.
        $paymentStatus = strtolower($sanitizedData['payment_status']);
        $finalStatus = 'failed';
        $message = 'PayFast (simulated verify from ITN data) - Payment Status: ' . $paymentStatus;

        if ($paymentStatus === 'complete') {
            $finalStatus = 'success';
        } elseif ($paymentStatus === 'pending') {
            $finalStatus = 'pending';
        }
        
        if ($sanitizedData['pf_payment_id'] === 'VERIFY_FAIL_PF') {
            $finalStatus = 'failed';
            $message = 'PayFast (simulated verify from ITN data) - Forced failure.';
        }

        return [
            'status' => $finalStatus,
            'message' => $message,
            'transactionId' => $sanitizedData['pf_payment_id'],
            'orderId' => $sanitizedData['m_payment_id'] ?? null,
            'paymentStatus' => $paymentStatus,
            'amount' => $sanitizedData['amount_gross'] ?? null,
            'rawData' => $sanitizedData
        ];
    }

    public function refund(array $data): array
    {
        // PayFast refunds are typically done via their merchant dashboard or a more specific API if available (e.g., for credit card refunds).
        // A general programmatic refund API for all payment types might not be as straightforward as some gateways.
        // Ad hoc refunds for EFT are often manual or require specific integration.
        // This mock will simulate a conceptual refund attempt if such an API existed or if it's a card transaction.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // PayFast pf_payment_id
            throw new RefundException('PayFast: transactionId (pf_payment_id) is required for refund.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('PayFast: Invalid or missing amount for refund.');
        }

        // Conceptual payload for a refund API endpoint (if one exists like /eng/process/refund)
        $payload = [
            'merchant_id' => $this->config['merchantId'],
            'merchant_key' => $this->config['merchantKey'],
            'pf_payment_id' => $sanitizedData['transactionId'],
            'amount' => number_format((float)$sanitizedData['amount'], 2, '.', ''),
            'reason' => $sanitizedData['reason'] ?? 'Merchant initiated refund.',
            // 'testing' => $this->config['isSandbox'] ? 'true' : 'false' // Some PayFast APIs use this
        ];
        // Signature might be needed for refunds as well.
        if (!empty($this->config['passphrase'])) {
            // $payload['signature'] = $this->generateSignature($payload, $this->config['passphrase']);
        }

        try {
            // $url = ($this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION) . '/some/refund/endpoint';
            // $response = $this->httpClient('POST', $url, $payload, []);
            // Mocked Response
            if ($payload['amount'] == '99.99') {
                 throw new RefundException('PayFast: API rejected refund (simulated amount error).');
            }
            if ($payload['pf_payment_id'] === 'NO_REFUND_PF'){
                // Simulate refund not allowed or failed
                 $mockResponseBody = ['status' => 'failure', 'message' => 'Refund not permitted for this transaction type or status.'];
                 $response = ['body' => $mockResponseBody, 'status_code' => 400]; // Bad request
            } else {
                // Simulate successful submission of refund request
                $mockResponseBody = ['status' => 'success', 'message' => 'Refund request submitted.', 'refund_id' => 'PF_REFUND_'.uniqid()];
                $response = ['body' => $mockResponseBody, 'status_code' => 200];
            }

            if ($response['status_code'] !== 200 || strtolower($response['body']['status'] ?? '') !== 'success') {
                throw new RefundException('PayFast: Refund API call failed. Error: ' . ($response['body']['message'] ?? 'Unknown API error'));
            }

            // Refunds via API (if available) might be asynchronous.
            return [
                'status' => 'pending', // Assume pending until confirmed, PayFast ITN might confirm if it covers refunds
                'message' => 'PayFast refund request submitted. Message: ' . $response['body']['message'],
                'refundId' => $response['body']['refund_id'] ?? $sanitizedData['transactionId'] . '_REF',
                'gatewayReferenceId' => $sanitizedData['transactionId'], // Original pf_payment_id
                'paymentStatus' => 'REFUND_PENDING',
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('PayFast: Refund failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 