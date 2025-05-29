<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

// It's good practice to alias the Braintree SDK classes if you were using them directly
// use Braintree\Gateway as BraintreeSdkGateway;
// use Braintree\Configuration as BraintreeSdkConfiguration;
// use Braintree\Exception as BraintreeSdkException;

class BraintreeGateway extends PaymentGateway
{
    // Braintree SDK handles endpoint selection based on environment.
    // No explicit base URLs needed here if using their SDK.
    // For direct API calls (not recommended), URLs would be like:
    // Sandbox: https://api.sandbox.braintreegateway.com/merchants/YOUR_MERCHANT_ID/...
    // Production: https://api.braintreegateway.com/merchants/YOUR_MERCHANT_ID/...

    protected function getDefaultConfig(): array
    {
        return [
            'environment' => 'sandbox', // 'sandbox' or 'production'
            'merchantId' => '',
            'publicKey' => '',
            'privateKey' => '',
            'timeout' => 60,
            // 'clientTokenVersion' => null, // Optional: specify client token version
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['environment', 'merchantId', 'publicKey', 'privateKey'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("Braintree: {$key} is required.");
            }
        }
        if (!in_array($config['environment'], ['sandbox', 'production'])) {
            throw new InvalidConfigurationException("Braintree: environment must be 'sandbox' or 'production'.");
        }
    }

    // In a real scenario, you'd initialize the Braintree SDK's Gateway object here.
    // protected function getBraintreeGateway()
    // {
    //     return new BraintreeSdkGateway([
    //         'environment' => $this->config['environment'],
    //         'merchantId' => $this->config['merchantId'],
    //         'publicKey' => $this->config['publicKey'],
    //         'privateKey' => $this->config['privateKey']
    //     ]);
    // }

    public function initialize(array $data): array
    {
        // Braintree typically involves generating a client token for the frontend (using Drop-in UI or Hosted Fields).
        // The frontend then gets a payment method nonce, which is sent to your server to create a transaction.
        // This `initialize` method will simulate generating that client token.
        $sanitizedData = $this->sanitize($data); 
        // customerId is optional for client token generation, but useful for Vault functionality.
        $customerId = $sanitizedData['customerId'] ?? null;
        $merchantAccountId = $sanitizedData['merchantAccountId'] ?? null; // For specific sub-merchant accounts

        try {
            // $gateway = $this->getBraintreeGateway();
            // $clientTokenParams = [];
            // if ($customerId) $clientTokenParams['customerId'] = $customerId;
            // if ($merchantAccountId) $clientTokenParams['merchantAccountId'] = $merchantAccountId;
            // $clientToken = $gateway->clientToken()->generate($clientTokenParams);
            
            // Mocked client token generation
            if ($customerId === 'FAIL_TOKEN_GEN') {
                throw new InitializationException('Braintree: Failed to generate client token (simulated error).');
            }
            $mockClientToken = 'MOCK_BRAINTREE_CLIENT_TOKEN_' . base64_encode(json_encode([
                'version' => 3,
                'merchantId' => $this->config['merchantId'],
                'authUrl' => 'https://auth.sandbox.braintree-api.com',
                'clientApiUrl' => 'https://client-api.sandbox.braintreegateway.com',
                'environment' => $this->config['environment'],
                'customerId' => $customerId,
                'merchantAccountId' => $merchantAccountId,
                'timestamp' => time()
            ]));

            return [
                'status' => 'client_token_generated',
                'message' => 'Braintree client token generated successfully. Use this on your frontend.',
                'clientToken' => $mockClientToken,
                'orderId' => $sanitizedData['orderId'] ?? null, // Pass through if provided
                'rawData' => ['tokenParams' => ['customerId' => $customerId, 'merchantAccountId' => $merchantAccountId]]
            ];
        } catch (\Exception $e) {
            // if ($e instanceof BraintreeSdkException\NotFound) { ... }
            throw new InitializationException('Braintree: Client token generation failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // This method handles the transaction creation using a payment method nonce obtained from the client-side.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['paymentMethodNonce'])) {
            throw new ProcessingException('Braintree: paymentMethodNonce is required.');
        }
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new ProcessingException('Braintree: Invalid or missing amount.');
        }
        // orderId is recommended for Braintree transactions for tracking and reporting.
        if (empty($sanitizedData['orderId'])) {
            throw new ProcessingException('Braintree: orderId is recommended and often required.');
        }

        $transactionParams = [
            'amount' => number_format((float)$sanitizedData['amount'], 2, '.', ''),
            'paymentMethodNonce' => $sanitizedData['paymentMethodNonce'],
            'orderId' => $sanitizedData['orderId'],
            'options' => [
                'submitForSettlement' => $sanitizedData['submitForSettlement'] ?? true, // true to capture, false to authorize
                // 'storeInVaultOnSuccess' => $sanitizedData['storeInVault'] ?? false,
            ],
            // 'customerId' => $sanitizedData['customerId'] ?? null,
            // 'merchantAccountId' => $sanitizedData['merchantAccountId'] ?? null,
            // 'shipping' => [...], 'billing' => [...], 'customer' => [...], etc.
        ];

        try {
            // $gateway = $this->getBraintreeGateway();
            // $result = $gateway->transaction()->sale($transactionParams);

            // Mocked Braintree transaction sale result
            $mockResult = null;
            if ($sanitizedData['paymentMethodNonce'] === 'nonce_fails_processing') {
                // Simulate a processor decline or validation error
                $mockResult = (object) [
                    'success' => false,
                    'errors' => (object) ['deepAll' => function() { return [(object)['code' => '81703', 'message' => 'Processor Declined - Insufficient Funds']]; }],
                    'transaction' => null,
                    'message' => 'Processor Declined - Insufficient Funds (mocked)'
                ];
            } elseif ($sanitizedData['paymentMethodNonce'] === 'nonce_needs_3ds') {
                 // Simulate a 3DS verification required scenario (less common in direct sale like this without handling it)
                 // Usually, 3DS is handled by the client-side SDK before nonce creation or by Braintree.js v3 with verifyCard
                 $mockResult = (object) [
                    'success' => false,
                    'errors' => (object) ['deepAll' => function() { return [(object)['code' => '2099', 'message' => 'Gateway Rejected: 3D Secure authentication is required.']]; }],
                    'transaction' => (object) [
                        'id' => '3DS_TRANS_ID_'.strtoupper(uniqid()),
                        'status' => 'gateway_rejected',
                        'gatewayRejectionReason' => 'three_d_secure',
                        // ... other minimal transaction details for this case
                    ],
                    'message' => 'Gateway Rejected: 3D Secure authentication is required. (mocked)'
                 ];
            } else { // Simulate success
                $mockTransactionId = 'BT_TRANS_ID_'.strtoupper(uniqid());
                $mockResult = (object) [
                    'success' => true,
                    'transaction' => (object) [
                        'id' => $mockTransactionId,
                        'status' => ($transactionParams['options']['submitForSettlement'] ? 'submitted_for_settlement' : 'authorized'),
                        'type' => 'sale',
                        'amount' => $transactionParams['amount'],
                        'currencyIsoCode' => $sanitizedData['currency'] ?? 'USD', // Braintree uses currency from transaction or merchant account
                        'orderId' => $transactionParams['orderId'],
                        'createdAt' => date('Y-m-d\TH:i:s\Z'),
                        'paymentInstrumentType' => 'credit_card', // Example
                        'creditCardDetails' => (object) ['last4' => '1111', 'cardType' => 'Visa'], // Example
                        // ... other transaction details like avsErrorResponseCode, cvvResponseCode, etc.
                    ]
                ];
            }

            if ($mockResult->success && $mockResult->transaction) {
                $transaction = $mockResult->transaction;
                return [
                    'status' => ($transaction->status === 'authorized' ? 'authorized' : 'success'),
                    'message' => 'Braintree transaction successful. Status: ' . $transaction->status,
                    'transactionId' => $transaction->id,
                    'orderId' => $transaction->orderId,
                    'paymentStatus' => $transaction->status,
                    'isRedirect' => false,
                    'rawData' => json_decode(json_encode($transaction), true) // Convert object to array
                ];
            } else {
                // $errorMessages = array_map(function($error) { return $error->message; }, $mockResult->errors->deepAll());
                $firstError = $mockResult->errors->deepAll()[0] ?? (object)['message' => 'Unknown error'];
                $errorMessage = $mockResult->message ?? $firstError->message;
                throw new ProcessingException('Braintree: Transaction failed. ' . $errorMessage . (isset($firstError->code) ? ' (Code: ' . $firstError->code . ')' : ''));
            }
        } catch (\Exception $e) {
             // if ($e instanceof BraintreeSdkException) { ... }
            throw new ProcessingException('Braintree: Payment processing failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function verify(array $data): array
    {
        // Verification typically means fetching the transaction status by its ID.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) {
            throw new VerificationException('Braintree: transactionId is required for verification.');
        }
        $transactionId = $sanitizedData['transactionId'];

        try {
            // $gateway = $this->getBraintreeGateway();
            // $transaction = $gateway->transaction()->find($transactionId);

            // Mocked Braintree transaction find result
            $mockTransaction = null;
            if ($transactionId === 'FAIL_BT_VERIFY') {
                // Simulate Braintree_Exception_NotFound
                throw new \Exception('Transaction with id ' . $transactionId . ' not found (simulated Braintree_Exception_NotFound)');
            }
            if (strpos($transactionId, 'BT_TRANS_ID_') === 0) { // Previously created mock ID
                $mockTransaction = (object) [
                    'id' => $transactionId,
                    'status' => 'settled', // Possible statuses: authorized, submitted_for_settlement, settling, settled, voided, failed, processor_declined, gateway_rejected
                    'type' => 'sale',
                    'amount' => '100.00', // Example
                    'currencyIsoCode' => 'USD',
                    'orderId' => 'ORDER_VERIFY_'.substr($transactionId, -5),
                    'createdAt' => date('Y-m-d\TH:i:s\Z', time() - 3600),
                    'updatedAt' => date('Y-m-d\TH:i:s\Z'),
                    // ... other details
                ];
            } elseif ($transactionId === 'AUTH_ONLY_ID') {
                 $mockTransaction = (object) ['id' => $transactionId, 'status' => 'authorized', 'amount' => '50.00', 'orderId' => 'ORDER_AUTH'];
            }
            
            if (!$mockTransaction) {
                 // This specific exception type would be \Braintree\Exception\NotFound in real SDK
                 throw new \Exception("Transaction with id {$transactionId} not found (simulated for verify)");
            }
            $transaction = $mockTransaction;

            $finalStatus = 'failed';
            if (in_array($transaction->status, ['authorized', 'submitted_for_settlement', 'settling', 'settled'])) {
                $finalStatus = ($transaction->status === 'authorized' ? 'authorized' : 'success'); // Treat settled/settling as success
            } elseif (in_array($transaction->status, ['authorization_expired', 'voided', 'failed', 'processor_declined', 'gateway_rejected'])) {
                $finalStatus = 'failed';
            } else {
                $finalStatus = 'pending'; // For other statuses or if unsure
            }

            return [
                'status' => $finalStatus,
                'message' => 'Braintree transaction status: ' . $transaction->status,
                'transactionId' => $transaction->id,
                'orderId' => $transaction->orderId ?? null,
                'paymentStatus' => $transaction->status,
                'amount' => $transaction->amount ?? null,
                'currency' => $transaction->currencyIsoCode ?? null,
                'rawData' => json_decode(json_encode($transaction), true)
            ];
        } catch (\Exception $e) {
            //  if ($e instanceof BraintreeSdkException\NotFound) {
            //      throw new VerificationException('Braintree: Transaction not found. ' . $e->getMessage(), 0, $e);
            //  }
            throw new VerificationException('Braintree: Transaction verification failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) {
            throw new RefundException('Braintree: transactionId is required for refund.');
        }
        // Amount is optional for full refund, required for partial refund.
        $amount = isset($sanitizedData['amount']) ? number_format((float)$sanitizedData['amount'], 2, '.', '') : null;
        $orderId = $sanitizedData['refundOrderId'] ?? null; // Optional: new order ID for the refund transaction

        try {
            // $gateway = $this->getBraintreeGateway();
            // $refundParams = [];
            // if ($amount) $refundParams['amount'] = $amount;
            // if ($orderId) $refundParams['orderId'] = $orderId;
            // $result = $gateway->transaction()->refund($sanitizedData['transactionId'], ...$refundParams); // Spread operator if using PHP 7.4+
            // Or $result = $gateway->transaction()->refund($sanitizedData['transactionId'], $amount, $orderId); for specific args

            // Mocked Braintree refund result
            $mockResult = null;
            if ($sanitizedData['transactionId'] === 'NO_REFUND_TRANS') {
                $mockResult = (object) [
                    'success' => false,
                    'errors' => (object) ['deepAll' => function() { return [(object)['code' => '91506', 'message' => 'Cannot refund a transaction unless it is settled.']]; }],
                    'transaction' => null,
                    'message' => 'Cannot refund a transaction unless it is settled. (mocked)'
                ];
            } elseif ($amount && (float)$amount > 2000) { // Simulate too large partial refund
                 $mockResult = (object) [
                    'success' => false,
                    'errors' => (object) ['deepAll' => function() { return [(object)['code' => '91508', 'message' => 'Amount for partial refund is invalid.']]; }],
                    'transaction' => null,
                    'message' => 'Amount for partial refund is invalid (mocked too high).',
                 ];
            } else { // Simulate successful refund
                $mockRefundTransactionId = 'BT_REFUND_ID_'.strtoupper(uniqid());
                $mockResult = (object) [
                    'success' => true,
                    'transaction' => (object) [
                        'id' => $mockRefundTransactionId,
                        'type' => 'credit', // Refunds are 'credit' transactions
                        'status' => 'submitted_for_settlement', // Refund transactions also have statuses
                        'amount' => $amount ?? '100.00', // Assume full refund if amount not specified
                        'refundedTransactionId' => $sanitizedData['transactionId'],
                        'orderId' => $orderId ?? ($sanitizedData['originalOrderId'] . '_R'),
                        // ... other refund transaction details
                    ]
                ];
            }

            if ($mockResult->success && $mockResult->transaction) {
                $refundTransaction = $mockResult->transaction;
                return [
                    'status' => 'success', // Or pending if refunds are not immediate
                    'message' => 'Braintree refund successful. Status: ' . $refundTransaction->status,
                    'refundId' => $refundTransaction->id, // ID of the refund transaction itself
                    'gatewayReferenceId' => $refundTransaction->refundedTransactionId, // Original transaction ID
                    'orderId' => $refundTransaction->orderId,
                    'paymentStatus' => 'REFUNDED' , // Or $refundTransaction->status
                    'rawData' => json_decode(json_encode($refundTransaction), true)
                ];
            } else {
                $firstError = $mockResult->errors->deepAll()[0] ?? (object)['message' => 'Unknown error'];
                $errorMessage = $mockResult->message ?? $firstError->message;
                throw new RefundException('Braintree: Refund failed. ' . $errorMessage . (isset($firstError->code) ? ' (Code: ' . $firstError->code . ')' : ''));
            }
        } catch (\Exception $e) {
            // if ($e instanceof BraintreeSdkException) { ... }
            throw new RefundException('Braintree: Refund processing failed. ' . $e->getMessage(), 0, $e);
        }
    }
    
    // Braintree webhooks are important for async updates (e.g. settlement, disputes)
    // public function parseWebhook(string $btSignature, string $btPayload): array 
    // {
    //     try {
    //         // $gateway = $this->getBraintreeGateway();
    //         // $webhookNotification = $gateway->webhookNotification()->parse($btSignature, $btPayload);
    //         // Mocked parsing
    //         if ($btSignature === 'FAIL_SIGNATURE') throw new \Exception('Webhook signature invalid (mocked)');
    //         $decodedPayload = json_decode($btPayload, true);
    //         if (!$decodedPayload || !isset($decodedPayload['kind'])) { 
    //              throw new \Exception('Invalid webhook payload (mocked)');
    //         }
    //         $mockWebhookNotification = (object) [
    //             'kind' => $decodedPayload['kind'], // e.g., 'transaction_settled', 'disbursement', 'dispute_opened'
    //             'timestamp' => new \DateTime($decodedPayload['timestamp'] ?? 'now'),
    //             'transaction' => isset($decodedPayload['transaction']) ? (object)$decodedPayload['transaction'] : null,
    //             // ... other potential webhook objects like dispute, disbursement
    //         ];

    //         return [
    //             'kind' => $mockWebhookNotification->kind,
    //             'timestamp' => $mockWebhookNotification->timestamp->format(DATE_ISO8601),
    //             'transactionId' => $mockWebhookNotification->transaction->id ?? null,
    //             'rawData' => json_decode(json_encode($mockWebhookNotification), true)
    //         ];
    //     } catch (\Exception $e) {
    //         // if ($e instanceof BraintreeSdkException\InvalidSignature) { ... }
    //         throw new ProcessingException('Braintree: Webhook parsing failed. ' . $e->getMessage(), 0, $e);
    //     }
    // }
} 