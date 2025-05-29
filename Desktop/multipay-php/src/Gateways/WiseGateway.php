<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class WiseGateway extends PaymentGateway
{
    private const API_BASE_URL_SANDBOX = 'https://api.sandbox.transferwise.tech';
    private const API_BASE_URL_PRODUCTION = 'https://api.transferwise.com';

    protected function getDefaultConfig(): array
    {
        return [
            'apiToken' => '',         // Your Wise API token (Personal or Business)
            'profileId' => '',        // Business Profile ID (if applicable, for Business API usage)
            'isSandbox' => true,
            'timeout' => 60,
            'webhookSecret' => '',    // For verifying webhook signatures (conceptual)
        ];
    }

    protected function validateConfig(array $config): void
    {
        if (empty($config['apiToken'])) {
            throw new InvalidConfigurationException('Wise: apiToken is required.');
        }
        // profileId might be required for business operations but not for personal token operations.
        // For simplicity, we won't enforce it here, but a real implementation would need to check based on use-case.
    }

    private function getApiBaseUrl(): string
    {
        return $this->config['isSandbox'] ? self::API_BASE_URL_SANDBOX : self::API_BASE_URL_PRODUCTION;
    }

    private function getRequestHeaders(): array
    {
        return [
            'Content-Type' => 'application/json',
            'Authorization' => 'Bearer ' . $this->config['apiToken'],
        ];
    }

    // Wise uses X-Signature-SHA256 for webhooks. Placeholder for its verification.
    protected function verifyWebhookSignature(string $payload, string $signature): bool
    {
        // $calculatedSignature = hash_hmac('sha256', $payload, $this->config['webhookSecret']);
        // return hash_equals($calculatedSignature, $signature);
        if ($signature === 'FAIL_WISE_SIGNATURE') return false;
        return true;
    }

    public function initialize(array $data): array
    {
        // Conceptual: Initializing a "payment" with Wise could mean generating a quote for a transfer 
        // that the user will pay, or creating a recipient account for the user to send money to.
        // This mock will simulate creating a unique "payment request" or "deposit instruction".
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Wise: Invalid or missing amount.');
        }
        if (empty($sanitizedData['currency'])) {
            throw new InitializationException('Wise: Missing currency code.');
        }
        if (empty($sanitizedData['orderId'])) {
            throw new InitializationException('Wise: Missing orderId.');
        }

        // For a real payment gateway scenario, Wise might be used to receive payments to one of your Wise balances.
        // The `initialize` step could create a unique reference for reconciliation.
        // A more direct payment method might involve Wise Checkout or similar, if available as such.
        
        // Simulate creation of a unique deposit reference
        $paymentReference = 'WISEPAY-' . strtoupper($sanitizedData['orderId']) . '-' . strtoupper(uniqid());

        if ($sanitizedData['amount'] == 999) {
            throw new InitializationException('Wise: Simulated error during initialization (e.g., invalid parameters for Wise API).');
        }

        // No direct payment URL from Wise in this context; it's more about providing instructions.
        // Or, if using "Request Money" feature, it would send an email/link via Wise platform.
        return [
            'status' => 'pending_payment', // User needs to make a transfer to this reference
            'message' => 'Wise payment details generated. User should transfer ' . $sanitizedData['amount'] . ' ' . $sanitizedData['currency'] . ' with reference: ' . $paymentReference,
            'orderId' => $sanitizedData['orderId'],
            'gatewayReferenceId' => $paymentReference, // This is our internal reference for reconciliation
            'paymentInstructions' => [
                'type' => 'bank_transfer_details', // Conceptual
                'reference_to_use' => $paymentReference,
                'account_details' => '[Mocked Wise Account Details for currency ' . $sanitizedData['currency'] . ']',
                // In a real scenario, you might fetch your Wise account details for the specified currency via API.
            ],
            'rawData' => ['reference' => $paymentReference, 'amount' => $sanitizedData['amount'], 'currency' => $sanitizedData['currency']]
        ];
    }

    public function process(array $data): array
    {
        // Processing for Wise would typically involve handling webhooks for incoming transfers.
        // "transfers" resource events: transfers.state_change, transfers.payment_sent, transfers.payment_received etc.
        $sanitizedData = $this->sanitize($data); // Assuming $data is the decoded webhook payload (e.g., a transfer object)

        // Example webhook payload structure might be more complex, this is simplified.
        if (empty($sanitizedData['resource']['id']) || empty($sanitizedData['event_type'])) {
            throw new ProcessingException('Wise Webhook: Invalid data. Missing resource ID or event_type.');
        }

        // Optional: Verify webhook signature
        // $rawNotification = json_encode($sanitizedData); // Or the raw JSON string received
        // $receivedSignature = $_SERVER['HTTP_X_SIGNATURE_SHA256'] ?? ''; 
        // if (!$this->verifyWebhookSignature($rawNotification, $receivedSignature)) {
        //     throw new ProcessingException('Wise Webhook: Signature verification failed.');
        // }

        $eventType = $sanitizedData['event_type'];
        $transfer = $sanitizedData['data'] ?? ($sanitizedData['resource'] ?? null); // Location of transfer data can vary
        
        if (!$transfer || empty($transfer['id'])) {
            throw new ProcessingException('Wise Webhook: Missing transfer data in payload.');
        }

        $paymentStatus = 'pending';
        $message = 'Wise webhook received: ' . $eventType;
        $wiseTransferId = $transfer['id'];
        // User reference ID (custom reference you set when the payer made the transfer)
        // This is crucial for matching with your orderId.
        $userReference = $transfer['reference'] ?? null; 
        $orderId = null;
        // Attempt to extract orderId from userReference (e.g., if format is WISEPAY-ORDERID-UNIQUEID)
        if ($userReference && strpos($userReference, 'WISEPAY-') === 0) {
            $parts = explode('-', $userReference);
            if (count($parts) >= 2) {
                $orderId = $parts[1];
            }
        }
        
        // Example: `transfers.state_change` with `current_state: funds_converted` or `outgoing_payment_sent` for payouts
        // For receiving payments, you'd look for states like `incoming_payment_received` or similar if that's the event type.
        // This mock focuses on receiving funds.
        // Suppose a webhook event indicates funds credited to your Wise account.

        if ($eventType === 'transfers.state_change') {
            $currentState = $transfer['status'] ?? ($transfer['state'] ?? ''); // Field name can be 'status' or 'state'
            if ($currentState === 'COMPLETED' || $currentState === 'funds_credited' || $currentState === 'incoming_payment_received') { // Mocked success states
                $paymentStatus = 'success';
                $message = 'Wise payment confirmed via webhook. Transfer ID: ' . $wiseTransferId;
            } elseif (in_array($currentState, ['PENDING', 'PROCESSING', 'funds_added'])) {
                $paymentStatus = 'pending';
                $message = 'Wise payment processing. Status: ' . $currentState;
            } elseif (in_array($currentState, ['FAILED', 'CANCELLED', 'REJECTED'])) {
                $paymentStatus = 'failed';
                $message = 'Wise payment failed or cancelled. Status: ' . $currentState;
            }
        } else {
            // Not a state_change event we are directly interested in for success/failure of payment receipt.
            // Could be other informational events.
             $message .= '. No direct payment status change.';
        }

        return [
            'status' => $paymentStatus,
            'message' => $message,
            'transactionId' => (string) $wiseTransferId,  // Wise Transfer ID
            'orderId' => $orderId ?? ($sanitizedData['custom_order_id'] ?? null), // Your order ID, ideally from reference
            'paymentStatus' => $eventType . ' (' . ($transfer['status'] ?? ($transfer['state'] ?? 'N/A')) . ')',
            'amount' => $transfer['targetAmount'] ?? ($transfer['sourceAmount'] ?? null), // Amount could be target or source depending on context
            'currency' => $transfer['targetCurrency'] ?? ($transfer['sourceCurrency'] ?? null),
            'rawData' => $sanitizedData
        ];
    }

    public function verify(array $data): array
    {
        // Verification would involve fetching a specific transfer by its ID.
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['transactionId'])) { // Wise Transfer ID
            throw new VerificationException('Wise: Missing transactionId (Transfer ID) for verification.');
        }

        $transferId = $sanitizedData['transactionId'];

        try {
            // $response = $this->httpClient('GET', $this->getApiBaseUrl() . '/v1/transfers/' . $transferId, [], $this->getRequestHeaders());
            // Mocked Response
            if ($transferId === 'FAIL_WISE_VERIFY') {
                throw new VerificationException('Wise: API error during verification (simulated transfer not found).');
            }

            $mockTransferDetails = null;
            if ($transferId === '12345') { // Simulate success
                 $mockTransferDetails = [
                    'id' => 12345,
                    'profile' => $this->config['profileId'] ?? 100,
                    'status' => 'COMPLETED', // Example states: PENDING, PROCESSING, COMPLETED, FAILED, CANCELLED
                    'reference' => 'WISEPAY-'.($sanitizedData['orderIdForTest'] ?? 'ORDER123').'-ABCDE', // User reference
                    'rate' => 0.85,
                    'sourceCurrency' => 'EUR',
                    'sourceAmount' => 117.65,
                    'targetCurrency' => 'GBP',
                    'targetAmount' => 100.00,
                    'created_time' => '2023-01-01T12:00:00Z',
                    // ... other transfer details
                ];
            } elseif ($transferId === '67890') { // Simulate pending
                 $mockTransferDetails = ['id' => 67890, 'status' => 'PROCESSING', 'reference' => 'WISEPAY-'.($sanitizedData['orderIdForTest'] ?? 'ORDER456').'-FGHIJ', 'targetAmount' => 50.00, 'targetCurrency' => 'USD'];
            } else {
                // Simulate not found or error by returning an empty body or error structure if API does that
                 $mockTransferDetails = null; // Or throw an exception if API returns non-200 for not found
            }
            
            $response = ['body' => $mockTransferDetails, 'status_code' => $mockTransferDetails ? 200 : 404];

            if ($response['status_code'] !== 200 || !$response['body']) {
                throw new VerificationException('Wise: Failed to verify transfer. Transfer not found or API error.');
            }

            $transfer = $response['body'];
            $currentStatus = 'failed';
            $orderId = null;
            if (!empty($transfer['reference']) && strpos($transfer['reference'], 'WISEPAY-') === 0) {
                $parts = explode('-', $transfer['reference']);
                if (count($parts) >= 2) $orderId = $parts[1];
            }

            if (($transfer['status'] ?? '') === 'COMPLETED' || ($transfer['status'] ?? '') === 'funds_credited') { // Using potential success states
                $currentStatus = 'success';
            } elseif (in_array(($transfer['status'] ?? ''), ['PENDING', 'PROCESSING', 'funds_added'])) {
                $currentStatus = 'pending';
            }

            return [
                'status' => $currentStatus,
                'message' => 'Wise transfer status: ' . ($transfer['status'] ?? 'Unknown'),
                'transactionId' => (string) $transfer['id'],
                'orderId' => $orderId,
                'paymentStatus' => $transfer['status'] ?? 'Unknown',
                'amount' => $transfer['targetAmount'] ?? ($transfer['sourceAmount'] ?? null),
                'currency' => $transfer['targetCurrency'] ?? ($transfer['sourceCurrency'] ?? null),
                'rawData' => $transfer
            ];

        } catch (\Exception $e) {
            throw new VerificationException('Wise: Transfer verification failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        // Refunding a payment received into a Wise account isn't a direct "refund" API call on the original transaction.
        // It would typically mean initiating a new transfer (payout) from your Wise account to the customer.
        // This requires recipient bank details and uses the "Create Transfer" and related endpoints.
        $sanitizedData = $this->sanitize($data);

        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new RefundException('Wise: Invalid or missing amount for refund (payout).');
        }
        if (empty($sanitizedData['currency'])) {
            throw new RefundException('Wise: Missing currency for refund (payout).');
        }
        if (empty($sanitizedData['recipientDetails'])) { // This would contain bank details, email etc.
            throw new RefundException('Wise: Missing recipientDetails for refund (payout).');
        }
        // recipientDetails might include: accountHolderName, accountNumber, sortCode/routingNumber, bankName, country etc.
        // Or for Wise-to-Wise transfer, a Wise recipient ID or email.

        // 1. Create a Recipient Account (if not already created)
        // For simplicity, we assume recipient ID is provided or skip this step conceptually.
        $recipientId = $sanitizedData['recipientDetails']['wiseRecipientId'] ?? null;
        if (!$recipientId && ($sanitizedData['recipientDetails']['type'] ?? 'bank_details') !== 'wise_member_id') {
            // Mock creating a recipient - in real life, this is an API call with detailed bank info
            // $recipientPayload = ['currency' => $sanitizedData['currency'], 'type' => 'iban', 'details' => [...] ];
            // $recipientResponse = $this->httpClient('POST', $this->getApiBaseUrl() . '/v1/accounts', $recipientPayload, ...);
            // $recipientId = $recipientResponse['body']['id'];
            if(empty($sanitizedData['recipientDetails']['mock_recipient_id'])){
                 throw new RefundException('Wise: Mock recipient creation failed (missing mock_recipient_id in recipientDetails).');
            }
            $recipientId = $sanitizedData['recipientDetails']['mock_recipient_id'];
        }

        // 2. Create a Quote for the payout transfer
        $quotePayload = [
            'sourceCurrency' => $sanitizedData['currency'], // Assuming you refund from a balance of the same currency
            'targetCurrency' => $sanitizedData['currency'], // Or could be different if cross-currency refund
            'sourceAmount' => null,
            'targetAmount' => (float) $sanitizedData['amount'],
            'profile' => $this->config['profileId'] ?? null, // Required for business transfers
            // 'payOut' => 'BANK_TRANSFER' // Default if not specified
        ];
        // $quoteResponse = $this->httpClient('POST', $this->getApiBaseUrl() . '/v2/quotes', $quotePayload, ...);
        // $quoteId = $quoteResponse['body']['id'];
        $mockQuoteId = 'WISEQUOTE-' . strtoupper(uniqid());
        if ($sanitizedData['amount'] == 99.99) {
            throw new RefundException('Wise: Quote creation for refund failed (simulated amount error).');
        }

        // 3. Create the Transfer (fund it from your balance)
        $transferPayload = [
            'targetAccount' => $recipientId,
            'quoteUuid' => $mockQuoteId, // From quote step
            'customerTransactionId' => $sanitizedData['refundId'] ?? 'REFUND-' . ($sanitizedData['originalOrderId'] ?? uniqid()),
            'details' => [
                'reference' => 'Refund for order: ' . ($sanitizedData['originalOrderId'] ?? 'N/A'),
                // 'transferPurpose' => 'refund.customer.ecommerce', // Example purpose
            ]
        ];
        // $transferResponse = $this->httpClient('POST', $this->getApiBaseUrl() . '/v1/transfers', $transferPayload, ...);
        // $refundTransferId = $transferResponse['body']['id'];
        $mockRefundTransferId = 'WISEREFUNDTRANS-' . strtoupper(uniqid());

        return [
            'status' => 'pending', // Payouts are usually asynchronous
            'message' => 'Wise refund (payout) initiated. Transfer ID: ' . $mockRefundTransferId,
            'refundId' => $transferPayload['customerTransactionId'],
            'gatewayReferenceId' => $mockRefundTransferId, // This is the ID of the new payout transfer
            'paymentStatus' => 'REFUND_INITIATED',
            'rawData' => ['quoteId' => $mockQuoteId, 'recipientId' => $recipientId, 'transferId' => $mockRefundTransferId]
        ];
    }
} 