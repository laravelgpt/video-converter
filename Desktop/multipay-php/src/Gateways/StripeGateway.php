<?php

namespace Multipay\Payment\Gateways;

use Multipay\Payment\PaymentGateway;
use Multipay\Payment\Exceptions\InvalidConfigurationException;
use Multipay\Payment\Exceptions\InitializationException;
use Multipay\Payment\Exceptions\ProcessingException;
use Multipay\Payment\Exceptions\VerificationException;
use Multipay\Payment\Exceptions\RefundException;

class StripeGateway extends PaymentGateway
{
    private const API_BASE_URL = 'https://api.stripe.com/v1';

    protected function getDefaultConfig(): array
    {
        return [
            'publishableKey' => '', // pk_test_... or pk_live_...
            'secretKey' => '',       // sk_test_... or sk_live_...
            'webhookSecret' => '',   // whsec_... for verifying webhook events
            'isSandbox' => true,      // Stripe differentiates live/test via keys, not usually URL
            'paymentMethodTypes' => ['card'], // Default, can be overridden for PaymentIntents
            'captureMethod' => 'automatic', // 'automatic' or 'manual' for PaymentIntents
            'timeout' => 60,
        ];
    }

    protected function validateConfig(array $config): void
    {
        foreach (['publishableKey', 'secretKey'] as $key) {
            if (empty($config[$key])) {
                throw new InvalidConfigurationException("Stripe: {$key} is required.");
            }
        }
        if (strpos($config['secretKey'], 'sk_test_') !== 0 && $config['isSandbox']) {
            // Optional: could warn if live key used in sandbox mode, but keys define the mode.
        }
    }

    private function getApiBaseUrl(): string
    {
        return self::API_BASE_URL;
    }

    private function getRequestHeaders(): array
    {
        return [
            'Authorization' => 'Bearer ' . $this->config['secretKey'],
            'Content-Type' => 'application/x-www-form-urlencoded', // Stripe uses form-urlencoded
            'Stripe-Version' => '2020-08-27' // Pin API version for consistency
        ];
    }

    // Stripe uses PaymentIntents for most modern integrations.
    // `initialize` would create a PaymentIntent.
    // `process` would confirm it (e.g. with a payment_method ID from Stripe.js/Elements or Google Pay token).

    public function initialize(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['amount']) || !is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
            throw new InitializationException('Stripe: Invalid or missing amount.');
        }
        if (empty($sanitizedData['currency'])) {
            throw new InitializationException('Stripe: Missing currency code.');
        }

        $payload = [
            'amount' => (int)round($sanitizedData['amount'] * 100), // Amount in cents
            'currency' => strtolower($sanitizedData['currency']),
            'payment_method_types' => $sanitizedData['paymentMethodTypes'] ?? $this->config['paymentMethodTypes'],
            'capture_method' => $sanitizedData['captureMethod'] ?? $this->config['captureMethod'],
            'description' => $sanitizedData['description'] ?? 'Payment for order: ' . ($sanitizedData['orderId'] ?? 'N/A'),
            // 'customer' => $sanitizedData['stripeCustomerId'] ?? null, // Optional: existing Stripe customer ID
            'metadata' => $sanitizedData['metadata'] ?? ['order_id' => $sanitizedData['orderId'] ?? 'N/A'],
            // 'confirm' => 'false', // Usually false, confirm happens in `process` or client-side
            // 'automatic_payment_methods' => ['enabled' => 'true'], // For newer integrations
        ];
        if (isset($sanitizedData['returnUrl'])) {
             $payload['confirmation_method'] = 'automatic'; // Required for automatic return_url handling
             $payload['confirm'] = 'true'; // Confirm immediately if return_url is provided for redirect methods
             $payload['return_url'] = $sanitizedData['returnUrl'];
        }

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/payment_intents', $payload, $this->getRequestHeaders());
            // Mocked Response
            if ($payload['amount'] == 99900) { // 999.00 in currency
                 throw new InitializationException('Stripe: API rejected PaymentIntent creation (simulated).');
            }
            $mockPIId = 'pi_' . substr(md5(uniqid()), 0, 24);
            $response = ['body' => [
                    'id' => $mockPIId,
                    'object' => 'payment_intent',
                    'client_secret' => 'cs_' . $mockPIId . '_' . substr(md5(uniqid()), 0, 20), // For client-side confirmation
                    'status' => isset($payload['return_url']) ? 'requires_action' : 'requires_payment_method',
                    'amount' => $payload['amount'],
                    'currency' => $payload['currency']
                ],
                'status_code' => 200
            ];
             if (isset($payload['return_url'])){
                $response['body']['next_action'] = ['redirect_to_url' => ['url' => $payload['return_url'] . '?payment_intent='.$mockPIId]];
             }


            if ($response['status_code'] !== 200 || empty($response['body']['id'])) {
                $error = $response['body']['error'] ?? ['message' => 'Unknown Stripe API error'];
                throw new InitializationException('Stripe: Failed to create PaymentIntent. ' . $error['message']);
            }

            $return = [
                'status' => ($response['body']['status'] === 'requires_action' && isset($response['body']['next_action']['redirect_to_url'])) ? 'pending_user_action' : 'client_setup_required',
                'message' => 'Stripe PaymentIntent created. Client secret provided for client-side confirmation.',
                'gatewayReferenceId' => $response['body']['id'], // PaymentIntent ID
                'clientSecret' => $response['body']['client_secret'],
                'publishableKey' => $this->config['publishableKey'],
                'rawData' => $response['body']
            ];
            if(isset($response['body']['next_action']['redirect_to_url']['url'])){
                $return['paymentUrl'] = $response['body']['next_action']['redirect_to_url']['url'];
            }
            return $return;

        } catch (\Exception $e) {
            throw new InitializationException('Stripe: PaymentIntent creation failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function process(array $data): array
    {
        // Process for Stripe: typically confirming a PaymentIntent with a payment_method ID or handling webhook.
        // If `initialize` created a PaymentIntent to be confirmed on server (e.g. with Google Pay token),
        // this method would take the payment_intent_id and payment_method_data.
        $sanitizedData = $this->sanitize($data);

        if (empty($sanitizedData['gatewayReferenceId'])) { // PaymentIntent ID
            throw new ProcessingException('Stripe: Missing gatewayReferenceId (PaymentIntent ID) for processing.');
        }
        $paymentIntentId = $sanitizedData['gatewayReferenceId'];

        // This mock assumes `process` is called after client-side confirmation or for server-side confirmation logic.
        // If webhook, $data would be the event object. We'll simulate a direct confirmation/status check.
        // Typically, you'd retrieve the PaymentIntent to check its status after client action or webhook.
        // return $this->verify($data); // Let verify handle the status check

        // For a server-side confirmation (e.g. if client sends payment_method_id):
        $payload = [];
        if (!empty($sanitizedData['paymentMethodId'])) { // e.g., pm_xxx from Stripe.js
            $payload['payment_method'] = $sanitizedData['paymentMethodId'];
        }
        // If using Google Pay token via this Stripe gateway directly:
        if (!empty($sanitizedData['googlePayToken'])) {
            $payload['payment_method_data'] = [
                'type' => 'card',
                'card' => ['token' => $sanitizedData['googlePayToken']] // This is a simplification for Google Pay via Stripe tokens API, usually done client side or PaymentIntents
            ];
        }
        
        try {
            // If $payload is not empty, it implies a confirmation call.
            // $endpoint = $this->getApiBaseUrl() . '/payment_intents/' . $paymentIntentId . (empty($payload) ? '' : '/confirm');
            // $response = $this->httpClient(empty($payload) ? 'GET' : 'POST', $endpoint, $payload, $this->getRequestHeaders());

            // Simplified mock: fetch the PaymentIntent (which verify already does well)
            // This process method might be more about applying specific post-authentication logic or if it were handling a webhook.
            // For simplicity, assuming this is a check after client interaction, so using verify logic.
            if ($paymentIntentId === 'pi_process_fail') {
                 throw new ProcessingException('Stripe: Processing failed (simulated).');
            }
            $verificationResult = $this->verify($data);
            
            // Adapt verification result to processing result structure if needed, but they are similar.
            return $verificationResult; 

        } catch (\Exception $e) {
            throw new ProcessingException('Stripe: Payment processing/confirmation failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function verify(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        if (empty($sanitizedData['gatewayReferenceId'])) { // PaymentIntent ID
            throw new VerificationException('Stripe: Missing gatewayReferenceId (PaymentIntent ID) for verification.');
        }
        $paymentIntentId = $sanitizedData['gatewayReferenceId'];

        try {
            // $response = $this->httpClient('GET', $this->getApiBaseUrl() . '/payment_intents/' . $paymentIntentId, [], $this->getRequestHeaders());
            // Mocked Response
            $mockStatus = 'succeeded'; $mockChargeId = 'ch_' . substr(md5(uniqid()),0,24);
             if ($paymentIntentId === 'pi_fail_verify') {
                $mockStatus = 'requires_payment_method'; $mockChargeId = null;
            } else if ($paymentIntentId === 'pi_pending_verify') {
                $mockStatus = 'processing'; $mockChargeId = null;
            }

            $response = ['body' => [
                    'id' => $paymentIntentId,
                    'object' => 'payment_intent',
                    'status' => $mockStatus, // e.g. succeeded, requires_payment_method, processing, requires_action, canceled
                    'amount' => ($sanitizedData['original_amount_for_test'] ?? 100) * 100,
                    'currency' => 'usd',
                    'charges' => [
                        'data' => $mockChargeId ? [[ 'id' => $mockChargeId, 'status' => $mockStatus]] : []
                    ]
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || empty($response['body']['id'])) {
                $error = $response['body']['error'] ?? ['message' => 'Unknown Stripe API error during verification'];
                throw new VerificationException('Stripe: Failed to retrieve PaymentIntent. ' . $error['message']);
            }

            $paymentStatus = $response['body']['status'];
            $isSuccess = $paymentStatus === 'succeeded';
            $isPending = in_array($paymentStatus, ['processing', 'requires_action']);

            $transactionId = null;
            if ($isSuccess && !empty($response['body']['charges']['data'][0]['id'])) {
                $transactionId = $response['body']['charges']['data'][0]['id']; // Charge ID
            }

            return [
                'status' => $isSuccess ? 'success' : ($isPending ? 'pending' : 'failed'),
                'message' => 'Stripe PaymentIntent status: ' . $paymentStatus,
                'transactionId' => $transactionId,
                'gatewayReferenceId' => $paymentIntentId,
                'orderId' => $response['body']['metadata']['order_id'] ?? ($sanitizedData['orderId'] ?? null),
                'paymentStatus' => $paymentStatus,
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new VerificationException('Stripe: PaymentIntent retrieval failed. ' . $e->getMessage(), 0, $e);
        }
    }

    public function refund(array $data): array
    {
        $sanitizedData = $this->sanitize($data);
        // Stripe refunds can be against a Charge ID or a PaymentIntent ID.
        // Prefer Charge ID if available, as it's more direct for refunds.
        if (empty($sanitizedData['transactionId']) && empty($sanitizedData['gatewayReferenceId'])) { 
            throw new RefundException('Stripe: Missing transactionId (Charge ID) or gatewayReferenceId (PaymentIntent ID) for refund.');
        }
        
        $payload = [];
        if (!empty($sanitizedData['amount'])) {
             if (!is_numeric($sanitizedData['amount']) || $sanitizedData['amount'] <= 0) {
                throw new RefundException('Stripe: Invalid amount for refund.');
            }
            $payload['amount'] = (int)round($sanitizedData['amount'] * 100); // Amount in cents
        }

        if (!empty($sanitizedData['transactionId'])) { // Charge ID (ch_xxx)
            $payload['charge'] = $sanitizedData['transactionId'];
        } elseif (!empty($sanitizedData['gatewayReferenceId'])) { // PaymentIntent ID (pi_xxx)
            $payload['payment_intent'] = $sanitizedData['gatewayReferenceId'];
        }
        
        if (isset($sanitizedData['reason'])) {
            $payload['reason'] = $sanitizedData['reason']; // e.g. 'requested_by_customer', 'duplicate', 'fraudulent'
        }
         if (isset($sanitizedData['metadata'])) {
            $payload['metadata'] = $sanitizedData['metadata'];
        }

        try {
            // $response = $this->httpClient('POST', $this->getApiBaseUrl() . '/refunds', $payload, $this->getRequestHeaders());
            // Mocked response
            if (($payload['amount'] ?? 0) === 99900) { 
                 throw new RefundException('Stripe: API rejected refund (simulated).');
            }
            $response = ['body' => [
                    'id' => 're_' . substr(md5(uniqid()),0,24),
                    'object' => 'refund',
                    'status' => 'succeeded', // Can also be 'pending', 'failed', 'canceled'
                    'amount' => $payload['amount'] ?? 1000, // Mocked original amount if full refund
                    'charge' => $payload['charge'] ?? ('ch_' . substr(md5(uniqid()),0,24)),
                    'payment_intent' => $payload['payment_intent'] ?? ('pi_' . substr(md5(uniqid()),0,24)),
                ],
                'status_code' => 200
            ];

            if ($response['status_code'] !== 200 || empty($response['body']['id'])) {
                 $error = $response['body']['error'] ?? ['message' => 'Unknown Stripe API error during refund'];
                throw new RefundException('Stripe: Failed to process refund. ' . $error['message']);
            }

            $refundStatus = $response['body']['status'];
            $isSuccess = $refundStatus === 'succeeded';
            $isPending = $refundStatus === 'pending';

            return [
                'status' => $isSuccess ? 'success' : ($isPending ? 'pending' : 'failed'),
                'message' => 'Stripe refund status: ' . $refundStatus,
                'refundId' => $response['body']['id'],
                'paymentStatus' => $refundStatus, // The status of the refund itself
                'rawData' => $response['body']
            ];
        } catch (\Exception $e) {
            throw new RefundException('Stripe: Refund request failed. ' . $e->getMessage(), 0, $e);
        }
    }
} 