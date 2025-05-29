<?php

namespace Multipay\Payment;

use Multipay\Payment\Exceptions\InvalidConfigurationException;

abstract class PaymentGateway
{
    protected array $config;

    /**
     * PaymentGateway constructor.
     *
     * @param array $config Gateway specific configuration.
     * @throws InvalidConfigurationException If configuration is invalid.
     */
    public function __construct(array $config)
    {
        $this->config = array_merge($this->getDefaultConfig(), $config);
        $this->validateConfig($this->config);
    }

    /**
     * Get the default configuration for the gateway.
     *
     * @return array
     */
    abstract protected function getDefaultConfig(): array;

    /**
     * Validate the gateway configuration.
     *
     * @param array $config
     * @throws InvalidConfigurationException If configuration is invalid.
     */
    abstract protected function validateConfig(array $config): void;

    abstract public function initialize(array $data): array;
    abstract public function process(array $data): array;
    abstract public function verify(array $data): array;
    abstract public function refund(array $data): array;

    /**
     * Helper method to make secure HTTP requests.
     * Gateways should use this for API calls.
     *
     * @param string $method HTTP method (GET, POST, etc.)
     * @param string $url The API endpoint URL.
     * @param array $data Request data.
     * @param array $headers Request headers.
     * @return array The response from the server.
     * @throws \Exception If the request fails.
     */
    protected function httpClient(string $method, string $url, array $data = [], array $headers = []): array
    {
        // In a real application, use a robust HTTP client like Guzzle.
        // This is a simplified example.
        $contextOptions = [
            'http' => [
                'method' => strtoupper($method),
                'header' => implode("\\r\\n", array_map(fn($key, $value) => "{$key}: {$value}", array_keys($headers), $headers)),
                'content' => http_build_query($data),
                'ignore_errors' => true, // Handle errors manually
                'timeout' => 30, // Seconds
                 // IMPORTANT: SSL/TLS settings for security
                'ssl' => [
                    'verify_peer' => true,
                    'verify_peer_name' => true,
                    'allow_self_signed' => false, // Should be false in production
                    // 'cafile' => '/path/to/your/cacert.pem', // Path to CA bundle
                    // 'capath' => '/path/to/your/ca_directory/',
                ],
            ]
        ];

        $context = stream_context_create($contextOptions);
        $response = @file_get_contents($url, false, $context);
        $responseHeaders = $http_response_header ?? [];

        if ($response === false) {
            $error = error_get_last();
            throw new \RuntimeException("HTTP request failed: " . ($error['message'] ?? 'Unknown error'));
        }
        
        // Basic status code check
        $statusCode = 0;
        if (!empty($responseHeaders)) {
            sscanf($responseHeaders[0], 'HTTP/%*d.%*d %d', $statusCode);
        }

        $decodedResponse = json_decode($response, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
             // Handle non-JSON responses or log error
            // For now, we'll return the raw response if not JSON
             return ['raw_response' => $response, 'status_code' => $statusCode, 'headers' => $responseHeaders];
        }

        return ['body' => $decodedResponse, 'status_code' => $statusCode, 'headers' => $responseHeaders];
    }

     /**
     * Sanitize input data.
     *
     * @param array $data
     * @return array
     */
    protected function sanitize(array $data): array
    {
        // Implement more specific sanitization based on expected data types and formats.
        // Example:
        // $data['amount'] = filter_var($data['amount'], FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
        // $data['email'] = filter_var($data['email'], FILTER_SANITIZE_EMAIL);
        return array_map(function ($value) {
            if (is_string($value)) {
                return htmlspecialchars(trim($value), ENT_QUOTES, 'UTF-8');
            }
            return $value;
        }, $data);
    }
}
