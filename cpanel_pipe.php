#!/usr/bin/php
<?php

$rawEmail = file_get_contents("php://stdin");
$saveDir = __DIR__ . '/emails';

if (!is_dir($saveDir)) {
    mkdir($saveDir, 0700, true);
}

// Split headers and body at the first blank line
$parts = preg_split("/\R\R/", $rawEmail, 2);
$rawHeaders = $parts[0] ?? '';
$rawBody = $parts[1] ?? '';

// Helper to extract one header
function getHeader($headers, $name) {
    if (preg_match('/^' . preg_quote($name, '/') . ':\s*(.+)$/mi', $headers, $m)) {
        return trim($m[1]);
    }
    return '';
}

$from      = getHeader($rawHeaders, 'From');
$to        = getHeader($rawHeaders, 'To');
$subject   = getHeader($rawHeaders, 'Subject');
$date      = getHeader($rawHeaders, 'Date');
$messageId = getHeader($rawHeaders, 'Message-ID');
$replyTo   = getHeader($rawHeaders, 'Reply-To');
$returnPath  = getHeader($rawHeaders, 'Return-Path');
$contentType = getHeader($rawHeaders, 'Content-Type');
$spf         = getHeader($rawHeaders, 'Received-SPF');

// Save a readable file with headers included
$output =
    "=== EMAIL HEADERS ===\n" .
    "From: $from\n" .
    "To: $to\n" .
    "Subject: $subject\n" .
    "Date: $date\n" .
    "Message-ID: $messageId\n" .
    "Reply-To: $replyTo\n" .
    "Return-Path: $returnPath\n" .
    "Content-Type: $contentType\n" .
    "Received-SPF: $spf\n\n" .
    "=== FULL RAW HEADERS ===\n" .
    $rawHeaders . "\n\n" .
    "=== BODY ===\n" .
    $rawBody . "\n";

$filename = $saveDir . '/email_' . date('Y-m-d_H-i-s') . '_' . uniqid() . '.txt';
file_put_contents($filename, $output, LOCK_EX);

// ── ScamShield API ────────────────────────────────────────────
$apiUrl = 'https://your-app.onrender.com/analyze';   // <-- replace with your Render URL
$apiKey = '';                                         // <-- set if you use SCAMSHIELD_API_KEY

$headers = ['Content-Type: message/rfc822'];
if ($apiKey !== '') {
    $headers[] = 'X-Api-Key: ' . $apiKey;
}

$ch = curl_init($apiUrl);
curl_setopt_array($ch, [
    CURLOPT_POST           => true,
    CURLOPT_POSTFIELDS     => $rawEmail,
    CURLOPT_HTTPHEADER     => $headers,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 60,
]);
curl_exec($ch);   // fire-and-forget — response stored in DB later
curl_close($ch);
// ─────────────────────────────────────────────────────────────

exit(0);
