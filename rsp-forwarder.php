<?php

/**
 * Plugin Name:       RSP Forwarder (with Recaptcha Verify)
 * Description:       Verifies reCAPTCHA v3 on the server, then generates X-Signature and forwards to the CRM.
 * Version:           1.1
 * Author:            Your Name
 * License:           GPL-2.0+
 */

if (! defined('ABSPATH')) {
    exit;
}

/**
 * 1) Replace these with your actual values:
 */
if (! defined('RSP_HMAC_SECRET')) {
    define('RSP_HMAC_SECRET', '7hg0HxC1xlDBC46b/SJihXzE697RikDmiYb1Uj++dzk=');
}

// Real reCAPTCHA secret key (must match the site key you used on the page, and that key must be allowed for localhost)
if (! defined('RSP_RECAPTCHA_SECRET')) {
    define('RSP_RECAPTCHA_SECRET', '6LffXFQrAAAAAATOAiQEgn9WX01eZ0QkSs2Utli1');
}

if (! defined('RSP_CRM_ENDPOINT')) {
    define('RSP_CRM_ENDPOINT', 'https://digital-services-api-software-qa.montylocal.net/api-gateway/crm-middleware/api/v1/EsimRSP');
}

/**
 * 2) Hook into admin_post for both logged-in and not-logged-in users.
 */
add_action('admin_post_nopriv_rsp_forward', 'rsp_handle_forward');
add_action('admin_post_rsp_forward',     'rsp_handle_forward');

/**
 * 3) Handler: verify reCAPTCHA, then forward to CRM.
 */
function rsp_handle_forward()
{
    // a) Read POST fields from FormData
    $firstName      = isset($_POST['FirstName'])      ? sanitize_text_field(wp_unslash($_POST['FirstName']))       : '';
    $lastName       = isset($_POST['LastName'])       ? sanitize_text_field(wp_unslash($_POST['LastName']))        : '';
    $email          = isset($_POST['Email'])          ? sanitize_email(wp_unslash($_POST['Email']))                : '';
    $country        = isset($_POST['Country'])        ? sanitize_text_field(wp_unslash($_POST['Country']))         : '';
    $phone          = isset($_POST['Phone'])          ? sanitize_text_field(wp_unslash($_POST['Phone']))           : '';
    $companyName    = isset($_POST['CompanyName'])    ? sanitize_text_field(wp_unslash($_POST['CompanyName']))     : '';
    $recaptchaToken = isset($_POST['recaptcha_token']) ? sanitize_text_field(wp_unslash($_POST['recaptcha_token']))  : '';

    // b) Ensure required fields exist
    if ('' === $firstName)       return wp_send_json_error('Missing field: FirstName');
    if ('' === $lastName)        return wp_send_json_error('Missing field: LastName');
    if ('' === $email)           return wp_send_json_error('Missing field: Email');
    if ('' === $country)         return wp_send_json_error('Missing field: Country');
    if ('' === $phone)           return wp_send_json_error('Missing field: Phone');
    if ('' === $companyName)     return wp_send_json_error('Missing field: CompanyName');
    if ('' === $recaptchaToken)  return wp_send_json_error('Missing field: recaptcha_token');

    // c) Server‐side verify reCAPTCHA via Google’s siteverify API
    $api_key = 'AIzaSyCRW7TUWacdLi_2J39yjTC7BvcPcRYGkg0'; // from GCP
    $endpoint = "https://recaptchaenterprise.googleapis.com/v1/projects/montymobile-rsp-landing-page/assessments?key={$api_key}";

    $request_body = [
        "event" => [
            "token"      => $recaptchaToken,
            "siteKey"    => RSP_RECAPTCHA_SECRET,
            "expectedAction" => "rsp_submit",
        ]
    ];

    $response = wp_remote_post($endpoint, [
        'headers' => ['Content-Type' => 'application/json'],
        'body'    => wp_json_encode($request_body),
    ]);

    $data = json_decode(wp_remote_retrieve_body($response), true);

    if (is_wp_error($response)) {
        return wp_send_json_error('Recaptcha request failed: ' . $response->get_error_message());
    }

    // 7) Decode the JSON response:
    $body = wp_remote_retrieve_body($response);
    $data = json_decode($body, true);

    // 8) Ensure we got a valid array back:
    if (!is_array($data) || !isset($data['tokenProperties'])) {
        return wp_send_json_error('Recaptcha Enterprise returned invalid response.');
    }

    // 9) Check that the token is valid and the action matches:
    $token_props = $data['tokenProperties'];
    if (isset($token_props['valid']) && false === $token_props['valid']) {
        return wp_send_json_error('Recaptcha token invalid.');
    }
    if (isset($token_props['action']) && 'rsp_submit' !== $token_props['action']) {
        return wp_send_json_error('Recaptcha action mismatch.');
    }


    // d) Build the JSON body for the CRM
    $crm_payload = array(
        'FirstName'   => $firstName,
        'LastName'    => $lastName,
        'Email'       => $email,
        'Country'     => $country,
        'Phone'       => $phone,
        'CompanyName' => $companyName,
    );
    $body_json = wp_json_encode($crm_payload, JSON_UNESCAPED_SLASHES);
    // Minify (remove whitespace) to match Postman’s “modifiedBody” logic:
    $minified_body = preg_replace('/\s+/', '', $body_json);

    // e) Compute HMAC-SHA256 signature (binary) and Base64-encode
    $raw_hmac  = hash_hmac('sha256', $minified_body, RSP_HMAC_SECRET, true);
    $signature = base64_encode($raw_hmac);

    // f) Prepare headers for the CRM request
    $headers = array(
        'Accept'         => '*/*',
        'Content-Type'   => 'application/json',
        'X-Signature'    => $signature,
        'RecaptchaToken' => $recaptchaToken,
        'LanguageCode' => 'en',
        'Tenant'       => '4efca093-86e4-416f-98c0-bdf3376061bb',
    );

    // g) Forward to the CRM endpoint
    $crm_response = wp_remote_post(
        RSP_CRM_ENDPOINT,
        array(
            'headers' => $headers,
            'body'    => $body_json,
            'timeout' => 20,
        )
    );

    if (is_wp_error($crm_response)) {
        return wp_send_json_error('WP_Error forwarding to CRM: ' . $crm_response->get_error_message());
    }

    $status_code   = wp_remote_retrieve_response_code($crm_response);
    $response_body = wp_remote_retrieve_body($crm_response);

    if (200 !== intval($status_code)) {
        return wp_send_json_error("CRM returned {$status_code}: {$response_body}");
    }

    // h) If we got here, everything succeeded
    return wp_send_json_success('Forwarded successfully.');
}
