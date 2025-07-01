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
// if (! defined('RSP_HMAC_SECRET')) {
//     define('RSP_HMAC_SECRET', 'g4naN4//moGpv/Gev4JIydVR9TwPnnVyJqkvlFoqdRU=');
// }

if (! defined('RSP_HMAC_SECRET')) {
    define('RSP_HMAC_SECRET', '7hg0HxC1xlDBC46b/SJihXzE697RikDmiYb1Uj++dzk=');
}


if (! defined('RSP_CRM_ENDPOINT')) {
    define('RSP_CRM_ENDPOINT', 'https://digital-services-api-software-qa.montylocal.net/api-gateway/crm-middleware/api/v1/EsimRSP');
}

// Real reCAPTCHA secret key (must match the site key you used on the page, and that key must be allowed for localhost)
if (! defined('RSP_RECAPTCHA_SECRET')) {
    define('RSP_RECAPTCHA_SECRET', '6LdXblYrAAAAACTfSVTL0vWXaH8gAE1M4mvxTeW_');
}

if (! defined('RSP_RECAPTCHA_ENDPOINT')) {
    define('RSP_RECAPTCHA_ENDPOINT', 'https://www.google.com/recaptcha/api/siteverify');
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
    if (
        ! isset($_POST['forum_form_nonce']) ||
        ! wp_verify_nonce($_POST['forum_form_nonce'], 'submit_forum_form_action')
    ) {
        // Invalid request — handle it securely
        return wp_send_json_error("Security check failed. Please try again.");
    }
    // a) Read POST fields from FormData
    $firstName      = isset($_POST['FirstName'])      ? sanitize_text_field(wp_unslash($_POST['FirstName']))       : '';
    $lastName       = isset($_POST['LastName'])       ? sanitize_text_field(wp_unslash($_POST['LastName']))        : '';
    $email          = isset($_POST['Email'])          ? sanitize_email(wp_unslash($_POST['Email']))                : '';
    $country        = isset($_POST['Country'])        ? sanitize_text_field(wp_unslash($_POST['Country']))         : '';
    $phone          = isset($_POST['Phone'])          ? sanitize_text_field(wp_unslash($_POST['Phone']))           : '';
    $companyName    = isset($_POST['CompanyName'])    ? sanitize_text_field(wp_unslash($_POST['CompanyName']))     : '';
    $recaptchaToken = isset($_POST['recaptcha_token']) ? sanitize_text_field(wp_unslash($_POST['recaptcha_token']))  : '';


    $allowed_countries = [
        'AF',
        'AL',
        'DZ',
        'AD',
        'AO',
        'AG',
        'AR',
        'AM',
        'AU',
        'AT',
        'AZ',
        'BS',
        'BH',
        'BD',
        'BB',
        'BY',
        'BE',
        'BZ',
        'BJ',
        'BT',
        'BO',
        'BA',
        'BW',
        'BR',
        'BN',
        'BG',
        'BF',
        'BI',
        'CV',
        'KH',
        'CM',
        'CA',
        'CF',
        'TD',
        'CL',
        'CN',
        'CO',
        'KM',
        'CG',
        'CR',
        'HR',
        'CU',
        'CY',
        'CZ',
        'DK',
        'DJ',
        'DM',
        'DO',
        'EC',
        'EG',
        'SV',
        'GQ',
        'ER',
        'EE',
        'SZ',
        'ET',
        'FJ',
        'FI',
        'FR',
        'GA',
        'GM',
        'GE',
        'DE',
        'GH',
        'GR',
        'GD',
        'GT',
        'GN',
        'GW',
        'GY',
        'HT',
        'VA',
        'HN',
        'HU',
        'IS',
        'IN',
        'ID',
        'IR',
        'IQ',
        'IE',
        'IL',
        'IT',
        'JM',
        'JP',
        'JO',
        'KZ',
        'KE',
        'KI',
        'KP',
        'KR',
        'KW',
        'KG',
        'LA',
        'LV',
        'LB',
        'LS',
        'LR',
        'LY',
        'LI',
        'LT',
        'LU',
        'MG',
        'MW',
        'MY',
        'MV',
        'ML',
        'MT',
        'MH',
        'MR',
        'MU',
        'MX',
        'FM',
        'MD',
        'MC',
        'MN',
        'ME',
        'MA',
        'MZ',
        'MM',
        'NA',
        'NR',
        'NP',
        'NL',
        'NZ',
        'NI',
        'NE',
        'NG',
        'MK',
        'NO',
        'OM',
        'PK',
        'PW',
        'PS',
        'PA',
        'PG',
        'PY',
        'PE',
        'PH',
        'PL',
        'PT',
        'QA',
        'RO',
        'RU',
        'RW',
        'KN',
        'LC',
        'VC',
        'WS',
        'SM',
        'ST',
        'SA',
        'SN',
        'RS',
        'SC',
        'SL',
        'SG',
        'SK',
        'SI',
        'SB',
        'SO',
        'ZA',
        'SS',
        'ES',
        'LK',
        'SD',
        'SR',
        'SE',
        'CH',
        'SY',
        'TJ',
        'TZ',
        'TH',
        'TL',
        'TG',
        'TO',
        'TT',
        'TN',
        'TR',
        'TM',
        'TV',
        'UG',
        'UA',
        'AE',
        'GB',
        'US',
        'UY',
        'UZ',
        'VU',
        'VE',
        'VN',
        'YE',
        'ZM',
        'ZW'
    ];



    // b) Ensure required fields exist
    if ('' === $firstName)       return wp_send_json_error('Missing field: FirstName');
    if ('' === $lastName)        return wp_send_json_error('Missing field: LastName');
    if ('' === $email)           return wp_send_json_error('Missing field: Email');
    if ('' === $country)         return wp_send_json_error('Missing field: Country');
    if ('' === $phone)           return wp_send_json_error('Missing field: Phone');
    if ('' === $companyName)     return wp_send_json_error('Missing field: CompanyName');
    if ('' === $recaptchaToken)  return wp_send_json_error('Missing field: recaptcha_token');


    if (! in_array(strtoupper($country), $allowed_countries, true)) {
        return wp_send_json_error('Invalid country selection.');
    }
    // $recaptcha_payload = array(
    //     'secret' => RSP_RECAPTCHA_SECRET,
    //     'response' => $recaptchaToken
    // );

    // $recaptcha_response = wp_remote_post(RSP_RECAPTCHA_ENDPOINT, [
    //     'body'    => $recaptcha_payload
    // ]);

    // $recaptcha_data = json_decode(wp_remote_retrieve_body($recaptcha_response), true);

    // if (is_wp_error($recaptcha_response)) {
    //     return wp_send_json_error('Recaptcha request failed: ' . $recaptcha_response->get_error_message());
    // }

    // // 8) Ensure we got a valid array back:
    // if (!is_array($recaptcha_data)) {
    //     return wp_send_json_error('Recaptcha Enterprise returned invalid responsess.');
    // }


    // if (isset($recaptcha_data['success']) && false === $recaptcha_data['success']) {
    //     return wp_send_json_error('Recaptcha token invalid.');
    // }
    // if (isset($recaptcha_data['action']) && 'submit' !== $recaptcha_data['action']) {
    //     return wp_send_json_error('Recaptcha action mismatch.');
    // }

    // var_dump($recaptchaToken);
    // // d) Build the JSON body for the CRM
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
        //return wp_send_json_error('WP_Error forwarding to CRM: ' . $crm_response->get_error_message());
        return wp_send_json_error('An error occured.');
    }

    $status_code   = wp_remote_retrieve_response_code($crm_response);
    $response_body = wp_remote_retrieve_body($crm_response);

    if (200 !== intval($status_code)) {
        //return wp_send_json_error("CRM returned {$status_code}: {$response_body}");
        return wp_send_json_error('An error occured.');
    }

    // h) If we got here, everything succeeded
    return wp_send_json_success('Forwarded successfully.');
}
